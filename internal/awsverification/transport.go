package awsverification

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	core "github.com/aidotmarket/aim-data-gateway/verification"
)

// Computed from the unmodified authoritative PEM bytes in testdata/tls.
const ISRG_ROOT_X1_SPKI_SHA256 = "0b9fa5a59eed715c26c1020c711b4f6ec42d58b0015e14337a39dad301c5afc3"
const ISRG_ROOT_X2_SPKI_SHA256 = "762195c225586ee6c0237456e2107dc54f1efc21f61a792ebd515913cce68332"
const ISRG_ROOT_YE_SPKI_SHA256 = "b0292ae545978e0fbb98abbd94c861605e5b18bb32ed523f50d5b7b5c71d47bc"
const ISRG_ROOT_YR_SPKI_SHA256 = "7e4e8838a8add6295de7ae3b047d3aba3488ab95db0a0aa56d897a00d8618bcf"

var ErrTLSPin = errors.New("tls_pin_mismatch")

func verifyTLS(s tls.ConnectionState) error {
	if s.ServerName != "api.ai.market" {
		return ErrRefused
	}
	for _, chain := range s.VerifiedChains {
		if len(chain) == 0 {
			continue
		}
		h := sha256.Sum256(chain[len(chain)-1].RawSubjectPublicKeyInfo)
		switch hex.EncodeToString(h[:]) {
		case ISRG_ROOT_X1_SPKI_SHA256, ISRG_ROOT_X2_SPKI_SHA256, ISRG_ROOT_YE_SPKI_SHA256, ISRG_ROOT_YR_SPKI_SHA256:
			return nil
		}
	}
	return ErrTLSPin
}
func MarketplaceClient(audits ...Audit) *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second}
	return &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return ErrRefused
	}, Transport: &http.Transport{
		Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "api.ai.market", VerifyConnection: func(s tls.ConnectionState) error {
			e := verifyTLS(s)
			if errors.Is(e, ErrTLSPin) {
				for _, a := range audits {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					a.Event(ctx, "tls_pin_mismatch", wire.Digest(nil))
					cancel()
				}
			}
			return e
		}},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != "api.ai.market:443" {
				return nil, ErrRefused
			}
			return d.DialContext(ctx, network, address)
		},
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second, MaxResponseHeaderBytes: 16 << 10,
	}}
}
func randomToken() (string, error) {
	var b [32]byte
	_, e := rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:]), e
}
func signJWS(key ed25519.PrivateKey, kid, typ string, claims any) (string, error) {
	h, e := wire.Canonical(map[string]any{"alg": "EdDSA", "typ": typ, "kid": kid})
	if e != nil {
		return "", e
	}
	b, e := wire.Canonical(claims)
	if e != nil {
		return "", e
	}
	s := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(b)
	return s + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(s))), nil
}

type Backend interface {
	Register(context.Context, []byte) (RegistrationAck, error)
	Work(context.Context, *Secret) (string, error)
	Snapshot(context.Context, *Secret, string) (string, error)
	Report(context.Context, *Secret, []byte, string) error
}
type HTTPBackend struct {
	Client *http.Client
	Config Config
	Now    func() time.Time
}

func (b HTTPBackend) request(ctx context.Context, s *Secret, method, path string, body []byte, limit int) ([]byte, error) {
	if len(body) > MaxReport || !strings.HasPrefix(path, "/api/v1/verification-runners/") || strings.ContainsAny(path, "?#\\") {
		return nil, ErrRefused
	}
	r, e := http.NewRequestWithContext(ctx, method, APIBaseURL+path, bytes.NewReader(body))
	if e != nil {
		return nil, ErrRefused
	}
	r.Header.Set("Content-Type", "application/json")
	if s != nil {
		n, e := randomToken()
		if e != nil {
			return nil, ErrRefused
		}
		at := time.Now()
		if b.Now != nil {
			at = b.Now()
		}
		t, e := signJWS(s.Private, s.Receipt, "aim-verification-request+jwt", map[string]any{
			"runner_id":       s.Runner,
			"kind":            "aws",
			"connection_id":   b.Config.Connection,
			"scanner_version": b.Config.Version,
			"image_digest":    b.Config.Digest,
			"method":          method,
			"path":            path,
			"nonce":           n,
			"iat":             at.Unix(),
			"body_sha256":     wire.Digest(body),
		})
		if e != nil || len(t) > 4096 {
			return nil, ErrRefused
		}
		r.Header.Set("Authorization", "Bearer "+t)
	}
	resp, e := b.Client.Do(r)
	if e != nil {
		return nil, ErrRefused
	}
	defer resp.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if e != nil || len(raw) > limit || resp.StatusCode != 200 {
		return nil, ErrRefused
	}
	return raw, nil
}
func (b HTTPBackend) Register(ctx context.Context, body []byte) (RegistrationAck, error) {
	var a RegistrationAck
	raw, e := b.request(ctx, nil, "POST", "/api/v1/verification-runners/register", body, 16<<10)
	if e == nil {
		_, e = closed(raw, "runner_id receipt_key_id scan_spec_keys ack_jws")
	}
	if e == nil {
		e = json.Unmarshal(raw, &a)
	}
	return a, e
}
func (b HTTPBackend) Work(ctx context.Context, s *Secret) (string, error) {
	raw, e := b.request(ctx, s, "POST", "/api/v1/verification-runners/"+s.Runner+"/work", []byte("{}"), 64<<10)
	if e != nil {
		return "", e
	}
	// null is the only optional discriminant in the work response.
	v, e := coreWorkResponse(raw)
	return v, e
}
func (b HTTPBackend) Snapshot(ctx context.Context, s *Secret, hash string) (string, error) {
	if !hex64.MatchString(hash) {
		return "", ErrRefused
	}
	raw, e := b.request(ctx, s, "GET", "/api/v1/verification-runners/"+s.Runner+"/snapshot/"+hash, nil, wire.MaxSnapshot)
	return string(raw), e
}
func (b HTTPBackend) Report(ctx context.Context, s *Secret, body []byte, iid string) error {
	raw, e := b.request(ctx, s, "POST", "/api/v1/verification-runners/"+s.Runner+"/report", body, 4096)
	if e != nil {
		return e
	}
	m, e := closed(raw, "iid status")
	if e != nil || m["iid"] != iid || m["status"] != "stored" {
		return ErrRefused
	}
	return nil
}

func coreWorkResponse(raw []byte) (string, error) {
	v, e := core.ParseCanonical(raw)
	if e != nil {
		return "", ErrRefused
	}
	m, ok := v.(map[string]any)
	if !ok || len(m) != 1 {
		return "", ErrRefused
	}
	v, ok = m["work_jws"]
	if !ok {
		return "", ErrRefused
	}
	if v == nil {
		return "", nil
	}
	s, ok := v.(string)
	if !ok || s == "" || len(s) > 64<<10 {
		return "", ErrRefused
	}
	return s, nil
}
