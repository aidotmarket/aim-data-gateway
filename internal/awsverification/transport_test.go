package awsverification

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/wire"
)

func TestAuthoritativeRootSPKI(t *testing.T) {
	for name, want := range map[string]string{
		"x1": ISRG_ROOT_X1_SPKI_SHA256,
		"x2": ISRG_ROOT_X2_SPKI_SHA256,
		"yr": ISRG_ROOT_YR_SPKI_SHA256,
		"ye": ISRG_ROOT_YE_SPKI_SHA256,
	} {
		b, e := os.ReadFile("testdata/tls/" + name + ".pem")
		if e != nil {
			t.Fatal(e)
		}
		p, rest := pem.Decode(b)
		if p == nil || p.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
			t.Fatal(name, "invalid certificate fixture")
		}
		c, e := x509.ParseCertificate(p.Bytes)
		if e != nil {
			t.Fatal(e)
		}
		sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
		if hex.EncodeToString(sum[:]) != want {
			t.Fatal(name, "pin wrong")
		}
		t.Log(name, hex.EncodeToString(sum[:]))
		if e = verifyTLS(tls.ConnectionState{ServerName: "api.ai.market", VerifiedChains: [][]*x509.Certificate{{c}}}); e != nil {
			t.Fatal("validated root not accepted", e)
		}
	}
}
func cert(t *testing.T, parent *x509.Certificate, parentKey ed25519.PrivateKey, ca bool, hostname string) (*x509.Certificate, ed25519.PrivateKey, []byte) {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	at := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(at.UnixNano()),
		Subject:               pkix.Name{CommonName: hostname},
		NotBefore:             at.Add(-time.Hour),
		NotAfter:              at.Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  ca,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		DNSNames:              []string{hostname},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ca {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	if parent == nil {
		parent = tmpl
		parentKey = key
	}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	if e != nil {
		t.Fatal(e)
	}
	c, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	return c, key, der
}
func TestTLSRefusalsSendZeroHTTPWork(t *testing.T) {
	for _, mode := range []string{
		"self_signed",
		"wrong_issuer",
		"valid_other_CA",
		"hostname_substitution",
		"pin_mismatch",
	} {
		t.Run(mode, func(t *testing.T) {
			ca, caKey, caDER := cert(t, nil, nil, true, "ISRG Root X1") // misleading issuer name cannot satisfy an SPKI pin
			host := "api.ai.market"
			if mode == "hostname_substitution" {
				host = "other.example"
			}
			leaf, leafKey, leafDER := cert(t, ca, caKey, false, host)
			_ = leaf
			pool := x509.NewCertPool()
			chain := [][]byte{leafDER, caDER}
			switch mode {
			case "self_signed":
				_, leafKey, leafDER = cert(t, nil, nil, false, host)
				chain = [][]byte{leafDER}
			case "wrong_issuer":
				_, _, otherDER := cert(t, nil, nil, true, "other issuer")
				chain = [][]byte{leafDER, otherDER}
			case "valid_other_CA", "hostname_substitution", "pin_mismatch":
				pool.AddCert(ca)
			}
			var requests atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				io.WriteString(w, `{"work_jws":null}`)
			}))
			server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: leafKey}}}
			server.Config.ErrorLog = nil
			server.StartTLS()
			defer server.Close()
			a := &memoryAudit{}
			client := MarketplaceClient(a)
			transport := client.Transport.(*http.Transport)
			transport.TLSClientConfig.RootCAs = pool
			transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				if address != "api.ai.market:443" {
					t.Fatal(address)
				}
				return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
			}
			if _, e := client.Post(APIBaseURL+"/api/v1/verification-runners/"+runnerID+"/work", "application/json", strings.NewReader("{}")); e == nil {
				t.Fatal("TLS accepted")
			}
			if requests.Load() != 0 {
				t.Fatal("TLS rejection sent work")
			}
			if mode == "pin_mismatch" && (len(a.events) != 1 || !strings.HasPrefix(a.events[0], "tls_pin_mismatch ")) {
				t.Fatal("pin mismatch log missing", a.events)
			}
		})
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
func TestAuthBodiesLimitsRedirectAndFixedEgress(t *testing.T) {
	f := newFixture(t)
	s, e := Bootstrap(ctx, f.h.Config, f.h.Ledger, f.secrets, f.backend, f.at)
	if e != nil {
		t.Fatal(e)
	}
	var nonces []string
	client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "api.ai.market" || r.URL.RawQuery != "" {
			t.Fatal("host substitution")
		}
		var raw []byte
		if r.Body != nil {
			raw, _ = io.ReadAll(r.Body)
		}
		var c struct {
			Runner     string `json:"runner_id"`
			Kind       string `json:"kind"`
			Connection string `json:"connection_id"`
			Version    string `json:"scanner_version"`
			Digest     string `json:"image_digest"`
			Method     string `json:"method"`
			Path       string `json:"path"`
			Nonce      string `json:"nonce"`
			Issued     int64  `json:"iat"`
			Hash       string `json:"body_sha256"`
		}
		_, e := wire.VerifyControl(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), "aim-verification-request+jwt", "runner_id kind connection_id scanner_version image_digest method path nonce iat body_sha256", map[string]ed25519.PublicKey{s.Receipt: s.Private.Public().(ed25519.PublicKey)}, &c, 4096)
		if e != nil || c.Hash != wire.Digest(raw) || c.Method != r.Method || c.Path != r.URL.Path || c.Kind != "aws" || c.Connection != connectionID || c.Runner != runnerID || c.Version != f.h.Config.Version || c.Digest != f.h.Config.Digest || c.Issued != f.at.Unix() {
			t.Fatal("auth binding wrong", e)
		}
		nonces = append(nonces, c.Nonce)
		reply := `{"work_jws":null}`
		if strings.Contains(r.URL.Path, "/snapshot/") {
			if r.Method != "GET" || len(raw) != 0 {
				t.Fatal("snapshot request body/method changed")
			}
			reply = "snapshot-jws"
		} else if strings.HasSuffix(r.URL.Path, "/report") {
			if r.Method != "POST" || string(raw) != `{"test":"control-only"}` {
				t.Fatal("report body/method changed")
			}
			reply = `{"iid":"report-iid","status":"stored"}`
		}
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(reply)),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	})}
	b := HTTPBackend{Client: client, Config: f.h.Config, Now: func() time.Time {
		return f.at
	}}
	for i := 0; i < 2; i++ {
		if work, e := b.Work(ctx, s); e != nil || work != "" {
			t.Fatal(e)
		}
	}
	if snapshot, err := b.Snapshot(ctx, s, strings.Repeat("a", 64)); err != nil || snapshot != "snapshot-jws" {
		t.Fatal("authenticated snapshot request failed", err)
	}
	for i := 0; i < 2; i++ {
		if err := b.Report(ctx, s, []byte(`{"test":"control-only"}`), "report-iid"); err != nil {
			t.Fatal("authenticated exact report retry failed", err)
		}
	}
	seen := map[string]bool{}
	for _, nonce := range nonces {
		if seen[nonce] {
			t.Fatal("request replay nonce reused")
		}
		seen[nonce] = true
	}
	if len(nonces) != 5 {
		t.Fatal("request replay nonce reused")
	}
	for _, p := range []string{"/api/v1/verification-runners/x?url=evil", "https://other.example/", "/api/v1/verification-runners/x#evil"} {
		if _, e = b.request(ctx, s, "POST", p, nil, 4096); e == nil {
			t.Fatal("path allowed", p)
		}
	}
	if _, e = b.request(ctx, s, "POST", "/api/v1/verification-runners/register", make([]byte, MaxReport+1), 4096); e == nil {
		t.Fatal("oversized body allowed")
	}
	client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", 65537))), Header: make(http.Header)}, nil
	})
	if _, e = b.Work(ctx, s); e == nil {
		t.Fatal("oversized response")
	}
	var calls int
	redirectClient := MarketplaceClient()
	redirectClient.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{
			StatusCode: 302,
			Header:     http.Header{"Location": []string{"https://other.example/"}},
			Body:       io.NopCloser(bytes.NewReader(nil)),
			Request:    r,
		}, nil
	})
	b.Client = redirectClient
	if _, e = b.Work(ctx, s); e == nil || calls != 1 {
		t.Fatal("redirect followed")
	}
	tr := MarketplaceClient().Transport.(*http.Transport)
	for _, host := range []string{"evil.example:443", "api.ai.market:80", "127.0.0.1:443"} {
		if _, e := tr.DialContext(ctx, "tcp", host); e == nil {
			t.Fatal("egress allowed", host)
		}
	}
}
func TestLiveProductionChain(t *testing.T) {
	if os.Getenv("AIM_TEST_LIVE_TLS") != "1" {
		t.Skip("explicit read-only production TLS check")
	}
	r, e := MarketplaceClient().Get(APIBaseURL + "/")
	if e != nil {
		t.Fatal(e)
	}
	defer r.Body.Close()
	if r.TLS == nil {
		t.Fatal("no TLS")
	}
	if e = verifyTLS(*r.TLS); e != nil {
		t.Fatal(e)
	}
	for _, chain := range r.TLS.VerifiedChains {
		names := []string{}
		for _, c := range chain {
			names = append(names, c.Subject.CommonName)
		}
		t.Log(strings.Join(names, " <- "))
	}
}
