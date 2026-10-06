package cloudflareverification

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	core "github.com/aidotmarket/aim-data-gateway/verification"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

type trip func(*http.Request) (*http.Response, error)

func (f trip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func reply(r *http.Request, body string) *http.Response {
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: r}
}
func testConfig() Config {
	return Config{Connection: "11111111-1111-1111-1111-111111111111", Bucket: "synthetic", Prefix: "p/", Jurisdiction: "default", Keys: []string{"p/data.csv"}, Token: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)), Version: "0.1.0", Release: "cloudflare-verifier-v0.1.0", Binary: strings.Repeat("b", 64), Worker: WorkerIdentity{Mode: "bundle", SHA256: strings.Repeat("c", 64)}}
}

var runner = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
var receipt = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

type fakeBackend struct {
	Backend
	register func(context.Context, []byte) (RegistrationAck, error)
}

func (b fakeBackend) Register(c context.Context, r []byte) (RegistrationAck, error) {
	return b.register(c, r)
}
func TestRegistrationLostReplyExactAckAndIdentity(t *testing.T) {
	c := testConfig()
	at := time.Unix(1791290000, 0)
	s, e := CreateSecret(c, at)
	if e != nil {
		t.Fatal(e)
	}
	original := append([]byte(nil), s.Registration...)
	var request map[string]any
	json.Unmarshal(original, &request)
	proof, _ := wire.DecodeDocument(request["key_proof"].(string), 64)
	delete(request, "key_proof")
	raw, _ := core.Canonical(request)
	if !ed25519.Verify(s.Private.Public().(ed25519.PublicKey), raw, proof) {
		t.Fatal("key proof")
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{66}, 32))
	calls := 0
	ack := RegistrationAck{Runner: runner, Receipt: receipt, Keys: []wire.Key{{KID: "scan-test", Alg: "EdDSA", Key: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}}}
	claims := map[string]any{"op": "scan_spec", "variant": "registered", "aud": runner, "iid": "cccccccc-cccc-cccc-cccc-cccccccccccc", "iat": at.Unix(), "runner_id": runner, "receipt_key_id": receipt, "registration_nonce": s.Nonce, "scanner_version": c.Version, "release_id": c.Release, "binary_sha256": c.Binary, "worker_identity": c.Worker}
	ack.JWS, _ = signJWS(key, "scan-test", "aim-scan-runner-ack+jwt", claims)
	backend := fakeBackend{register: func(_ context.Context, b []byte) (RegistrationAck, error) {
		calls++
		if !bytes.Equal(b, original) {
			t.Fatal("registration regenerated")
		}
		if calls == 1 {
			return RegistrationAck{}, errors.New("lost reply")
		}
		return ack, nil
	}}
	if Register(context.Background(), c, s, backend) == nil {
		t.Fatal("lost reply accepted")
	}
	// Persist/reload simulates a cold retry many hours later; exact ack binds original time.
	saved, _ := json.Marshal(s)
	var restored Secret
	json.Unmarshal(saved, &restored)
	if e = Register(context.Background(), c, &restored, backend); e != nil {
		t.Fatal(e)
	}
	if restored.Runner != runner || restored.Receipt != receipt || !bytes.Equal(restored.Registration, original) || restored.Ack != ack.JWS {
		t.Fatal("ack/state not exact")
	}
	bad := *s
	claims["binary_sha256"] = strings.Repeat("d", 64)
	ack.JWS, _ = signJWS(key, "scan-test", "aim-scan-runner-ack+jwt", claims)
	if Register(context.Background(), c, &bad, backend) == nil {
		t.Fatal("wrong hash accepted")
	}
	c.Worker.SHA256 = strings.Repeat("d", 64)
	if restored.validate(c) == nil {
		t.Fatal("mixed release accepted")
	}
}
func TestPinnedRootsAndNoAlternateEgressOrRedirect(t *testing.T) {
	files, _ := rootFiles.ReadDir("roots")
	for _, f := range files {
		b, _ := rootFiles.ReadFile("roots/" + f.Name())
		p, _ := pem.Decode(b)
		cert, e := x509.ParseCertificate(p.Bytes)
		if e != nil {
			t.Fatal(e)
		}
		if verifyTLS(tls.ConnectionState{ServerName: "api.ai.market", VerifiedChains: [][]*x509.Certificate{{cert}}}) != nil {
			t.Fatal("shipped root refused")
		}
	}
	for _, state := range []tls.ConnectionState{{ServerName: "api.ai.market"}, {ServerName: "elsewhere"}, {ServerName: "api.ai.market", VerifiedChains: [][]*x509.Certificate{{{RawSubjectPublicKeyInfo: []byte("interception")}}}}} {
		if verifyTLS(state) == nil {
			t.Fatal("unverified/wrong root accepted")
		}
	}
	client := MarketplaceClient()
	tr := client.Transport.(*http.Transport)
	if tr.TLSClientConfig.InsecureSkipVerify || tr.Proxy != nil || len(tr.TLSClientConfig.RootCAs.Subjects()) != 4 {
		t.Fatal("TLS defaults")
	}
	for _, host := range []string{"evil.invalid:443", "api.ai.market:80", "127.0.0.1:443"} {
		if _, e := tr.DialContext(context.Background(), "tcp", host); e == nil {
			t.Fatal(host)
		}
	}
	calls := 0
	client.Transport = trip(func(r *http.Request) (*http.Response, error) {
		calls++
		out := reply(r, "")
		out.StatusCode = 302
		out.Header.Set("Location", "https://evil.invalid/")
		return out, nil
	})
	if _, e := client.Get(APIBaseURL + "/"); e == nil || calls != 1 {
		t.Fatal("redirect followed")
	}
}
func TestHTTPReportsExactAckFreshNonceAndDeadline(t *testing.T) {
	c := testConfig()
	s, _ := CreateSecret(c, time.Now())
	s.Runner, s.Receipt, s.Ack = runner, receipt, "ack"
	nonces := map[string]bool{}
	body := []byte(`{"control":"only"}`)
	at := time.Unix(1791290000, 0)
	client := &http.Client{Transport: trip(func(r *http.Request) (*http.Response, error) {
		var claims struct {
			Runner     string         `json:"runner_id"`
			Kind       string         `json:"kind"`
			Connection string         `json:"connection_id"`
			Release    string         `json:"release_id"`
			Version    string         `json:"scanner_version"`
			Binary     string         `json:"binary_sha256"`
			Worker     WorkerIdentity `json:"worker_identity"`
			Method     string         `json:"method"`
			Path       string         `json:"path"`
			Nonce      string         `json:"nonce"`
			Issued     int64          `json:"iat"`
			Hash       string         `json:"body_sha256"`
		}
		_, e := wire.VerifyControl(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), "aim-verification-request+jwt", "runner_id kind connection_id release_id scanner_version binary_sha256 worker_identity method path nonce iat body_sha256", map[string]ed25519.PublicKey{receipt: s.Private.Public().(ed25519.PublicKey)}, &claims, 4096)
		raw, _ := io.ReadAll(r.Body)
		if e != nil || !bytes.Equal(raw, body) || claims.Hash != wire.Digest(body) || claims.Kind != "cloudflare" || claims.Worker != c.Worker || claims.Binary != c.Binary || claims.Release != c.Release || claims.Path != r.URL.Path || claims.Method != r.Method || claims.Issued != at.Unix() || nonces[claims.Nonce] {
			t.Fatal("auth binding", e)
		}
		nonces[claims.Nonce] = true
		return reply(r, `{"iid":"test-iid","status":"stored"}`), nil
	})}
	b := HTTPBackend{Client: client, Config: c, Now: func() time.Time { return at }}
	for range 2 {
		if e := b.Report(context.Background(), s, body, "test-iid"); e != nil {
			t.Fatal(e)
		}
	}
	if len(nonces) != 2 {
		t.Fatal("nonce reuse")
	}
	if e := b.Report(context.Background(), s, body, "wrong-iid"); e == nil {
		t.Fatal("wrong ack accepted")
	}
	tr := trip(func(r *http.Request) (*http.Response, error) {
		if r.Context().Err() == nil {
			t.Fatal("deadline missing")
		}
		return nil, r.Context().Err()
	})
	b.Client = &http.Client{Transport: tr}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if _, e := b.Work(ctx, s); e == nil {
		t.Fatal("deadline ignored")
	}
}
func TestBridgeMemberIndexOnlyAndEveryReadPins(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: trip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != "http://r2-bridge.internal/member/2" || r.Header.Get("Authorization") != "Bearer signed-capability" {
			t.Fatal("scope leaked")
		}
		res := reply(r, "abcd")
		res.Header.Set("X-Object-Size", "4")
		res.Header.Set("X-Object-Etag", "opaque")
		if r.Header.Get("Range") != "" {
			res.StatusCode = 206
			res.Body = io.NopCloser(strings.NewReader("bc"))
			res.Header.Set("X-Range-Offset", "1")
			res.Header.Set("X-Range-Length", "2")
		}
		return res, nil
	})}
	bridge := HTTPBridge{Client: client, Capability: "signed-capability"}
	q := Request{MemberIndex: 2, Bucket: "never-wire", Key: "never-wire", IfMatch: "opaque"}
	if h, e := bridge.Head(context.Background(), q); e != nil || h.ETag != "opaque" {
		t.Fatal(e)
	}
	body, e := get(context.Background(), bridge, q, 4)
	if e != nil {
		t.Fatal(e)
	}
	body.Close()
	q.Range = &Range{Offset: 1, Length: 2}
	body, e = get(context.Background(), bridge, q, 4)
	if e != nil {
		t.Fatal(e)
	}
	body.Close()
	q.IfMatch = "changed"
	if _, e = get(context.Background(), bridge, q, 4); e == nil {
		t.Fatal("pin changed")
	}
	if calls != 4 {
		t.Fatal(calls)
	}
	for _, host := range []string{"api.ai.market:443", "r2-bridge.internal:443", "other:80"} {
		if _, e := BridgeClient().Transport.(*http.Transport).DialContext(context.Background(), "tcp", host); e == nil {
			t.Fatal(host)
		}
	}
}
func TestWorkVectorsScanAndDeadlineNoReads(t *testing.T) {
	raw, e := os.ReadFile("../../contract/vectors/verification/r2_listing/control.json")
	if e != nil {
		t.Fatal(e)
	}
	var v map[string]struct {
		Token   string
		Payload struct{ Canonical string }
	}
	json.Unmarshal(raw, &v)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{66}, 32)).Public().(ed25519.PublicKey)
	var payload map[string]any
	json.Unmarshal([]byte(v["scan_spec"].Payload.Canonical), &payload)
	at, _ := utc(payload["issued_at_utc"].(string))
	keys := map[string]ed25519.PublicKey{payload["platform_key_id"].(string): key}
	j, e := VerifyWork(v["scan_spec"].Token, keys, payload["runner_id"].(string), payload["runner_id"].(string), "0.1.0", at)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = VerifyWork(v["scan_spec"].Token+"x", keys, j.Envelope.RunnerID, j.Envelope.RunnerID, "0.1.0", at); e == nil {
		t.Fatal("tamper accepted")
	}
	fixture, _ := os.ReadFile("../../contract/vectors/verification/r2_listing/csv_etag.json")
	var input struct {
		Snapshot struct {
			Connection string `json:"connection_id"`
			Bucket     string
			Members    []struct {
				Key, ETag, Format string
				Size              int64 `json:"size_bytes"`
			}
		}
		Members []struct {
			Source string `json:"source_hex"`
		}
	}
	json.Unmarshal(fixture, &input)
	c := testConfig()
	c.Connection = input.Snapshot.Connection
	c.Bucket = input.Snapshot.Bucket
	c.Prefix = ""
	c.Keys = nil
	bridge := &fakeBridge{objects: map[string][]byte{}}
	var objects []Object
	for i, m := range input.Snapshot.Members {
		data, _ := hex.DecodeString(input.Members[i].Source)
		bridge.objects[m.Key] = data
		objects = append(objects, Object{Key: m.Key, ETag: m.ETag, Size: m.Size, Format: m.Format})
		c.Keys = append(c.Keys, m.Key)
	}
	src, e := NewSource(bridge, c.Bucket, objects)
	if e != nil {
		t.Fatal(e)
	}
	sec, _ := CreateSecret(c, at)
	sec.Runner, sec.Receipt = payload["runner_id"].(string), receipt
	j.ScannerVersion, j.ReceiptKeyID = c.Version, receipt
	result, e := (Handler{Config: c, Now: func() time.Time { return at }}).scan(context.Background(), sec, j, src)
	if e != nil {
		t.Fatal(e)
	}
	var out struct {
		Variant  string
		Document string   `json:"document_b64"`
		Members  []string `json:"member_sha256s"`
	}
	json.Unmarshal(result, &out)
	if out.Variant != "scan" || len(out.Members) != len(objects) {
		t.Fatal("scan incomplete")
	}
	for i, o := range objects {
		sum := sha256.Sum256(bridge.objects[o.Key])
		if out.Members[i] != hex.EncodeToString(sum[:]) {
			t.Fatal("companion")
		}
	}
	doc, _ := wire.DecodeDocument(out.Document, wire.MaxScanDocument)
	var report map[string]any
	parsed, _ := core.ParseCanonical(doc)
	report = parsed.(map[string]any)
	sig, _ := base64.StdEncoding.DecodeString(report["receipt_signature"].(string))
	delete(report, "receipt_signature")
	binding, _ := core.Canonical(receiptBinding(report, "scan"))
	if !ed25519.Verify(sec.Private.Public().(ed25519.PublicKey), binding, sig) {
		t.Fatal("receipt")
	}
	service := &Service{Release: c.Release, Version: c.Version, Binary: c.Binary, Now: func() time.Time { return at.Add(781 * time.Second) }}
	invocation, _ := json.Marshal(Invocation{Config: c, Secret: sec, Token: j.Token, Start: at.Unix(), Pickup: at.Unix(), Capability: "signed", Snapshot: "invalid"})
	rr := httptest.NewRecorder()
	service.ServeHTTP(rr, httptest.NewRequest("POST", "/execute", bytes.NewReader(invocation)))
	if rr.Code != 403 {
		t.Fatal("deadline permitted", rr.Code)
	}
}
