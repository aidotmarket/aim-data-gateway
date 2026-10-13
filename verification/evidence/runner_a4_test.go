//go:build evidence

package evidence

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/canary"
	"github.com/aidotmarket/aim-data-gateway/internal/config"
	"github.com/aidotmarket/aim-data-gateway/internal/gateway"
	"github.com/aidotmarket/aim-data-gateway/internal/pairing"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	"github.com/coder/websocket"
)

func runnerTLSCertificate(t *testing.T, hostname string, expired bool) (tls.Certificate, []byte) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	must(t, err)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{hostname}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	if expired {
		leaf.NotAfter = now.Add(-time.Minute)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, pub, key)
	must(t, err)
	return tls.Certificate{Certificate: [][]byte{leafDER, der}, PrivateKey: key}, caPEM
}

// Redirect only the final socket to an isolated local test server. All URL,
// TLS/SNI/CA and proxy guards are the runner's; DNS/IP guards have separate tests.
func runnerLocalTLSClient(t *testing.T, ca []byte, address string) *http.Client {
	t.Helper()
	base, err := testBase("https://backend:8443")
	must(t, err)
	c, err := constrainedClient(base, "172.28.90.0/24", "172.28.90.5", ca)
	must(t, err)
	tr := c.Transport.(testTransport).next.(*http.Transport)
	if tr.Proxy != nil || tr.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.ServerName != "backend" {
		t.Fatal("TLS/proxy guards disabled")
	}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != "backend:8443" {
			return nil, errors.New("unexpected test dial")
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	t.Cleanup(tr.CloseIdleConnections)
	return c
}

func TestRunnerTLSAndWSS(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "http://127.0.0.1:1")
	for _, tc := range []struct {
		name, host               string
		expired, foreignCA, want bool
	}{
		{"test CA", "backend", false, false, true}, {"wrong hostname", "other", false, false, false},
		{"expired certificate", "backend", true, false, false}, {"foreign CA", "backend", false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert, ca := runnerTLSCertificate(t, tc.host, tc.expired)
			calls := 0
			s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.TLS.ServerName != "backend" {
					t.Error("wrong SNI")
				}
				if r.URL.Path == "/redirect" {
					http.Redirect(w, r, "https://api.ai.market/", http.StatusFound)
					return
				}
				if r.URL.Path == "/api/v1/gateway-channel" {
					ws, err := websocket.Accept(w, r, nil)
					if err != nil {
						t.Error(err)
						return
					}
					defer ws.CloseNow()
					_ = ws.Write(r.Context(), websocket.MessageText, []byte("unchanged.frame"))
					return
				}
				if r.URL.Path != "/api/v1/verification-runners/test/snapshot/hash" || r.Header.Get("Authorization") != "Bearer exact.signature" {
					t.Error("request mutated")
				}
				body, err := io.ReadAll(r.Body)
				if err != nil || string(body) != "exact-body" {
					t.Error("body mutated", err)
				}
				_, _ = io.WriteString(w, "exact.signed.snapshot")
			}))
			s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
			s.StartTLS()
			defer s.Close()
			if tc.foreignCA {
				_, ca = runnerTLSCertificate(t, "backend", false)
			}
			client := runnerLocalTLSClient(t, ca, s.Listener.Addr().String())
			req, err := http.NewRequest("GET", "https://api.ai.market/api/v1/verification-runners/test/snapshot/hash", strings.NewReader("exact-body"))
			must(t, err)
			req.Header.Set("Authorization", "Bearer exact.signature")
			resp, err := client.Do(req)
			if !tc.want {
				if err == nil {
					resp.Body.Close()
					t.Fatal("untrusted TLS accepted")
				}
				if calls != 0 {
					t.Fatal("untrusted TLS reached handler")
				}
				return
			}
			must(t, err)
			raw, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			must(t, err)
			if string(raw) != "exact.signed.snapshot" || resp.Request.URL.String() != req.URL.String() {
				t.Fatal("signed response/logical origin changed")
			}
			resp, err = client.Get("https://backend:8443/redirect")
			must(t, err)
			resp.Body.Close()
			if resp.StatusCode != http.StatusFound || calls != 2 {
				t.Fatal("redirect followed")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			ws, _, err := websocket.Dial(ctx, "wss://backend:8443/api/v1/gateway-channel", &websocket.DialOptions{HTTPClient: client})
			must(t, err)
			defer ws.CloseNow()
			_, frame, err := ws.Read(ctx)
			must(t, err)
			if string(frame) != "unchanged.frame" {
				t.Fatal("wss frame mutated")
			}
		})
	}
	base, err := testBase("https://backend:8443")
	must(t, err)
	for _, ca := range [][]byte{nil, []byte("not a CA")} {
		if _, err := constrainedClient(base, "172.28.90.0/24", "172.28.90.5", ca); err == nil {
			t.Fatal("missing/invalid CA accepted")
		}
	}
	_, ca := runnerTLSCertificate(t, "backend", false)
	if _, err := constrainedClient(base, "", "", ca); err == nil {
		t.Fatal("missing exact network/IP guard accepted")
	}
}

func TestRunnerDialPortAndMixedAnswer(t *testing.T) {
	d, err := newTestDialer("172.28.90.0/24", "172.28.90.5")
	must(t, err)
	d.resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("172.28.90.5"), netip.MustParseAddr("172.28.90.6")}, nil
	}
	d.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("refused destination dialed")
		return nil, nil
	}
	for _, addr := range []string{"backend:8000", "backend:443", "localhost:8443", "127.0.0.1:8443", "backend:8443"} {
		if _, err := d.DialContext(context.Background(), "tcp", addr); err == nil {
			t.Fatal("unsafe dial accepted", addr)
		}
	}
}

func runnerGateway(t *testing.T) (*gateway.Gateway, testPinExpectations) {
	t.Helper()
	expected, pins := runnerTestPins(t)
	pins.GatewayID = "11111111-1111-4111-8111-111111111111"
	pins.CanaryHost, pins.CanaryZone = "s1656-egress-canary.ai.market", "s1656-gw-canary.ai.market"
	_, key, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	g, err := gateway.Open(t.TempDir(), config.Config{VerificationEnabled: true}, pairing.State{Private: key, Secret: make([]byte, 32), Pins: pins})
	must(t, err)
	t.Cleanup(func() { _ = g.Ledger.Close() })
	must(t, g.InitVerification("1.2.3"))
	t.Cleanup(func() { g.Verifier.Close() })
	return g, expected
}

func TestRunnerDoorPairedIdentityAndRotation(t *testing.T) {
	g, expected := runnerGateway(t)
	c := evidenceChannel(g, "1.2.3", map[string]ed25519.PublicKey{expected.Scan.KID: expected.Scan.Public})
	d := evidenceDoor(g, c.PinsSnapshot, context.Background())
	if d.Server(":8082").Addr != ":8082" || d.GatewayID != c.State.Pins.GatewayID || !bytes.Equal(d.GatewayKey, c.State.Private) {
		t.Fatal("door identity/listener differs from channel")
	}
	server := httptest.NewServer(d.Handler())
	defer server.Close()
	nonce := strings.Repeat("a", 32)
	resp, err := server.Client().Get(server.URL + "/.well-known/aim-gateway?nonce=" + nonce)
	must(t, err)
	raw, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	must(t, err)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/jose" {
		t.Fatal("door statement failed")
	}
	parts := strings.Split(string(raw), ".")
	if len(parts) != 3 {
		t.Fatal("bad door JWT")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	must(t, err)
	pub := g.State.Private.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		t.Fatal("door signed with different identity")
	}
	claims, err := base64.RawURLEncoding.DecodeString(parts[1])
	must(t, err)
	var body struct{ GID, Nonce string }
	must(t, json.Unmarshal(claims, &body))
	if body.GID != g.State.Pins.GatewayID || body.Nonce != nonce {
		t.Fatal("wrong door gid/nonce")
	}
	if ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]+"tampered"), sig) {
		t.Fatal("altered statement verified")
	}
	for _, path := range []string{"/.well-known/aim-gateway", "/.well-known/aim-gateway?nonce=bad", "/unrelated"} {
		resp, err := server.Client().Get(server.URL + path)
		must(t, err)
		resp.Body.Close()
		if resp.StatusCode == 200 {
			t.Fatal("invalid nonce/path accepted", path)
		}
	}
	resp, err = server.Client().Post(server.URL+"/.well-known/aim-gateway?nonce="+nonce, "", nil)
	must(t, err)
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatal("door accepted POST")
	}
	_, next, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	pin := wire.Key{KID: "next-permission", Alg: "EdDSA", Key: base64.RawURLEncoding.EncodeToString(next.Public().(ed25519.PublicKey))}
	i := wire.Instruction{Op: "key_rotation", Audience: g.State.Pins.GatewayID, IID: "99999999-9999-4999-8999-999999999999", IssuedAt: time.Now().Unix(), Keys: []wire.Key{pin}}
	_, _, err = c.Handle(context.Background(), i, "permission", expected.Permission.KID)
	must(t, err)
	g.State.Pins.KeyExpires[expected.Permission.KID] = time.Now().Add(-time.Minute).Format(time.RFC3339Nano)
	keys := d.PermissionKeyProvider()
	if keys[expected.Permission.KID] != nil || !keys[pin.KID].Equal(next.Public()) || keys[expected.Listing.KID] != nil || keys[expected.Scan.KID] != nil {
		t.Fatal("door rotation/expiry/class boundary lost")
	}
	// Permission rotation cannot authorize a scan rotation into its KID.
	_, _, err = c.Handle(context.Background(), i, "scan", expected.Scan.KID)
	if err == nil {
		t.Fatal("scan rotation substituted permission KID")
	}
}

type runnerResolver func(context.Context, string) ([]net.IPAddr, error)

func (f runnerResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return f(ctx, host)
}

type runnerDial func(context.Context, string, string) (net.Conn, error)

func (f runnerDial) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

func TestRunnerCanaryProductProbeAndAudit(t *testing.T) {
	g, expected := runnerGateway(t)
	c := evidenceChannel(g, "1.2.3", map[string]ed25519.PublicKey{expected.Scan.KID: expected.Scan.Public})
	var queried string
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	defer listener.Close()
	// Only the test probe dependencies point at local fixtures. The live callback
	// above uses canary.Probe{} (actual system resolver/dialer), never a closed stub.
	probe := canary.Probe{Resolver: runnerResolver(func(_ context.Context, host string) ([]net.IPAddr, error) {
		queried = host
		return []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}}, nil
	}), Dialer: runnerDial(func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "s1656-egress-canary.ai.market:443" || network != "tcp" {
			t.Fatal("unexpected canary dial", address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
	})}
	callback := evidenceCanary(g, c.PinsSnapshot, probe)
	must(t, callback(context.Background()))
	e, err := g.Log.Read(g.Log.Sequence())
	must(t, err)
	var result wire.CanaryResult
	must(t, json.Unmarshal(e.Body, &result))
	if e.MessageType != "canary_result" || result.State != "open" || result.DNS != "open" || result.TCP != "open" || result.Proxy != "not_configured" || queried != result.Label+".s1656-gw-canary.ai.market" || !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(result.Label) {
		t.Fatal("probe result altered/fabricated", result)
	}
	if _, err := time.Parse(time.RFC3339, result.At); err != nil {
		t.Fatal(err)
	}
	seq := g.Log.Sequence()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Canary(ctx); !errors.Is(err, context.Canceled) || g.Log.Sequence() != seq {
		t.Fatal("canceled real canary appended a result", err)
	}
	g.State.Pins.CanaryHost = "egress-canary.ai.market"
	if callback(context.Background()) == nil || g.Log.Sequence() != seq {
		t.Fatal("foreign canary host accepted")
	}
	g.State.Pins.CanaryHost = "s1656-egress-canary.ai.market"
	g.Config.Egress.ConnectProxy = "localhost:3128"
	if callback(context.Background()) == nil || g.Log.Sequence() != seq {
		t.Fatal("CONNECT proxy accepted")
	}
}
