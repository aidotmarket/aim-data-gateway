//go:build evidence

package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/config"
	"github.com/aidotmarket/aim-data-gateway/internal/gateway"
	"github.com/aidotmarket/aim-data-gateway/internal/inventory"
	"github.com/aidotmarket/aim-data-gateway/internal/ledger"
	"github.com/aidotmarket/aim-data-gateway/internal/pairing"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	core "github.com/aidotmarket/aim-data-gateway/verification"
)

func TestRunnerResolvedDestinationBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, host, cidr, backend string
		ips                       []string
		want                      string
	}{
		{"loopback", "localhost", "", "", []string{"127.0.0.1"}, "127.0.0.1:8000"},
		{"IPv6 loopback", "localhost", "", "", []string{"::1"}, "[::1]:8000"},
		{"Compose", "backend", "172.28.90.0/24", "172.28.90.5", []string{"172.28.90.5"}, "172.28.90.5:8000"},
		{"public localhost", "localhost", "", "", []string{"8.8.8.8"}, ""},
		{"public backend", "backend", "172.28.90.0/24", "172.28.90.5", []string{"8.8.8.8"}, ""},
		{"mixed answer", "localhost", "", "", []string{"127.0.0.1", "8.8.8.8"}, ""},
		{"wrong Compose peer", "backend", "172.28.90.0/24", "172.28.90.5", []string{"172.28.90.6"}, ""},
		{"outside Compose", "backend", "172.28.90.0/24", "172.28.90.5", []string{"172.28.91.5"}, ""},
		{"unconstrained backend", "backend", "", "", []string{"172.28.90.5"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := newTestDialer(tc.cidr, tc.backend)
			must(t, err)
			resolves, calls := 0, 0
			d.resolve = func(context.Context, string) ([]netip.Addr, error) {
				resolves++
				var ips []netip.Addr
				for _, ip := range tc.ips {
					ips = append(ips, netip.MustParseAddr(ip))
				}
				return ips, nil
			}
			d.dial = func(_ context.Context, network, address string) (net.Conn, error) {
				calls++
				if address != tc.want || network != "tcp" {
					t.Fatalf("unvalidated dial %s %s", network, address)
				}
				return nil, nil
			}
			_, err = d.DialContext(context.Background(), "tcp", net.JoinHostPort(tc.host, "8000"))
			if tc.want == "" {
				if err == nil || calls != 0 {
					t.Fatal("refused resolution connected", err, calls)
				}
			} else {
				must(t, err)
				if calls != 1 {
					t.Fatal(calls)
				}
			}
			if resolves != 1 {
				t.Fatal("unexpected re-resolution", resolves)
			}
		})
	}
	for _, tc := range [][2]string{{"0.0.0.0/0", "8.8.8.8"}, {"172.28.0.0/16", "172.28.90.5"}, {"172.28.90.1/24", "172.28.90.5"}, {"172.28.90.0/24", "172.28.91.5"}, {"", "172.28.90.5"}, {"172.28.90.0/24", ""}} {
		if _, err := newTestDialer(tc[0], tc[1]); err == nil {
			t.Fatal("unsafe Compose constraint", tc)
		}
	}
}

func TestRunnerAllSignerClasses(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	pin := wire.Key{KID: "approved", Alg: "EdDSA", Key: base64.RawURLEncoding.EncodeToString(pub)}
	good := pairing.Pins{PermissionKeys: []wire.Key{pin}, ListingKeys: []wire.Key{pin}, ScanSpecKeys: []wire.Key{pin}}
	must(t, validateTestPins(good, "approved", pub))
	for _, class := range []string{"permission", "listing", "scan-spec"} {
		for _, mutation := range []string{"missing", "wrong kid", "wrong key", "extra key", "wrong alg"} {
			t.Run(class+"/"+mutation, func(t *testing.T) {
				p := good
				keys := []wire.Key{pin}
				switch mutation {
				case "missing":
					keys = nil
				case "wrong kid":
					keys[0].KID = "other"
				case "wrong key":
					keys[0].Key = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
				case "extra key":
					keys = append(keys, wire.Key{KID: "other"})
				case "wrong alg":
					keys[0].Alg = "other"
				}
				switch class {
				case "permission":
					p.PermissionKeys = keys
				case "listing":
					p.ListingKeys = keys
				case "scan-spec":
					p.ScanSpecKeys = keys
				}
				if validateTestPins(p, "approved", pub) == nil {
					t.Fatal("unexpected signer accepted")
				}
			})
		}
	}
}

func TestRunnerProductAdmissionWithPairedExpiry(t *testing.T) {
	v := vector(t, "scan_spec")
	in := v["input"].(map[string]any)
	seed, err := hex.DecodeString(v["test_only_seed_hex"].(string))
	must(t, err)
	key := ed25519.NewKeyFromSeed(seed)
	pub := key.Public().(ed25519.PublicKey)
	pins := map[string]ed25519.PublicKey{"test-only-scan-key": pub}
	raw, err := wire.DecodeDocument(in["payload_b64"].(string), 40000)
	must(t, err)
	parsed, err := core.ParseCanonical(raw)
	must(t, err)
	payload := parsed.(map[string]any)
	now := time.Now().UTC().Truncate(time.Second)
	for _, field := range []string{"accepted_at_utc", "issued_at_utc"} {
		payload[field] = now.Format("2006-01-02T15:04:05.000000Z")
	}
	payload["expires_at_utc"] = now.Add(10 * time.Minute).Format("2006-01-02T15:04:05.000000Z")
	raw = canonical(t, payload)
	in["payload_b64"] = base64.RawURLEncoding.EncodeToString(raw)
	in["spec_hash"] = wire.Digest(raw)
	in["iat"] = now.Unix()
	token, err := wire.Sign("aim-scan-spec+jwt", "test-only-scan-key", in, key)
	must(t, err)
	j, err := wire.VerifyScan(token, pins, in["aud"].(string), in["runner_id"].(string), "1.2.3", now)
	must(t, err)
	_, identity, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	dir, err := filepath.EvalSymlinks(t.TempDir())
	must(t, err)
	state := pairing.State{Private: identity, Secret: make([]byte, 32), Pins: pairing.Pins{GatewayID: j.Envelope.Audience, ScanSpecKeys: []wire.Key{{KID: "test-only-scan-key", Alg: "EdDSA", Key: base64.RawURLEncoding.EncodeToString(pub)}}, KeyExpires: map[string]string{"test-only-scan-key": now.Add(-time.Minute).Format(time.RFC3339Nano)}}}
	cfg := config.Config{VerificationEnabled: true, Sources: []config.Source{{Name: "data", Path: dir}}, OfferCeiling: []string{"data/*"}}
	g, err := gateway.Open(dir, cfg, state)
	must(t, err)
	defer g.Ledger.Close()
	must(t, g.InitVerification("1.2.3"))
	defer g.Verifier.Close()
	// Only the fixture registration binding is set locally, never the providers.
	g.Verifier.Keys.Binding.RunnerID = j.Envelope.RunnerID
	g.Verifier.Keys.Binding.ScannerVersion = "1.2.3"
	g.Verifier.Keys.Binding.ReceiptKeyID = "77777777-7777-4777-8777-777777777777"
	g.Verifier.Keys.Binding.Ack = "fixture-ack"
	snapshot := vector(t, "snapshot")
	snapshotToken := snapshot["token"].(string)
	s, err := wire.VerifySnapshot(snapshotToken, pins, j)
	must(t, err)
	for i, m := range s.Members {
		data, err := hex.DecodeString(snapshot["source_hex"].(map[string]any)[m.FileID].(string))
		must(t, err)
		name := fmt.Sprintf("file%d.csv", i)
		must(t, os.WriteFile(filepath.Join(dir, name), data, 0600))
		rec := inventory.Record{Phase1: inventory.Phase1{FileID: m.FileID, SizeBytes: m.Size, Present: true}, Root: dir, Source: "data", RelativePath: name}
		sha, err := hex.DecodeString(m.SHA256)
		must(t, err)
		copy(rec.SHA256[:], sha)
		must(t, g.Ledger.PutFile(context.Background(), rec))
		must(t, g.Ledger.PutOffer(context.Background(), ledger.Offer{FileID: m.FileID, SHA256: m.SHA256, ListingVersionID: s.ListingVersionID, IID: "offer", State: "offered", KeyClass: "listing"}))
	}
	fetches := 0
	g.Verifier.HTTP = &http.Client{Transport: trip(func(req *http.Request) (*http.Response, error) { fetches++; return response(req, snapshotToken), nil })}
	control := evidenceChannel(g, "1.2.3", pins).Verification
	must(t, g.Verifier.Start(context.Background(), dir))
	// With the worker ready, exercise expiry: no snapshot fetch or admission.
	if err = control(context.Background(), token); err == nil {
		t.Fatal("expired paired key admitted work")
	}
	if fetches != 0 {
		t.Fatal("expired signer fetched snapshot")
	}
	if _, err = g.Ledger.Verification(context.Background(), j.Text("spec_id")); err == nil {
		t.Fatal("expired signer created admission")
	}
	// Paired state changes remain visible to the providers installed by the product.
	g.State.Pins.KeyExpires["test-only-scan-key"] = now.Add(time.Hour).Format(time.RFC3339Nano)
	must(t, control(context.Background(), token))
	if fetches != 1 {
		t.Fatal("valid work did not reach product Submit snapshot path", fetches)
	}
	a, err := g.Ledger.Verification(context.Background(), j.Text("spec_id"))
	must(t, err)
	if string(a.Spec) != token {
		t.Fatal("product did not durably admit exact token")
	}
}
