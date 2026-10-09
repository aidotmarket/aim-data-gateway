//go:build evidence

package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
		{"loopback", "localhost", "", "", []string{"127.0.0.1"}, ""},
		{"IPv6 loopback", "localhost", "", "", []string{"::1"}, ""},
		{"Compose", "backend", "172.28.90.0/24", "172.28.90.5", []string{"172.28.90.5"}, "172.28.90.5:8443"},
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
			_, err = d.DialContext(context.Background(), "tcp", net.JoinHostPort(tc.host, "8443"))
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
			if resolves != 1 && tc.host == "backend" {
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
	expected, good := runnerTestPins(t)
	must(t, validateTestPins(good, expected))
	classes := []struct {
		name string
		keys []wire.Key
	}{{"permission", good.PermissionKeys}, {"listing", good.ListingKeys}, {"scan-spec", good.ScanSpecKeys}}
	for _, class := range classes {
		for _, mutation := range []string{"missing", "wrong kid", "wrong key", "extra key", "wrong alg", "swap permission", "swap listing", "swap scan-spec"} {
			t.Run(class.name+"/"+mutation, func(t *testing.T) {
				p := good
				keys := slices.Clone(class.keys)
				switch mutation {
				case "missing":
					keys = nil
				case "wrong kid":
					keys[0].KID = "foreign"
				case "wrong key":
					keys[0].Key = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
				case "extra key":
					keys = append(keys, wire.Key{KID: "foreign"})
				case "wrong alg":
					keys[0].Alg = "RS256"
				default:
					for _, other := range classes {
						if mutation == "swap "+other.name {
							if class.name == other.name {
								return
							}
							keys = other.keys
						}
					}
				}
				switch class.name {
				case "permission":
					p.PermissionKeys = keys
				case "listing":
					p.ListingKeys = keys
				case "scan-spec":
					p.ScanSpecKeys = keys
				}
				if validateTestPins(p, expected) == nil {
					t.Fatal("unexpected class signer accepted")
				}
			})
		}
	}
	bad := expected
	bad.Listing.Public = expected.Permission.Public
	if bad.validate() == nil {
		t.Fatal("equal class keys accepted")
	}
	bad = expected
	bad.Scan.KID = "foreign"
	if bad.validate() == nil {
		t.Fatal("foreign expected KID accepted")
	}
}

func runnerTestPins(t *testing.T) (testPinExpectations, pairing.Pins) {
	t.Helper()
	var expected testPinExpectations
	for kid, pin := range map[string]*testPin{"s1656-test-permission-v1": &expected.Permission, "s1656-test-listing-v1": &expected.Listing, "s1656-test-scan_spec-v1": &expected.Scan} {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		must(t, err)
		*pin = testPin{kid, pub}
	}
	keys := func(p testPin) []wire.Key {
		return []wire.Key{{KID: p.KID, Alg: "EdDSA", Key: base64.RawURLEncoding.EncodeToString(p.Public)}}
	}
	return expected, pairing.Pins{PermissionKeys: keys(expected.Permission), ListingKeys: keys(expected.Listing), ScanSpecKeys: keys(expected.Scan)}
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
	c := evidenceChannel(g, "1.2.3", pins)
	control := c.Verification
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
	// Rotate through the same product callback used after channel verification.
	// Expired old keys remain historical, while only the new key admits work.
	_, next, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	i := wire.Instruction{Op: "key_rotation", Audience: j.Envelope.Audience, IID: "99999999-9999-4999-8999-999999999999", IssuedAt: now.Unix(), Keys: []wire.Key{{KID: "next-scan", Alg: "EdDSA", Key: base64.RawURLEncoding.EncodeToString(next.Public().(ed25519.PublicKey))}}}
	// Authentic outgoing signature is verified by the channel before Handle.
	g.State.Pins.KeyExpires["test-only-scan-key"] = now.Add(time.Hour).Format(time.RFC3339Nano)
	rotation, err := wire.Sign("aim-keys+jwt", "test-only-scan-key", i, key)
	must(t, err)
	verified, err := wire.VerifyScanRotation(rotation, g.Verifier.ActivePins())
	must(t, err)
	_, _, err = c.Handle(context.Background(), verified, "scan", "test-only-scan-key")
	must(t, err)
	g.State.Pins.KeyExpires["test-only-scan-key"] = now.Add(-time.Minute).Format(time.RFC3339Nano)
	if g.Verifier.ActivePins()["test-only-scan-key"] != nil || g.Verifier.Pins()["test-only-scan-key"] == nil || g.Verifier.ActivePins()["next-scan"] == nil {
		t.Fatal("product active/historical rotation providers changed")
	}
	if control(context.Background(), token) == nil {
		t.Fatal("retired key admitted work")
	}
	payload["platform_key_id"] = "next-scan"
	raw = canonical(t, payload)
	in["payload_b64"] = base64.RawURLEncoding.EncodeToString(raw)
	in["spec_hash"] = wire.Digest(raw)
	token, err = wire.Sign("aim-scan-spec+jwt", "next-scan", in, next)
	must(t, err)
	parts := strings.Split(snapshotToken, ".")
	snapshotBody, err := base64.RawURLEncoding.DecodeString(parts[1])
	must(t, err)
	snapshotToken, err = wire.Sign("aim-scan-snapshot+jwt", "next-scan", json.RawMessage(snapshotBody), next)
	must(t, err)
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
