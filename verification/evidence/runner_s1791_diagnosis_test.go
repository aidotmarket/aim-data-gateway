//go:build evidence

package evidence

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/config"
	"github.com/aidotmarket/aim-data-gateway/internal/gateway"
	"github.com/aidotmarket/aim-data-gateway/internal/pairing"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
)

// Backend source: 0f7b61ff, app/api/v1/endpoints/aim_gateway.py:581-587.
// The seven response fields below exactly match pair_gateway's return shape.
// gateway_id is normally uuid4(); minimum_version is a deployment setting not
// supplied in the incident facts (0.2.1 is a representative nonempty value).
// No key_expires field is emitted. Canary settings use the A4 required names.
// No backend signer private keys are needed for this pre-channel failure.
const s1791PairResponse = `{
  "gateway_id":"11111111-1111-4111-8111-111111111111",
  "permission_keys":[{"kid":"s1656-test-permission-v1","alg":"EdDSA","key":"avTT5ep67FVVOyPPyyWNUq5TxhoPzmMC8pLFuKlvPr4"}],
  "listing_keys":[{"kid":"s1656-test-listing-v1","alg":"EdDSA","key":"cbJu6RjRBO-uD9fV8c41j3UqupOmx6rsAJx-kkjNN6I"}],
  "scan_spec_keys":[{"kid":"s1656-test-scan_spec-v1","alg":"EdDSA","key":"NBFRkWH6jYBqYheyrCocvywEyZmcurMSXCXecHwqCeo"}],
  "minimum_version":"0.2.1",
  "canary_host":"s1656-egress-canary.ai.market",
  "canary_zone":"s1656-gw-canary.ai.market"
}`

func TestS1791A4InvalidVerification(t *testing.T) {
	const digest = "sha256:fe7c6cbdbf9aae906d033a9230316a8f6e415025179a47b54fe8ad1005514d1b"
	t.Setenv("AIM_GATEWAY_IMAGE_DIGEST", digest)
	t.Setenv("CP82_COMPOSE_CIDR", "172.28.90.0/24")
	t.Setenv("CP82_COMPOSE_BACKEND_IP", "172.28.90.5")
	var pins pairing.Pins
	must(t, json.Unmarshal([]byte(s1791PairResponse), &pins))
	var expected testPinExpectations
	for _, c := range []struct {
		name string
		key  wire.Key
		pin  *testPin
	}{{"PERMISSION", pins.PermissionKeys[0], &expected.Permission}, {"LISTING", pins.ListingKeys[0], &expected.Listing}, {"SCAN", pins.ScanSpecKeys[0], &expected.Scan}} {
		pub, err := base64.RawURLEncoding.DecodeString(c.key.Key)
		must(t, err)
		t.Setenv("TEST_"+c.name+"_PUBLIC_HEX", hex.EncodeToString(pub))
		t.Setenv("TEST_"+c.name+"_KID", c.key.KID)
		*c.pin = testPin{KID: os.Getenv("TEST_" + c.name + "_KID"), Public: pub}
	}
	for _, version := range []string{"0.2.1+s1656.cp82.a4", "0.2.1-s1656.cp82.a4", "0.2.1"} {
		t.Run(version, func(t *testing.T) {
			t.Setenv("TEST_SCANNER_VERSION", version)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var requests atomic.Int32
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != "POST" || r.URL.Path != "/api/v1/gateway-channel/pair" || r.TLS.ServerName != "backend" {
					t.Error("unexpected request", r.Method, r.URL.Path)
					http.Error(w, "unexpected request", 500)
					return
				}
				var body map[string]string
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["version"] != version || body["code"] != "local-diagnostic-only" {
					t.Error("unexpected pair body", body, err)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(s1791PairResponse))
			}))
			cert, ca := runnerTLSCertificate(t, "backend", false)
			srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
			srv.StartTLS()
			defer srv.Close()
			client := runnerLocalTLSClient(t, ca, srv.Listener.Addr().String())
			// Same RunEvidenceRunner sequence up to evidenceChannel, using the
			// existing A4 local socket injection so no Compose/live DNS is used.
			dir := filepath.Join(t.TempDir(), "fresh")
			must(t, os.Mkdir(dir, 0700))
			root, stateDir := filepath.Join(dir, "fixture"), filepath.Join(dir, "state")
			must(t, os.Mkdir(root, 0700))
			must(t, os.WriteFile(filepath.Join(root, "data.csv"), []byte(SyntheticFixture), 0600))
			state, err := pairing.Pair(ctx, stateDir, "local-diagnostic-only", version, "https://backend:8443/api/v1/gateway-channel/pair", client)
			must(t, err)
			t.Log("pairing.Pair (including ValidateKeySet): PASS, HTTP 200")
			must(t, validateTestPins(state.Pins, expected))
			t.Log("validateTestPins: PASS")
			cfg := config.Config{VerificationEnabled: true, Sources: []config.Source{{Name: "synthetic", Path: root}}}
			must(t, cfg.Validate())
			g, err := gateway.Open(stateDir, cfg, state)
			must(t, err)
			defer g.Ledger.Close()
			t.Log("gateway.Open: PASS")
			must(t, g.InitVerification(version))
			defer g.Verifier.Close()
			t.Log("InitVerification/OpenKeys: PASS; fresh binding has no Ack, VerifyBinding skipped")
			g.Verifier.HTTP = client
			must(t, g.Verifier.Start(ctx, stateDir))
			t.Log("Verifier.Start: PASS")
			body, err := g.Verifier.Keys.Registration(state.Pins.GatewayID, time.Now())
			must(t, err)
			t.Log("Keys.Registration: PASS")
			raw, err := wire.Canonical(body)
			must(t, err)
			validation := wire.ValidateScanReportBody(raw)
			err = g.RegisterVerification()
			if strings.Contains(version, "+") {
				if !errors.Is(validation, wire.ErrVerification) || !errors.Is(err, wire.ErrVerification) || g.Log.Sequence() != 0 {
					t.Fatal("expected registration rejection before audit append", validation, err, g.Log.Sequence())
				}
				t.Logf("RegisterVerification -> Log.Append -> wire.ValidateScanReportBody: %v; audit seq=0", err)
				// All other values unchanged: isolates scanner_version predicate.
				body["scanner_version"] = "0.2.1-s1656.cp82.a4"
				raw, err = wire.Canonical(body)
				must(t, err)
				must(t, wire.ValidateScanReportBody(raw))
				t.Log("changing only scanner_version '+' to '-': ValidateScanReportBody PASS")
			} else {
				must(t, validation)
				must(t, err)
				if g.Log.Sequence() != 1 {
					t.Fatal("registration not persisted")
				}
				t.Log("RegisterVerification: PASS; audit seq=1; ready for evidenceChannel")
			}
			if requests.Load() != 1 {
				t.Fatal("unexpected additional backend requests", requests.Load())
			}
			t.Log("backend requests=1 (pair only); stopped before channel/door/canary")
		})
	}
}
