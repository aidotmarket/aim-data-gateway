//go:build evidence

package evidence

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/audit"
	"github.com/aidotmarket/aim-data-gateway/internal/channel"
	"github.com/aidotmarket/aim-data-gateway/internal/config"
	"github.com/aidotmarket/aim-data-gateway/internal/gateway"
	"github.com/aidotmarket/aim-data-gateway/internal/pairing"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
)

type RunnerOptions struct {
	BaseURL, PairingCode, Directory, Version, SignerKID string
	ComposeCIDR, ComposeBackendIP                       string
	SignerPublic                                        ed25519.PublicKey
}

// TestRunnerS1656 is the opt-in executable entry point, not a unit test against
// the stack. Ordinary evidence test runs skip it before any filesystem/network
// operation. Compile with go test -c or invoke this test alone when authorized.
func TestRunnerS1656(t *testing.T) {
	if os.Getenv("CP82_RUNNER_ENABLE") != "1" {
		t.Skip("opt-in S1656 runner; set CP82_RUNNER_ENABLE=1 only for an authorized run")
	}
	pub, err := hex.DecodeString(os.Getenv("TEST_SCAN_PUBLIC_HEX"))
	if err != nil {
		t.Fatal(err)
	}
	base := os.Getenv("CP82_RUNNER_BACKEND")
	if base == "" {
		base = "http://localhost:18000"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	err = RunEvidenceRunner(ctx, RunnerOptions{BaseURL: base,
		PairingCode: os.Getenv("TEST_PAIRING_CODE"), Directory: os.Getenv("CP82_RUNNER_DIR"),
		Version: os.Getenv("TEST_SCANNER_VERSION"), SignerKID: os.Getenv("TEST_SCAN_KID"), SignerPublic: pub,
		ComposeCIDR: os.Getenv("CP82_COMPOSE_CIDR"), ComposeBackendIP: os.Getenv("CP82_COMPOSE_BACKEND_IP")})
	if err != nil {
		t.Fatal(err)
	}
	t.Log("TEST backend acknowledged product probe and scan frames; retained local audit is evidence only")
}

// RunEvidenceRunner runs only the customer lane. The browser/backend must issue
// real offers, consent, probe work and authorized scan work; no specs are minted
// here and no listing, epoch or payment state is written directly.
func RunEvidenceRunner(ctx context.Context, o RunnerOptions) error {
	base, err := testBase(o.BaseURL)
	if err != nil {
		return err
	}
	if o.PairingCode == "" || o.Directory == "" || o.Version == "" || o.SignerKID == "" || len(o.SignerPublic) != ed25519.PublicKeySize {
		return errors.New("pairing code, fresh directory, version and test signer are required")
	}
	if os.Getenv("AIM_GATEWAY_IMAGE_DIGEST") == "" {
		return errors.New("explicit test AIM_GATEWAY_IMAGE_DIGEST required for product registration")
	}
	httpClient, err := constrainedClient(base, o.ComposeCIDR, o.ComposeBackendIP)
	if err != nil {
		return err
	}
	dir, err := filepath.Abs(o.Directory)
	if err != nil {
		return err
	}
	// Refuse reuse: state and source bytes cannot come from another customer run.
	if err = os.Mkdir(dir, 0700); err != nil {
		return fmt.Errorf("fresh evidence directory: %w", err)
	}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}
	root, stateDir := filepath.Join(dir, "fixture"), filepath.Join(dir, "state")
	if err = os.Mkdir(root, 0700); err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(root, "data.csv"), []byte(SyntheticFixture), 0600); err != nil {
		return err
	}
	state, err := pairing.Pair(ctx, stateDir, o.PairingCode, o.Version, base.String()+"/api/v1/gateway-channel/pair", httpClient)
	if err != nil {
		return err
	}
	pins := map[string]ed25519.PublicKey{o.SignerKID: o.SignerPublic}
	if err = validateTestPins(state.Pins, o.SignerKID, o.SignerPublic); err != nil {
		return err
	}
	cfg := config.Config{VerificationEnabled: true, Sources: []config.Source{{Name: "synthetic", Path: root}}}
	if err = cfg.Validate(); err != nil {
		return err
	}
	g, err := gateway.Open(stateDir, cfg, state)
	if err != nil {
		return err
	}
	defer g.Ledger.Close()
	if err = g.InitVerification(o.Version); err != nil {
		return err
	}
	defer g.Verifier.Close()
	g.Verifier.HTTP = httpClient
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if err = g.Verifier.Start(runCtx, stateDir); err != nil {
		return err
	}
	if err = g.RegisterVerification(); err != nil {
		return err
	}
	c := evidenceChannel(g, o.Version, pins)
	u := *base
	u.Scheme, u.Path = "ws", "/api/v1/gateway-channel"
	c.URL, c.HTTPClient = u.String(), httpClient
	var mu sync.Mutex
	seen := map[string]bool{}
	complete := false
	delivered := c.Delivered
	c.Delivered = func(ctx context.Context, entry audit.Entry) error {
		if err := delivered(ctx, entry); err != nil {
			return err
		}
		mu.Lock()
		defer mu.Unlock()
		// Acks are cumulative; inspect the actual durable product frames.
		for seq := uint64(1); seq <= entry.Seq; seq++ {
			e, err := g.Log.Read(seq)
			if err != nil {
				return err
			}
			if e.MessageType != "scan_report" {
				continue
			}
			var body struct {
				Variant string `json:"variant"`
			}
			if err = json.Unmarshal(e.Body, &body); err != nil {
				return err
			}
			if body.Variant == "terminal" {
				return errors.New("product scanner returned terminal report; retained in audit")
			}
			seen[body.Variant] = true
		}
		if seen["probe"] && seen["scan"] {
			complete = true
			cancel()
		}
		return nil
	}
	// One native connection: a disconnect is visible evidence, not hidden by
	// the production Run reconnect loop. Operator can start a fresh run.
	err = c.Connect(runCtx)
	mu.Lock()
	defer mu.Unlock()
	if complete {
		return nil
	}
	if err == nil {
		return errors.New("channel ended before probe and scan acknowledgments")
	}
	return err
}

func splitHeader(token string) (wire.Header, error) {
	var h wire.Header
	// This only dispatches control types; product code verifies all signatures.
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return h, wire.ErrVerification
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return h, err
	}
	err = json.Unmarshal(raw, &h)
	return h, err
}

// The explicit signer is an extra restriction; InitVerification retains ownership
// of historical and active admission pins, including expiry and paired rotation.
func restrictedControl(g *gateway.Gateway, version string, pins map[string]ed25519.PublicKey) func(context.Context, string) error {
	return func(ctx context.Context, token string) error {
		h, err := splitHeader(token)
		if err != nil {
			return err
		}
		if h.Type == "aim-scan-spec+jwt" {
			b := g.Verifier.Keys.Snapshot()
			if _, err = wire.VerifyScan(token, pins, g.State.Pins.GatewayID, b.RunnerID, version, time.Now()); err != nil {
				return err
			}
		}
		return g.VerificationControl(ctx, token)
	}
}

func validateTestPins(p pairing.Pins, kid string, key ed25519.PublicKey) error {
	for name, keys := range map[string][]wire.Key{"permission": p.PermissionKeys, "listing": p.ListingKeys, "scan-spec": p.ScanSpecKeys} {
		if len(keys) == 0 {
			return fmt.Errorf("test backend must supply %s pins", name)
		}
		for _, pin := range keys {
			pub, err := base64.RawURLEncoding.DecodeString(pin.Key)
			if err != nil || pin.Alg != "EdDSA" || pin.KID != kid || !key.Equal(ed25519.PublicKey(pub)) {
				return fmt.Errorf("paired %s pins differ from explicit test signer", name)
			}
		}
	}
	return nil
}

// Serialize paired-state changes from channel callbacks with the test-side pin
// snapshot. Product Handle/VerificationControl still own rotation and admission.
func evidenceChannel(g *gateway.Gateway, version string, pins map[string]ed25519.PublicKey) *channel.Client {
	var mu sync.Mutex
	c := &channel.Client{State: &g.State, Log: g.Log, Version: version,
		Complete: func(ctx context.Context, iid string) error { _, err := g.Ledger.Seen(ctx, iid); return err },
		Scan:     g.Scan, Poll: g.Poll, Delivered: g.Delivered, Reconcile: g.Reconcile,
		VerificationRefused: g.Verifier.QueueRefusal}
	c.Handle = func(ctx context.Context, i wire.Instruction, class, signer string) (string, any, error) {
		mu.Lock()
		defer mu.Unlock()
		return g.Handle(ctx, i, class, signer)
	}
	control := restrictedControl(g, version, pins)
	c.Verification = func(ctx context.Context, token string) error {
		mu.Lock()
		defer mu.Unlock()
		return control(ctx, token)
	}
	c.PinsSnapshot = func() pairing.Pins {
		mu.Lock()
		defer mu.Unlock()
		p := g.State.Pins
		p.PermissionKeys = slices.Clone(p.PermissionKeys)
		p.ListingKeys = slices.Clone(p.ListingKeys)
		p.ScanSpecKeys = slices.Clone(p.ScanSpecKeys)
		p.KeyExpires = maps.Clone(p.KeyExpires)
		return p
	}
	return c
}
