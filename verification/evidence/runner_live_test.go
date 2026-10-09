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
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/audit"
	"github.com/aidotmarket/aim-data-gateway/internal/canary"
	"github.com/aidotmarket/aim-data-gateway/internal/channel"
	"github.com/aidotmarket/aim-data-gateway/internal/config"
	"github.com/aidotmarket/aim-data-gateway/internal/door"
	"github.com/aidotmarket/aim-data-gateway/internal/gateway"
	"github.com/aidotmarket/aim-data-gateway/internal/pairing"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
)

type RunnerOptions struct {
	BaseURL, PairingCode, Directory, Version string
	ComposeCIDR, ComposeBackendIP            string
	TestCA                                   []byte
	Expectations                             testPinExpectations
}

type testPin struct {
	KID    string
	Public ed25519.PublicKey
}
type testPinExpectations struct{ Permission, Listing, Scan testPin }

func (p testPinExpectations) validate() error {
	for _, c := range []struct {
		pin testPin
		kid string
	}{
		{p.Permission, "s1656-test-permission-v1"}, {p.Listing, "s1656-test-listing-v1"}, {p.Scan, "s1656-test-scan_spec-v1"},
	} {
		if c.pin.KID != c.kid || len(c.pin.Public) != ed25519.PublicKeySize {
			return errors.New("exact per-class S1656 public expectations required")
		}
	}
	if p.Permission.Public.Equal(p.Listing.Public) || p.Permission.Public.Equal(p.Scan.Public) || p.Listing.Public.Equal(p.Scan.Public) {
		return errors.New("test class keys must be distinct")
	}
	return nil
}

// TestRunnerS1656 is the opt-in executable entry point, not a unit test against
// the stack. Ordinary evidence test runs skip it before any filesystem/network
// operation. Compile with go test -c or invoke this test alone when authorized.
func TestRunnerS1656(t *testing.T) {
	if os.Getenv("CP82_RUNNER_ENABLE") != "1" {
		t.Skip("opt-in S1656 runner; set CP82_RUNNER_ENABLE=1 only for an authorized run")
	}
	var expectations testPinExpectations
	for name, pin := range map[string]*testPin{"PERMISSION": &expectations.Permission, "LISTING": &expectations.Listing, "SCAN": &expectations.Scan} {
		pub, err := hex.DecodeString(os.Getenv("TEST_" + name + "_PUBLIC_HEX"))
		if err != nil {
			t.Fatal("invalid public expectation", name)
		}
		*pin = testPin{os.Getenv("TEST_" + name + "_KID"), pub}
	}
	ca, err := os.ReadFile(os.Getenv("CP82_TEST_CA_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	base := os.Getenv("CP82_RUNNER_BACKEND")
	if base == "" {
		base = "https://backend:8443"
	}
	stopCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(stopCtx, 30*time.Minute)
	defer cancel()
	err = RunEvidenceRunner(ctx, RunnerOptions{BaseURL: base,
		PairingCode: os.Getenv("TEST_PAIRING_CODE"), Directory: os.Getenv("CP82_RUNNER_DIR"),
		Version: os.Getenv("TEST_SCANNER_VERSION"), Expectations: expectations, TestCA: ca,
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
	if o.PairingCode == "" || o.Directory == "" || o.Version == "" {
		return errors.New("pairing code, fresh directory and version are required")
	}
	if err = o.Expectations.validate(); err != nil {
		return err
	}
	if os.Getenv("AIM_GATEWAY_IMAGE_DIGEST") == "" {
		return errors.New("explicit test AIM_GATEWAY_IMAGE_DIGEST required for product registration")
	}
	httpClient, err := constrainedClient(base, o.ComposeCIDR, o.ComposeBackendIP, o.TestCA)
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
	pins := map[string]ed25519.PublicKey{o.Expectations.Scan.KID: o.Expectations.Scan.Public}
	if err = validateTestPins(state.Pins, o.Expectations); err != nil {
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
	server := evidenceDoor(g, c.PinsSnapshot, runCtx).Server(":8082")
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return fmt.Errorf("evidence door: %w", err)
	}
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Serve(listener); cancel() }()
	defer func() {
		shutdownCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = server.Shutdown(shutdownCtx)
	}()
	u := *base
	u.Scheme, u.Path = "wss", "/api/v1/gateway-channel"
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
		}
		return nil
	}
	// One native connection: a disconnect is visible evidence, not hidden by
	// the production Run reconnect loop. Operator can start a fresh run.
	err = c.Connect(runCtx)
	mu.Lock()
	defer mu.Unlock()
	select {
	case e := <-serverErr:
		return fmt.Errorf("evidence door stopped: %w", e)
	default:
	}
	// Stay connected for scheduled canary correlation/readiness. An operator
	// signal ends the run; timeout/disconnect never becomes success merely from acks.
	if complete && ctx.Err() == context.Canceled {
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

func validateTestPins(p pairing.Pins, expected testPinExpectations) error {
	if err := expected.validate(); err != nil {
		return err
	}
	for name, c := range map[string]struct {
		keys []wire.Key
		pin  testPin
	}{"permission": {p.PermissionKeys, expected.Permission}, "listing": {p.ListingKeys, expected.Listing}, "scan-spec": {p.ScanSpecKeys, expected.Scan}} {
		if len(c.keys) != 1 {
			return fmt.Errorf("test backend must supply %s pins", name)
		}
		for _, pin := range c.keys {
			pub, err := base64.RawURLEncoding.DecodeString(pin.Key)
			if err != nil || pin.Alg != "EdDSA" || pin.KID != c.pin.KID || !c.pin.Public.Equal(ed25519.PublicKey(pub)) {
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
	pins = maps.Clone(pins)
	c := &channel.Client{State: &g.State, Log: g.Log, Version: version,
		Complete: func(ctx context.Context, iid string) error { _, err := g.Ledger.Seen(ctx, iid); return err },
		Scan:     g.Scan, Poll: g.Poll, Delivered: g.Delivered, Reconcile: g.Reconcile,
		VerificationRefused: g.Verifier.QueueRefusal}
	c.Handle = func(ctx context.Context, i wire.Instruction, class, signer string) (string, any, error) {
		mu.Lock()
		defer mu.Unlock()
		typ, body, err := g.Handle(ctx, i, class, signer)
		// Only authenticated scan-class product rotation extends the extra
		// scan restriction. Permission/listing rotations never populate it.
		if err == nil && i.Op == "key_rotation" && class == "scan" {
			for _, k := range g.State.Pins.ScanSpecKeys {
				pub, e := base64.RawURLEncoding.DecodeString(k.Key)
				if e == nil && k.Alg == "EdDSA" && len(pub) == ed25519.PublicKeySize {
					pins[k.KID] = ed25519.PublicKey(pub)
				}
			}
		}
		return typ, body, err
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
	c.Canary = evidenceCanary(g, c.PinsSnapshot, canary.Probe{})
	return c
}

func evidenceCanary(g *gateway.Gateway, snapshot func() pairing.Pins, probe canary.Probe) func(context.Context) error {
	return func(ctx context.Context) error {
		p := snapshot()
		if p.CanaryHost != "s1656-egress-canary.ai.market" || p.CanaryZone != "s1656-gw-canary.ai.market" || g.Config.Egress.ConnectProxy != "" {
			return errors.New("exact S1656 canary hosts and no CONNECT proxy required")
		}
		result, err := probe.Run(ctx, p.CanaryHost, p.CanaryZone, g.Config.Egress.ConnectProxy)
		if err != nil {
			return err
		}
		_, err = g.Log.Append("canary_result", result)
		return err
	}
}

func evidenceDoor(g *gateway.Gateway, snapshot func() pairing.Pins, ctx context.Context) *door.Door {
	return &door.Door{Ledger: g.Ledger, Config: func() config.Config { return g.Config }, GatewayID: g.State.Pins.GatewayID,
		GatewayKey: g.State.Private, GatewayKID: "gateway", RecoveryContext: ctx,
		PermissionKeyProvider: func() map[string]ed25519.PublicKey {
			p := snapshot()
			keys := map[string]ed25519.PublicKey{}
			for _, k := range p.PermissionKeys {
				if at := p.KeyExpires[k.KID]; at != "" {
					deadline, err := time.Parse(time.RFC3339Nano, at)
					if err != nil || !time.Now().Before(deadline) {
						continue
					}
				}
				pub, err := base64.RawURLEncoding.DecodeString(k.Key)
				if err == nil && k.Alg == "EdDSA" && len(pub) == ed25519.PublicKeySize {
					keys[k.KID] = ed25519.PublicKey(pub)
				}
			}
			return keys
		}}
}
