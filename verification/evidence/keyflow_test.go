//go:build evidence

package evidence

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"

	aws "github.com/aidotmarket/aim-data-gateway/internal/awsverification"
	cf "github.com/aidotmarket/aim-data-gateway/internal/cloudflareverification"
	gw "github.com/aidotmarket/aim-data-gateway/internal/verification"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
)

// Hooks observe exactly the E2 frames with the corresponding live local key;
// keys never enter durable evidence. These tests deliberately run serially.
var keyObserver func(*harness)
var frameObserver func(*testing.T, string, string, []byte)

func TestE3KeyAbsenceE2Frames(t *testing.T) {
	keys := map[string][32]byte{}
	var rows []map[string]any
	keyObserver = func(h *harness) { keys[h.kind] = h.key }
	frameObserver = func(t *testing.T, kind, class string, raw []byte) {
		key := keys[kind]
		if key == [32]byte{} {
			t.Fatal("no key observed")
		}
		forms := [][]byte{key[:], []byte(hex.EncodeToString(key[:])), []byte(base64.RawURLEncoding.EncodeToString(key[:])), []byte(base64.StdEncoding.EncodeToString(key[:]))}
		hits := 0
		searchLayers(raw, func(layer []byte) {
			for _, form := range forms {
				hits += bytes.Count(layer, form)
			}
		}, 0)
		// Also catch JSON integer-array serialization of a [32]byte secret.
		var walk func(any)
		walk = func(v any) {
			switch x := v.(type) {
			case map[string]any:
				for _, y := range x {
					walk(y)
				}
			case []any:
				b := make([]byte, len(x))
				ok := true
				for i, y := range x {
					n, yes := y.(float64)
					if !yes || n < 0 || n > 255 || float64(byte(n)) != n {
						ok = false
						break
					}
					b[i] = byte(n)
				}
				if ok && bytes.Equal(b, key[:]) {
					hits++
				}
				for _, y := range x {
					walk(y)
				}
			}
		}
		var v any
		if json.Unmarshal(raw, &v) == nil {
			walk(v)
		}
		rows = append(rows, map[string]any{"kind": kind, "class": class, "sha256": wire.Digest(raw), "key_hits": hits})
		if hits != 0 {
			t.Errorf("commitment key leaked in %s/%s", kind, class)
		}
	}
	defer func() { keyObserver = nil; frameObserver = nil }()
	TestE2ByteCaptures(t)
	writeJSON(t, filepath.Join(keyflowDir, "absence.json"), map[string]any{"authority": cp81Authority, "frames": rows})
}

// A repeatable test-only reader identifies data flow from CSPRNG to the
// commitment key. Production crypto/rand.Reader is restored before return.
type entropy struct {
	seed    string
	counter int
	pending []byte
}

func (e *entropy) Read(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		if len(e.pending) == 0 {
			d := sha256.Sum256([]byte(fmt.Sprintf("%s/%d", e.seed, e.counter)))
			e.counter++
			e.pending = d[:]
		}
		k := copy(p, e.pending)
		p = p[k:]
		e.pending = e.pending[k:]
	}
	return n, nil
}

func generated(t *testing.T, kind, seed string, hostile bool) ([32]byte, ed25519.PrivateKey) {
	t.Helper()
	old := rand.Reader
	rand.Reader = &entropy{seed: seed}
	defer func() { rand.Reader = old }()
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	version := "1.2.3"
	connection := "11111111-1111-4111-8111-111111111111"
	if hostile {
		version = "cloud-selected-version"
		connection = "22222222-2222-4222-8222-222222222222"
	}
	switch kind {
	case "aim_gateway":
		k, e := gw.OpenKeys(t.TempDir(), version, "sha256:"+strings.Repeat("a", 64))
		must(t, e)
		return k.Commitment, k.Private
	case "aws_s3_verifier":
		c := aws.Config{Connection: connection, Bucket: "cloud-bucket", Version: version, Digest: "sha256:" + strings.Repeat("a", 64), Token: token}
		s := &secretStore{}
		_, e := aws.Bootstrap(ctx, c, aws.Ledger{Client: bootstrapDB{}, Table: "evidence"}, s, stopRegistration{}, at)
		if e == nil || s.secret == nil {
			t.Fatal("expected persisted key before registration stop")
		}
		return s.secret.Commitment, s.secret.Private
	default:
		c := cf.Config{ConfigHash: strings.Repeat("d", 64), Connection: connection, Bucket: "cloud-bucket", Jurisdiction: "default", Keys: []string{"a.csv"}, Token: token, Version: version, Release: "cloudflare-verifier-v1", Binary: strings.Repeat("b", 64), Worker: cf.WorkerIdentity{Mode: "bundle", SHA256: strings.Repeat("c", 64)}}
		if hostile {
			c.ConfigHash = strings.Repeat("e", 64)
			c.Keys = []string{"hostile.csv"}
			c.Worker.SHA256 = strings.Repeat("f", 64)
		}
		s, e := cf.CreateSecret(c, at)
		must(t, e)
		return s.Commitment, s.Private
	}
}

type hostileCFBackend struct{ cf.Backend }

func (hostileCFBackend) Register(_ context.Context, _ []byte) (cf.RegistrationAck, error) {
	return cf.RegistrationAck{Runner: "cloud-commitment-key-selector", Receipt: "seed-from-cloud"}, nil
}

type hostileAWSBackend struct {
	aws.Backend
	store  *secretStore
	before [32]byte
}

func (b *hostileAWSBackend) Register(_ context.Context, _ []byte) (aws.RegistrationAck, error) {
	b.before = b.store.secret.Commitment
	return aws.RegistrationAck{Runner: "cloud-commitment-key-selector", Receipt: "seed-from-cloud"}, nil
}

func TestE3LocalEntropyAndInputIndependence(t *testing.T) {
	var rows []map[string]any
	for _, kind := range kinds {
		t.Run(kind, func(t *testing.T) {
			key, receipt := generated(t, kind, "entropy-a", false)
			for _, name := range []string{"AIM_COMMITMENT_KEY", "AIM_COMMITMENT_SEED", "AIM_COMMITMENT_KEY_SELECTOR", "DETERMINISTIC_SEED", "VERIFICATION_COMMITMENT_KEY", "VERIFICATION_RECEIPT_KEY"} {
				t.Setenv(name, strings.Repeat("7", 64))
			}
			same, _ := generated(t, kind, "entropy-a", true)
			other, _ := generated(t, kind, "entropy-b", true)
			if same != key {
				t.Fatal("cloud configuration/environment affected commitment key under identical local entropy")
			}
			if other == key {
				t.Fatal("different local entropy did not change commitment key")
			}
			if bytes.Equal(key[:], receipt.Seed()) {
				t.Fatal("commitment key equals receipt seed")
			}
			h := newHarness(t, kind)
			before := h.key
			h.seed = strings.Repeat("7", 64) // signed spec deterministic_seed controls traversal, not HMAC key.
			frame := h.scan(t, []file{{Key: "cloud-selected-snapshot.csv", Format: "csv", Data: []byte("id\n1\n2\n")}}, "scan")
			if h.key != before {
				t.Fatal("spec/snapshot changed key")
			}
			switch kind {
			case "aim_gateway":
				if h.gateway.Keys.Commitment != before {
					t.Fatal("scanner mutated retained key")
				}
			case "aws_s3_verifier":
				if h.awsSecret.Commitment != before {
					t.Fatal("scanner mutated retained key")
				}
			case "r2_verifier":
				if h.cfSecret.Commitment != before {
					t.Fatal("scanner mutated retained key")
				}
			}
			_, doc := document(t, frame)
			j := job(t, kind, "scan")
			// The harness snapshot hash is known; exact gateway HMAC preimage uses it.
			files := []file{{Key: "cloud-selected-snapshot.csv", Format: "csv", Data: []byte("id\n1\n2\n")}}
			snapshotHash := wire.Digest(canonical(t, files))
			preimage := "gateway_listing\x00" + j.Envelope.Audience + "\x00" + snapshotHash
			if kind != "aim_gateway" {
				preimage = cloudLocatorPreimage(t, kind, j, snapshotHash)
			}
			candidates := [][]byte{h.private.Seed(), h.private.Public().(ed25519.PublicKey), []byte(j.Text("deterministic_seed")), []byte(snapshotHash), []byte(j.Text("runner_id"))}
			for _, candidate := range candidates {
				d := sha256.Sum256(candidate)
				for _, k := range [][]byte{candidate, d[:]} {
					mac := hmac.New(sha256.New, k)
					_, _ = io.WriteString(mac, preimage)
					if hex.EncodeToString(mac.Sum(nil)) == doc["artifact_locator_commitment"] {
						t.Fatal("public/receipt-derived candidate recovered commitment")
					}
				}
			}
			// Positive control: local key with exact preimage must recover commitment.
			mac := hmac.New(sha256.New, h.key[:])
			_, _ = io.WriteString(mac, preimage)
			if hex.EncodeToString(mac.Sum(nil)) != doc["artifact_locator_commitment"] {
				t.Fatal("HMAC positive control failed", kind)
			}
			switch kind {
			case "aim_gateway":
				_ = h.gateway.Keys.Acknowledge("cloud-key-seed-selector", h.gateway.GatewayID, nil, at)
				if h.gateway.Keys.Commitment != before {
					t.Fatal("registration response changed key")
				}
			case "r2_verifier":
				h.cfSecret.Runner = ""
				h.cfSecret.Receipt = ""
				_ = cf.Register(ctx, h.cfConfig, h.cfSecret, hostileCFBackend{})
				if h.cfSecret.Commitment != before {
					t.Fatal("registration response changed key")
				}
			case "aws_s3_verifier":
				store := &secretStore{}
				backend := &hostileAWSBackend{store: store}
				_, err := aws.Bootstrap(ctx, h.awsConfig, aws.Ledger{Client: bootstrapDB{}, Table: "evidence"}, store, backend, at)
				if err == nil || store.secret == nil || backend.before == [32]byte{} || store.secret.Commitment != backend.before {
					t.Fatal("registration response altered key or was not exercised")
				}
			}
			rows = append(rows, map[string]any{"kind": kind, "same_entropy_cloud_changes_key_unchanged": true, "different_entropy_changes_key": true, "spec_snapshot_key_unchanged": true, "candidate_attempts": len(candidates) * 2, "local_hmac_positive_control": true})
		})
	}
	writeJSON(t, filepath.Join(keyflowDir, "independence.json"), map[string]any{"authority": cp81Authority, "results": rows, "limits": "Finite candidate attacks and controlled entropy are data-flow evidence, not a proof against every mathematical derivation. See source audit for accepted input surface."})
}

func cloudLocatorPreimage(t *testing.T, kind string, j wire.ScanJob, hash string) string {
	// Keep this explicit and independently checked by the positive control.
	source := map[string]string{"aws_s3_verifier": "s3_listing", "r2_verifier": "r2_listing"}[kind]
	return source + "\x00" + markers[2] + "\x00" + hash
}
