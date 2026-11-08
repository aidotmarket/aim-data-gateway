package cloudflareverification

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	core "github.com/aidotmarket/aim-data-gateway/verification"
)

var updateCensusWire = flag.Bool("update", false, "regenerate gateway-owned census_wire receipt vectors")

const censusWireDir = "../../contract/vectors/census_wire"
const censusPlatformKID = "census-platform-test-24"
const censusScanPreimage = "spec_hash nonce_echo install_key_id artifact_locator_commitment content_sha256 started_at_utc completed_at_utc duration_ms coverage fingerprint_hash scan_mode binding_method planned_processed_bytes depth_class content_census unread_binding_sha256"
const censusTerminalPreimage = "verification_id listing_id source_handle_id spec_id spec_version connector_type connector_version spec_hash nonce_echo install_key_id agent_version terminal_error_code completed_at_utc canonicalization_version signature_algorithm"

func censusTestKey(b byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, 32))
}

// Also used as the documented top-level shape of backend_{probe,scan}_v2.json.
type censusSpecVector struct {
	Token             string         `json:"token"`
	Payload           map[string]any `json:"payload"`
	PayloadCanonical  string         `json:"payload_canonical"`
	SpecHash          string         `json:"spec_hash"`
	PlatformPublicKey string         `json:"platform_public_key"`
	KID               string         `json:"kid"`
	GatewayID         string         `json:"gateway_id"`
	RunnerID          string         `json:"runner_id"`
	RunnerVersion     string         `json:"runner_version"`
	Now               string         `json:"now"`
}

type censusReceiptVector struct {
	Description    string           `json:"description"`
	Spec           censusSpecVector `json:"spec"`
	Variant        string           `json:"variant"`
	Receipt        map[string]any   `json:"receipt"`
	SignatureValid bool             `json:"signature_valid"`
}

func wireCensusJob() wire.ScanJob {
	return wire.ScanJob{Payload: map[string]any{"scan_mode": core.ContentCensusV1, "planned_processed_bytes": censusR1BudgetBytes}}
}

func canonicalTest(t *testing.T, v any) []byte {
	t.Helper()
	b, err := core.Canonical(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func decodeCensusVector(t *testing.T, raw []byte, v any) {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber() // Preserve signed literals such as -1000.0, not just their value.
	if err := d.Decode(v); err != nil {
		t.Fatal(err)
	}
}

func mapTest(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	v, err := core.ParseCanonical(raw)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatal("expected object")
	}
	return m
}

func signCensusSpec(t *testing.T, envelope map[string]any) string {
	t.Helper()
	token, err := signJWS(censusTestKey(0x24), censusPlatformKID, "aim-scan-spec+jwt", envelope)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func verifyCensusSpec(t *testing.T, v censusSpecVector) wire.ScanJob {
	t.Helper()
	now, err := time.Parse(time.RFC3339, v.Now)
	if err != nil {
		t.Fatal(err)
	}
	pub := censusTestKey(0x24).Public().(ed25519.PublicKey)
	if v.KID != censusPlatformKID || v.PlatformPublicKey != base64.RawURLEncoding.EncodeToString(pub) {
		t.Fatal("platform test key metadata")
	}
	j, err := VerifyWork(v.Token, map[string]ed25519.PublicKey{v.KID: pub}, v.GatewayID, v.RunnerID, v.RunnerVersion, now)
	if err != nil {
		t.Fatal(err)
	}
	if string(j.Raw) != v.PayloadCanonical || wire.Digest(j.Raw) != v.SpecHash || !bytes.Equal(j.Raw, canonicalTest(t, v.Payload)) {
		t.Fatal("embedded spec binding")
	}
	return j
}

type unreadCensusSource struct {
	*Source
	unread string
}

func (s unreadCensusSource) OpenRange(ctx context.Context, id string, off, n int64) (io.ReadCloser, error) {
	if id == s.unread {
		return nil, io.ErrUnexpectedEOF
	}
	return s.Source.OpenRange(ctx, id, off, n)
}

func generateCensusReceipts(t *testing.T) map[string]any {
	t.Helper()
	// Start with the frozen v1 R2 control payload; add exactly the v2 contract.
	raw, err := os.ReadFile("../../contract/vectors/verification/r2_listing/control.json")
	if err != nil {
		t.Fatal(err)
	}
	var control struct {
		ScanSpec struct {
			Canonical string `json:"canonical"`
		} `json:"scan_spec"`
	}
	if err := json.Unmarshal(raw, &control); err != nil {
		t.Fatal(err)
	}
	data := []byte("Deterministic census text for contract verification.\n")
	keys := []string{"RAW_KEY_MARKER/a.txt", "RAW_KEY_MARKER/b.txt"}
	objects := []Object{{Key: keys[0], Size: int64(len(data)), ETag: "pinned", Format: "txt"}, {Key: keys[1], Size: int64(len(data)), ETag: "pinned", Format: "txt"}}
	env := mapTest(t, []byte(control.ScanSpec.Canonical))
	editPayload(env, func(p map[string]any) {
		p["spec_version"], p["scan_mode"], p["binding_method"] = "2", core.ContentCensusV1, "planned_read_commitment_v2"
		p["depth_class"], p["planned_processed_bytes"], p["platform_key_id"] = "content_census_sampled_v1", int64(2*len(data)), censusPlatformKID
		p["manifest_hash"] = wire.Digest(snapshotRaw(t, wire.ScanJob{Payload: p}, "fixture", objects))
	})
	token := signCensusSpec(t, env)
	payloadRaw, err := wire.DecodeDocument(env["payload_b64"].(string), 40<<10)
	if err != nil {
		t.Fatal(err)
	}
	payload := mapTest(t, payloadRaw)
	at, _ := utc(payload["issued_at_utc"].(string))
	v := censusSpecVector{token, payload, string(payloadRaw), wire.Digest(payloadRaw), base64.RawURLEncoding.EncodeToString(censusTestKey(0x24).Public().(ed25519.PublicKey)), censusPlatformKID, env["aud"].(string), env["runner_id"].(string), ScannerVersion, timestamp(at)}
	j := verifyCensusSpec(t, v)
	j.ScannerVersion, j.ReceiptKeyID = ScannerVersion, "77777777-7777-4777-8777-777777777777"
	bridge := &lockedBridge{fakeBridge: &fakeBridge{objects: map[string][]byte{keys[0]: data, keys[1]: data}}}
	src, err := NewSource(bridge, "fixture", objects)
	if err != nil {
		t.Fatal(err)
	}
	p := scanPolicy(j, &collectedCommitments{Commitments: Commitments{Bucket: "fixture", ManifestHash: j.Text("manifest_hash"), Key: [32]byte(bytes.Repeat([]byte{0x63}, 32))}, Digests: map[string]string{}})
	if len(core.PlannedReadSet(p.Seed, src.Members(), p)) != 2 {
		t.Fatal("both members must be planned")
	}
	out := map[string]any{}
	for _, sampled := range []bool{false, true} {
		cs := unreadCensusSource{Source: src}
		name, depth, description := "cf_receipt_success_complete.json", "content_census_complete_v1", "Both planned members fully read under sampled authorization."
		if sampled {
			cs.unread = src.members[1].Identity
			name, depth, description = "cf_receipt_success_sampled.json", "content_census_sampled_v1", "Both members planned; one GET fails with a read error and its pinned HEAD remains unchanged."
		}
		facts, err := core.Scan(context.Background(), cs, p)
		if err != nil {
			t.Fatal(err)
		}
		if facts.ContentCensus == nil || facts.ContentCensus.DepthClass != depth {
			t.Fatal("achieved depth", facts.ContentCensus)
		}
		d := report(j, facts, at, at.Add(time.Second))
		if err := signReceipt(d, censusTestKey(0x42), "scan"); err != nil {
			t.Fatal(err)
		}
		out[name] = censusReceiptVector{description, v, "scan", d, true}
		if !sampled {
			tampered := mapTest(t, canonicalTest(t, d))
			tampered["content_census"].(map[string]any)["depth_class"] = "content_census_sampled_v1"
			out["cf_receipt_tampered.json"] = censusReceiptVector{"Complete success with content_census.depth_class altered after signing; signature must fail.", v, "scan", tampered, false}
		}
	}
	d := terminal(j, "artifact_changed", at.Add(time.Second))
	if err := signReceipt(d, censusTestKey(0x42), "terminal"); err != nil {
		t.Fatal(err)
	}
	out["cf_receipt_terminal_v2.json"] = censusReceiptVector{"Terminal artifact_changed with v1 terminal shape and spec_version 2.", v, "terminal", d, true}

	return out
}

func TestCensusWireReceiptVectors(t *testing.T) {
	generated := generateCensusReceipts(t)
	if *updateCensusWire {
		if err := os.MkdirAll(censusWireDir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	for name, value := range generated {
		t.Run(name, func(t *testing.T) {
			raw := append(canonicalTest(t, value), '\n')
			path := filepath.Join(censusWireDir, name)
			if *updateCensusWire {
				if err := os.WriteFile(path, raw, 0644); err != nil {
					t.Fatal(err)
				}
			}
			stored, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(raw, stored) {
				t.Fatal("vector drift; regenerate explicitly with -update")
			}
			if name == "index.json" {
				return
			}
			var v censusReceiptVector
			decodeCensusVector(t, stored, &v)
			j := verifyCensusSpec(t, v.Spec)
			d := mapTest(t, canonicalTest(t, v.Receipt))
			sig, err := base64.StdEncoding.DecodeString(d["receipt_signature"].(string))
			if err != nil {
				t.Fatal(err)
			}
			delete(d, "receipt_signature")
			fields := censusScanPreimage
			if v.Variant == "terminal" {
				fields = censusTerminalPreimage
			}
			binding := map[string]any{}
			for _, k := range strings.Fields(fields) {
				if d[k] == nil {
					t.Fatal("missing preimage field", k)
				}
				binding[k] = d[k]
			}
			preimage := canonicalTest(t, binding)
			if !bytes.Equal(preimage, canonicalTest(t, receiptBinding(d, v.Variant))) {
				t.Fatal("16.1 preimage drift")
			}
			valid := ed25519.Verify(censusTestKey(0x42).Public().(ed25519.PublicKey), preimage, sig)
			if valid != v.SignatureValid || valid != (name != "cf_receipt_tampered.json") {
				t.Fatal("signature result", valid)
			}
			if d["spec_hash"] != j.Envelope.SpecHash || d["spec_version"] != "2" || d["nonce_echo"] != j.Text("nonce") {
				t.Fatal("spec to receipt binding")
			}
		})
	}
}

func editPayload(env map[string]any, edit func(map[string]any)) {
	raw, _ := wire.DecodeDocument(env["payload_b64"].(string), 40<<10)
	v, _ := core.ParseCanonical(raw)
	p := v.(map[string]any)
	edit(p)
	raw, _ = core.Canonical(p)
	env["payload_b64"], env["spec_hash"] = base64.RawURLEncoding.EncodeToString(raw), wire.Digest(raw)
}
