package awsverification

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
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
	f := newFixture(t)
	f.at = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	data := []byte("Deterministic census text for contract verification.\n")
	keys := []string{"RAW_KEY_MARKER/a.txt", "RAW_KEY_MARKER/b.txt"}
	f.s3.objects = map[string][]byte{keys[0]: data, keys[1]: data}
	f.jobWithMembers(t, 1, "scan", []any{member(keys[0], "txt", len(data)), member(keys[1], "txt", len(data))})
	j := censusWork(t, f, int64(2*len(data)))
	raw, err := wire.DecodeDocument(strings.Split(j.Token, ".")[1], 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	env := mapTest(t, raw)
	editPayload(env, func(p map[string]any) { p["platform_key_id"] = censusPlatformKID })
	token := signCensusSpec(t, env)
	payloadRaw, err := wire.DecodeDocument(env["payload_b64"].(string), 40<<10)
	if err != nil {
		t.Fatal(err)
	}
	v := censusSpecVector{token, mapTest(t, payloadRaw), string(payloadRaw), wire.Digest(payloadRaw), base64.RawURLEncoding.EncodeToString(censusTestKey(0x24).Public().(ed25519.PublicKey)), censusPlatformKID, runnerID, runnerID, ScannerVersion, timestamp(f.at)}
	j = verifyCensusSpec(t, v)
	j.ScannerVersion, j.ReceiptKeyID = ScannerVersion, receiptID
	src, err := NewSource(f.s3, f.h.Config.Bucket, []Object{{Key: keys[0], Size: int64(len(data)), ETag: f.s3.liveETag, Format: "txt"}, {Key: keys[1], Size: int64(len(data)), ETag: f.s3.liveETag, Format: "txt"}})
	if err != nil {
		t.Fatal(err)
	}
	p := scanPolicy(j, &collectedCommitments{Commitments: Commitments{Bucket: f.h.Config.Bucket, ManifestHash: j.Text("manifest_hash"), Key: [32]byte(bytes.Repeat([]byte{0x63}, 32))}, Digests: map[string]string{}})
	if len(core.PlannedReadSet(p.Seed, src.Members(), p)) != 2 {
		t.Fatal("both members must be planned")
	}
	out := map[string]any{}
	for _, sampled := range []bool{false, true} {
		cs := unreadCensusSource{Source: src}
		name, depth, description := "receipt_success_complete.json", "content_census_complete_v1", "Both planned members fully read under sampled authorization."
		if sampled {
			cs.unread = src.members[1].Identity
			name, depth, description = "receipt_success_sampled.json", "content_census_sampled_v1", "Both members planned; one GET fails with a read error and its pinned HEAD remains unchanged."
		}
		facts, err := core.Scan(ctx, cs, p)
		if err != nil {
			t.Fatal(err)
		}
		if facts.ContentCensus == nil || facts.ContentCensus.DepthClass != depth {
			t.Fatal("achieved depth", facts.ContentCensus)
		}
		d := report(j, facts, f.at, f.at.Add(time.Second))
		if err := signReceipt(d, censusTestKey(0x42), "scan"); err != nil {
			t.Fatal(err)
		}
		out[name] = censusReceiptVector{description, v, "scan", d, true}
		if !sampled {
			tampered := mapTest(t, canonicalTest(t, d))
			tampered["content_census"].(map[string]any)["depth_class"] = "content_census_sampled_v1"
			out["receipt_tampered.json"] = censusReceiptVector{"Complete success with content_census.depth_class altered after signing; signature must fail.", v, "scan", tampered, false}
		}
	}
	d := terminal(j, "artifact_changed", f.at.Add(time.Second))
	if err := signReceipt(d, censusTestKey(0x42), "terminal"); err != nil {
		t.Fatal(err)
	}
	out["receipt_terminal_v2.json"] = censusReceiptVector{"Terminal artifact_changed with v1 terminal shape and spec_version 2.", v, "terminal", d, true}
	keyInfo := func(seed byte, kid string) any {
		pub := censusTestKey(seed).Public().(ed25519.PublicKey)
		return map[string]any{"kid": kid, "seed_hex": hex.EncodeToString(bytes.Repeat([]byte{seed}, 32)), "public_key_hex": hex.EncodeToString(pub), "public_key_base64url": base64.RawURLEncoding.EncodeToString(pub), "test_only": true}
	}
	out["index.json"] = map[string]any{
		"description": "Runbooks 16.1 AWS census wire proof. Gateway receipts are generated by real Scan/report/terminal/signReceipt; backend specs are consumed unchanged. Fixed keys are public test material only.",
		"generator":   "go test ./internal/awsverification -run '^TestCensusWireReceiptVectors$' -update; python3 scripts/check-vector-digest.py --update",
		"receipt_key": keyInfo(0x42, receiptID), "platform_key": keyInfo(0x24, censusPlatformKID),
		"canonicalization": "python-json-sort-compact-v1", "signature_algorithm": "Ed25519", "receipt_signature_encoding": "base64 (standard, padded)",
		"scan_signed_preimage_fields": strings.Fields(censusScanPreimage), "terminal_signed_preimage_fields": strings.Fields(censusTerminalPreimage),
		"receipt_files":         []string{"receipt_success_complete.json", "receipt_success_sampled.json", "receipt_terminal_v2.json", "receipt_tampered.json"},
		"receipt_fixture_shape": "{description, spec: <backend_fixture_shape>, variant: scan|terminal, receipt: <signed document including receipt_signature>, signature_valid: boolean}. spec is the exact signed v2 scan answered by this receipt. Tampered is the complete receipt with only content_census.depth_class changed after signing.",
		"backend_files":         []string{"backend_probe_v2.json", "backend_scan_v2.json"},
		"backend_fixture_shape": map[string]any{"token": "compact EdDSA aim-scan-spec+jwt JWS, header kid=census-platform-test-24", "payload": "exact signed spec JSON object", "payload_canonical": "exact decoded payload_b64 bytes as a JSON string", "spec_hash": "SHA-256 hex of those bytes", "platform_public_key": "unpadded base64url public key for seed 0x24 repeated 32 times", "kid": censusPlatformKID, "gateway_id": "aud passed to VerifyWork", "runner_id": "runner_id passed to VerifyWork", "runner_version": "eligible semantic version passed to VerifyWork (e.g. 0.3.0)", "now": "fixed RFC3339 UTC timestamp passed to VerifyWork"},
		"backend_requirements":  "Backend emits top-level backend_fixture_shape with variant probe or scan in the token; exact 16.1 schema with only scan_mode, binding_method and planned_processed_bytes added to v1. The gateway never regenerates backend files. Consumer skips only missing files and rejects re-signed v1 census, unknown field, or each of content_read_budget_bytes/archive_allowance_bytes/archive_caps/pattern_versions.",
	}
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
			if valid != v.SignatureValid || valid != (name != "receipt_tampered.json") {
				t.Fatal("signature result", valid)
			}
			if d["spec_hash"] != j.Envelope.SpecHash || d["spec_version"] != "2" || d["nonce_echo"] != j.Text("nonce") {
				t.Fatal("spec to receipt binding")
			}
		})
	}
}

func TestBackendSignedCensusSpecsParse(t *testing.T) {
	for _, variant := range []string{"probe", "scan"} {
		t.Run(variant, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(censusWireDir, "backend_"+variant+"_v2.json"))
			if os.IsNotExist(err) {
				t.Skip("backend fold fixture has not been copied in yet")
			}
			if err != nil {
				t.Fatal(err)
			}
			var v censusSpecVector
			decodeCensusVector(t, raw, &v)
			j := verifyCensusSpec(t, v)
			if j.Envelope.Variant != variant || j.Text("spec_version") != "2" {
				t.Fatal("expected v2", variant)
			}
			for _, field := range []string{"spec_version", "unknown_extra_field", "content_read_budget_bytes", "archive_allowance_bytes", "archive_caps", "pattern_versions"} {
				t.Run(field, func(t *testing.T) {
					envRaw, err := wire.DecodeDocument(strings.Split(v.Token, ".")[1], 64<<10)
					if err != nil {
						t.Fatal(err)
					}
					env := mapTest(t, envRaw)
					editPayload(env, func(p map[string]any) {
						p[field] = 1
						if field == "spec_version" {
							p[field] = "1"
						}
						if field == "archive_caps" {
							p[field] = map[string]any{"uncompressed_bytes": 256 << 20, "entries": 10000, "compression_ratio": 1000}
						}
						if field == "pattern_versions" {
							p[field] = []string{"email_v1"}
						}
					})
					token := signCensusSpec(t, env)
					now, _ := time.Parse(time.RFC3339, v.Now)
					if _, err := VerifyWork(token, map[string]ed25519.PublicKey{v.KID: censusTestKey(0x24).Public().(ed25519.PublicKey)}, v.GatewayID, v.RunnerID, v.RunnerVersion, now); err == nil {
						t.Fatal("accepted forbidden field", field)
					}
				})
			}
		})
	}
}
