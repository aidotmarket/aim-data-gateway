package verification

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"testing"
)

func TestPythonCanonicalScalars(t *testing.T) {
	var fixture struct {
		Scalars []struct {
			Hex string `json:"canonical_hex"`
		}
	}
	if e := json.Unmarshal(read(t, "testdata/oracle/boundaries.json"), &fixture); e != nil {
		t.Fatal(e)
	}
	values := []any{math.Copysign(0, -1), 1e-7, 1e16, .1, "<&>\u2028\u2029 😀"}
	for i, v := range values {
		b, e := canonical(v)
		if e != nil || hex.EncodeToString(b) != fixture.Scalars[i].Hex {
			t.Fatalf("scalar %d %s %v", i, b, e)
		}
	}
	for _, raw := range []string{`{"a":1,"a":1}`, `{"a":1} `, `{"a":1e0}`, `{"a":-0}`, `{"a":NaN}`, `{"a":1} {}`, `{"a":"\u003c"}`, `{"a":1.00}`} {
		if _, e := requireCanonical([]byte(raw)); e == nil {
			t.Fatalf("accepted noncanonical %s", raw)
		}
	}
	for _, raw := range []string{`{"a":1.0}`, `{"a":-0.0}`, `{"é":"<&>"}`, `{"a":1e-07}`} {
		if _, e := requireCanonical([]byte(raw)); e != nil {
			t.Fatalf("rejected %s: %v", raw, e)
		}
	}
	if _, e := canonical(math.Inf(1)); e == nil {
		t.Fatal("nonfinite scalar")
	}
	if _, e := canonical("\xff"); e == nil {
		t.Fatal("invalid utf8")
	}
}

func TestSharedCanonicalAndReceiptDocuments(t *testing.T) {
	for _, name := range []string{"scan_report", "probe_report", "terminal_report", "registration", "source_bindings", "canonicalization"} {
		var v struct{ Canonical string }
		if e := json.Unmarshal(read(t, "../contract/vectors/verification/"+name+".json"), &v); e != nil {
			t.Fatal(e)
		}
		if _, e := requireCanonical([]byte(v.Canonical)); e != nil {
			t.Fatalf("%s canonical: %v", name, e)
		}
	}
	var vector struct {
		Input struct {
			Valid   []struct{ Raw string }
			Invalid []string
		}
	}
	if e := json.Unmarshal(read(t, "../contract/vectors/verification/canonicalization.json"), &vector); e != nil {
		t.Fatal(e)
	}
	for _, v := range vector.Input.Valid {
		if _, e := requireCanonical([]byte(v.Raw)); e != nil {
			t.Fatal(e)
		}
	}
	for _, raw := range vector.Input.Invalid {
		if raw == `{"unknown":true}` {
			continue
		}
		if _, e := requireCanonical([]byte(raw)); e == nil {
			t.Fatalf("accepted alternate canonical bytes %s", raw)
		}
	}
}

func TestSharedReceiptSignatures(t *testing.T) {
	for _, name := range []string{"scan_report", "probe_report", "terminal_report", "registration"} {
		var v struct {
			Canonical string
			Pub       string `json:"test_only_public_hex"`
		}
		if e := json.Unmarshal(read(t, "../contract/vectors/verification/"+name+".json"), &v); e != nil {
			t.Fatal(e)
		}
		pub, e := hex.DecodeString(v.Pub)
		if e != nil {
			t.Fatal(e)
		}
		parsed, e := requireCanonical([]byte(v.Canonical))
		if e != nil {
			t.Fatal(e)
		}
		report := parsed.(map[string]any)
		binding := map[string]any{}
		signatureKey := "receipt_signature"
		decoder := base64.StdEncoding
		if name == "registration" {
			signatureKey = "key_proof"
			decoder = base64.RawURLEncoding
		}
		for k, z := range report {
			if k != signatureKey {
				binding[k] = z
			}
		}
		if name == "scan_report" {
			binding = map[string]any{}
			for _, k := range []string{"spec_hash", "nonce_echo", "install_key_id", "artifact_locator_commitment", "content_sha256", "started_at_utc", "completed_at_utc", "duration_ms", "coverage", "fingerprint_hash"} {
				binding[k] = report[k]
			}
		}
		raw, e := canonical(binding)
		if e != nil {
			t.Fatal(e)
		}
		sig, e := decoder.DecodeString(report[signatureKey].(string))
		if e != nil || !ed25519.Verify(pub, raw, sig) {
			t.Fatalf("%s receipt bytes", name)
		}
	}
}
