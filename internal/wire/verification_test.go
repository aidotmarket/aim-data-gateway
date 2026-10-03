package wire

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	core "github.com/aidotmarket/aim-data-gateway/verification"
	"os"
	"strings"
	"testing"
	"time"
)

type scanVector struct {
	Token, Typ string
	Input      map[string]any
	Public     string `json:"test_only_public_hex"`
	Seed       string `json:"test_only_seed_hex"`
}

func vector(t *testing.T, name string) scanVector {
	t.Helper()
	raw, e := os.ReadFile("../../contract/vectors/verification/" + name + ".json")
	if e != nil {
		t.Fatal(e)
	}
	var v scanVector
	if e = json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	return v
}
func testKeys(t *testing.T) map[string]ed25519.PublicKey {
	v := vector(t, "scan_spec")
	pub, _ := hex.DecodeString(v.Public)
	return map[string]ed25519.PublicKey{"test-only-scan-key": pub, "test-only-listing-key": pub}
}
func testJob(t *testing.T, name string, now time.Time) (ScanJob, error) {
	v := vector(t, name)
	return VerifyScan(v.Token, testKeys(t), v.Input["aud"].(string), v.Input["runner_id"].(string), "1.2.3", now)
}
func TestScanContracts(t *testing.T) {
	at := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	for _, name := range []string{"scan_spec", "probe_spec"} {
		t.Run(name, func(t *testing.T) {
			j, e := testJob(t, name, at)
			if e != nil {
				t.Fatal(e)
			}
			s, e := VerifySnapshot(vector(t, "snapshot").Token, testKeys(t), j)
			if e != nil {
				t.Fatal(e)
			}
			for _, m := range s.Members {
				if len(m.FileID) != 32 {
					t.Fatal("FID width")
				}
			}
		})
	}
}
func TestScanStrictRefusals(t *testing.T) {
	at := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	v := vector(t, "scan_spec")
	seed, _ := hex.DecodeString(v.Seed)
	key := ed25519.NewKeyFromSeed(seed)
	aud := v.Input["aud"].(string)
	runner := v.Input["runner_id"].(string)
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"wrong audience", func(m map[string]any) { m["aud"] = "99999999-9999-4999-8999-999999999999" }},
		{"wrong runner", func(m map[string]any) { m["runner_id"] = "99999999-9999-4999-8999-999999999999" }},
		{"unknown envelope", func(m map[string]any) { m["extra"] = true }},
		{"null discriminant", func(m map[string]any) { m["variant"] = nil }},
		{"hash mismatch", func(m map[string]any) { m["spec_hash"] = strings.Repeat("0", 64) }},
		{"D6 mismatch", func(m map[string]any) { m["d6_hash"] = strings.Repeat("0", 64) }},
		{"unknown payload", func(m map[string]any) {
			raw, _ := base64.RawURLEncoding.DecodeString(m["payload_b64"].(string))
			z, _ := core.ParseCanonical(raw)
			p := z.(map[string]any)
			p["extra"] = true
			b, _ := core.Canonical(p)
			m["payload_b64"] = base64.RawURLEncoding.EncodeToString(b)
			m["spec_hash"] = Digest(b)
		}},
		{"bad policy", func(m map[string]any) {
			raw, _ := base64.RawURLEncoding.DecodeString(m["payload_b64"].(string))
			z, _ := core.ParseCanonical(raw)
			p := z.(map[string]any)
			p["minimum_aggregate_occupancy"] = 9
			b, _ := core.Canonical(p)
			m["payload_b64"] = base64.RawURLEncoding.EncodeToString(b)
			m["spec_hash"] = Digest(b)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := json.Marshal(v.Input)
			var m map[string]any
			json.Unmarshal(raw, &m)
			tc.mutate(m)
			token, e := Sign(v.Typ, "test-only-scan-key", m, key)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = VerifyScan(token, testKeys(t), aud, runner, "1.2.3", at); e == nil {
				t.Fatal("accepted")
			}
		})
	}
	if _, e := VerifyScan(v.Token, map[string]ed25519.PublicKey{}, aud, runner, "1.2.3", at); e == nil {
		t.Fatal("wrong key accepted")
	}
	if _, e := testJob(t, "scan_spec", at.Add(25*time.Hour)); e == nil {
		t.Fatal("stale consent")
	}
	if _, e := testJob(t, "scan_spec", at.Add(-300*time.Second)); e != nil {
		t.Fatal("inclusive skew", e)
	}
	if _, e := testJob(t, "scan_spec", at.Add(-301*time.Second)); e == nil {
		t.Fatal("outside skew")
	}
	if _, e := VerifyScan(strings.Repeat("a", 65537), testKeys(t), aud, runner, "1.2.3", at); e == nil {
		t.Fatal("cap")
	}
}
func TestD6Strict(t *testing.T) {
	v := vector(t, "scan_spec")
	raw, _ := DecodeDocument(v.Input["d6_b64"].(string), 2048)
	if _, e := ValidateD6(raw); e != nil {
		t.Fatal(e)
	}
	for _, b := range []string{`{}`, `{"domain_class":"health"}`, `{"domain_class":"education_learning","intended_use_tags":null,"known_limitation_tags":[],"record_granularity":"entity","temporal_scope":"current_snapshot","update_cadence":"daily"}`} {
		if _, e := ValidateD6([]byte(b)); e == nil {
			t.Fatal("D6 accepted")
		}
	}
}
