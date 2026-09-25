package contract

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aidotmarket/aim-data-gateway/internal/audit"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
)

func pinVector(t *testing.T, name string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, '\n')
	path := filepath.Join("vectors", name+".json")
	if os.Getenv("UPDATE_VECTORS") == "1" {
		if err = os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, b) {
		t.Fatalf("%s vector drift: %v", name, err)
	}
}

func TestAmendmentBVectors(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, 32)
	key := ed25519.NewKeyFromSeed(seed)
	body := map[string]any{"text": "& <> \u2028 café", "zero": int64(0), "negative": int64(-3), "above_js_safe": int64(9007199254740993), "max_int64": int64(9223372036854775807)}
	unsigned := map[string]any{"seq": int64(1), "time": "2026-01-01T00:00:00Z", "message_type": "inventory", "body": body, "prev_hash": ""}
	signed, err := wire.Canonical(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	entry := audit.Entry{Seq: 1, Time: "2026-01-01T00:00:00Z", MessageType: "inventory", PrevHash: "", Sig: hex.EncodeToString(ed25519.Sign(key, signed))}
	entry.Body, err = wire.Canonical(body)
	if err != nil {
		t.Fatal(err)
	}
	entryBytes, err := wire.Canonical(entry)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := audit.Hash(entry)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(entryBytes)
	if hash != hex.EncodeToString(sum[:]) {
		t.Fatal("entry hash mismatch")
	}
	if _, err = audit.ValidateRaw(entryBytes, key.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	pinVector(t, "audit_entry", map[string]any{"label": "TEST ONLY - synthetic golden vector", "test_only_seed_hex": hex.EncodeToString(seed), "test_only_public_hex": hex.EncodeToString(key.Public().(ed25519.PublicKey)), "signed_bytes": string(signed), "entry_bytes": string(entryBytes), "entry_hash": hash, "expected_verdict": "valid"})
	for name, raw := range map[string]string{
		"audit_refused_exponent":      `{"body":{"n":1e2},"message_type":"inventory","prev_hash":"","seq":1,"sig":"x","time":"t"}`,
		"audit_refused_fraction":      `{"body":{"n":1.0},"message_type":"inventory","prev_hash":"","seq":1,"sig":"x","time":"t"}`,
		"audit_refused_negative_zero": `{"body":{"n":-0},"message_type":"inventory","prev_hash":"","seq":1,"sig":"x","time":"t"}`,
		"audit_refused_leading_zero":  `{"body":{"n":01},"message_type":"inventory","prev_hash":"","seq":1,"sig":"x","time":"t"}`,
		"audit_refused_overflow":      `{"body":{"n":9223372036854775808},"message_type":"inventory","prev_hash":"","seq":1,"sig":"x","time":"t"}`,
		"audit_refused_duplicate":     `{"body":{"n":1,"n":2},"message_type":"inventory","prev_hash":"","seq":1,"sig":"x","time":"t"}`,
	} {
		if _, err := audit.ValidateRaw([]byte(raw), key.Public().(ed25519.PublicKey)); err == nil {
			t.Fatalf("accepted %s", name)
		}
		pinVector(t, name, map[string]any{"label": "TEST ONLY - refused audit entry", "raw": raw, "expected_verdict": "invalid"})
	}
	pinVector(t, "resume", map[string]any{"label": "TEST ONLY - transport control", "input": map[string]any{"resume": map[string]any{"seq": 1, "entry_hash": hash}}, "expected_verdict": "valid"})
	pinVector(t, "ack", map[string]any{"label": "TEST ONLY - transport control", "input": map[string]any{"ack": 1}, "expected_verdict": "valid"})
	pinVector(t, "withheld", map[string]any{"label": "TEST ONLY - stored redaction", "input": map[string]any{"seq": 1, "entry_hash": hash, "body": map[string]string{"withheld": "description_not_confirmed"}}, "expected_verdict": "valid"})
}
