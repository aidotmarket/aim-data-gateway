package contract

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/aidotmarket/aim-data-gateway/internal/wire"
)

func TestDescriptionFailureVectors(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, 32)
	key := ed25519.NewKeyFromSeed(seed)
	keys := map[string]ed25519.PublicKey{"test-only-kid": key.Public().(ed25519.PublicKey)}
	for _, tc := range []struct {
		name, raw, verdict string
	}{
		{"description_failure", `{"file_id":"0123456789abcdef0123456789abcdef","failure_code":"read_error"}`, "valid"},
		{"description_failure_extra_key", `{"file_id":"0123456789abcdef0123456789abcdef","failure_code":"read_error","extra":true}`, "invalid"},
		{"description_failure_mixed", `{"file_id":"0123456789abcdef0123456789abcdef","failure_code":"read_error","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","row_count":0,"columns":[]}`, "invalid"},
		{"description_failure_invalid_file_id", `{"file_id":"invalid","failure_code":"read_error"}`, "invalid"},
		{"description_failure_unknown_code", `{"file_id":"0123456789abcdef0123456789abcdef","failure_code":"file_missing"}`, "invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			canonical, err := wire.Canonical(json.RawMessage(tc.raw))
			if err != nil {
				t.Fatal(err)
			}
			token, err := wire.Sign("aim-description+jwt", "test-only-kid", json.RawMessage(tc.raw), key)
			if err != nil {
				t.Fatal(err)
			}
			pinVector(t, tc.name, vector{Label: "TEST ONLY - synthetic description failure", TestOnlySeedHex: hex.EncodeToString(seed), TestOnlyPublicHex: hex.EncodeToString(key.Public().(ed25519.PublicKey)), Input: canonical, Canonical: string(canonical), Token: token, ExpectedVerdict: tc.verdict})
			if err := verify(tc.name, token, keys); (err == nil) != (tc.verdict == "valid") {
				t.Fatalf("expected %s, got %v", tc.verdict, err)
			}
		})
	}
	for _, code := range []string{"unsupported_format", "read_error", "gateway_timeout"} {
		token, err := wire.Sign("aim-description+jwt", "test-only-kid", wire.DescriptionFailure{FileID: fileID, FailureCode: code}, key)
		if err != nil {
			t.Fatal(err)
		}
		if err := verify("description_failure", token, keys); err != nil {
			t.Fatalf("accepted failure code %s: %v", code, err)
		}
		if err := verify("description", token, keys); err == nil {
			t.Fatal("failure accepted as success")
		}
	}
}
