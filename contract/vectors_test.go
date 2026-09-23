package contract

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aidotmarket/aim-data-gateway/internal/ids"
	"github.com/aidotmarket/aim-data-gateway/internal/profile"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
)

type vector struct {
	Label             string          `json:"label"`
	TestOnlySeedHex   string          `json:"test_only_seed_hex"`
	TestOnlyPublicHex string          `json:"test_only_public_hex"`
	Input             json.RawMessage `json:"input"`
	Canonical         string          `json:"canonical"`
	Token             string          `json:"token,omitempty"`
	ExpectedVerdict   string          `json:"expected_verdict"`
}

func TestGoldenVectors(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, 32)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	fixtures := map[string]struct {
		typ  string
		body any
	}{
		"permission":      {typ: "aim-permission+jwt", body: wire.Permission{Audience: "gateway-test", OrderID: "order-test", ListingVersionID: "listing-test", FileID: "0123456789abcdef0123456789abcdef", SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", JTI: "jti-test", IssuedAt: 100, StartDeadline: 1000, TransferDeadline: 2000, ResumeOffset: 0}},
		"offer":           {typ: "aim-offer+jwt", body: wire.Instruction{Op: "offer", Audience: "gateway-test", IID: "iid-test", IssuedAt: 100, FileID: "fid-test", SHA256: "sha-test", ListingVersionID: "lvid-test"}},
		"unoffer":         {typ: "aim-offer+jwt", body: wire.Instruction{Op: "unoffer", Audience: "gateway-test", IID: "iid-test", IssuedAt: 100, FileID: "fid-test", SHA256: "sha-test", ListingVersionID: "lvid-test"}},
		"describe":        {typ: "aim-describe+jwt", body: wire.Instruction{Op: "describe", Audience: "gateway-test", IID: "iid-test", IssuedAt: 100, FileID: "fid-test", ConfirmationID: "cid-test", ExpiresAt: 1000}},
		"revoke":          {typ: "aim-revoke+jwt", body: wire.Instruction{Op: "revoke", Audience: "gateway-test", IID: "iid-test", IssuedAt: 100, JTI: "jti-test"}},
		"prepare":         {typ: "aim-prepare+jwt", body: wire.Instruction{Op: "prepare", Audience: "gateway-test", IID: "iid-test", IssuedAt: 100, OrderID: "order-test", FileID: "fid-test", SHA256: "sha-test"}},
		"key_rotation":    {typ: "aim-keys+jwt", body: wire.Instruction{Op: "key_rotation", Audience: "gateway-test", IID: "iid-test", IssuedAt: 100, Keys: []wire.Key{{KID: "next-test", Alg: "EdDSA", Key: "public-test"}}}},
		"minimum_version": {typ: "aim-minver+jwt", body: wire.Instruction{Op: "minimum_version", Audience: "gateway-test", IID: "iid-test", IssuedAt: 100, Version: "1.2.3"}},
		"revoke_ack":      {body: wire.RevokeAck{Op: "revoke_ack", JTI: "jti-test", StateBefore: "unknown"}},
		"prepare_ack":     {body: wire.PrepareAck{Op: "prepare_ack", IID: "iid-test", OrderID: "order-test", FileID: "fid-test", Ready: true, ResumeOffset: 0, TransmittedBytes: 0, IntervalCount: 0, MaxServeCount: 0}},
		"receipt":         {body: wire.Receipt{Op: "receipt", OrderID: "order-test", FileID: "fid-test", SHA256: "sha-test", SizeBytes: 2, JTIs: []string{"jti-test"}, Transmitted: []wire.Interval{{0, 1}}, TransmittedBytes: 2, MaxServesReachedBytes: 0, Outcome: "complete", BlocksVerified: true, FirstByteAt: "2026-01-01T00:00:00Z", LastByteAt: "2026-01-01T00:00:01Z", Seq: 1}},
		"hello":           {body: map[string]any{"gid": "gateway-test", "nonce": "nonce-test", "version": "1.0.0", "ts": "2026-01-01T00:00:00Z"}},
		"inventory":       {body: map[string]any{"generation": 1, "files": []any{map[string]any{"file_id": "fid-test", "display_name": "file-01234567.csv", "size_bytes": 2, "media_type": "text/csv", "content_commitment": "commitment-test", "present": true}}}},
		"description":     {body: map[string]any{"file_id": "fid-test", "sha256": "sha-test", "row_count": 2, "columns": []any{map[string]any{"name": "safe", "type": "integer", "null_rate_pct": 0, "distinct_bucket": "2-10"}}}},
		"canary_result":   {body: map[string]any{"state": "closed", "dns": "closed", "tcp": "closed", "proxy": "closed", "label": "test-only", "at": "2026-01-01T00:00:00Z"}},
		"revocation_ack":  {body: wire.RevokeAck{Op: "revoke_ack", JTI: "jti-test", StateBefore: "active"}},
		"offer_ack":       {body: map[string]any{"iid": "iid-test", "fid": "fid-test", "ready": true}},
		"error":           {body: map[string]any{"code": "read_error", "message": "test only"}},
	}
	for name, item := range fixtures {
		t.Run(name, func(t *testing.T) {
			canonical, e := wire.Canonical(item.body)
			if e != nil {
				t.Fatal(e)
			}
			v := vector{Label: "TEST ONLY - synthetic golden vector", TestOnlySeedHex: hex.EncodeToString(seed), TestOnlyPublicHex: hex.EncodeToString(pub), Input: canonical, Canonical: string(canonical), ExpectedVerdict: "valid"}
			if item.typ != "" {
				v.Token, e = wire.Sign(item.typ, "test-only-kid", item.body, priv)
				if e != nil {
					t.Fatal(e)
				}
			}
			data, e := json.MarshalIndent(v, "", "  ")
			if e != nil {
				t.Fatal(e)
			}
			data = append(data, '\n')
			path := filepath.Join("vectors", name+".json")
			if os.Getenv("UPDATE_VECTORS") == "1" {
				if e = os.WriteFile(path, data, 0600); e != nil {
					t.Fatal(e)
				}
			} else {
				got, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				if !bytes.Equal(got, data) {
					t.Fatal("golden vector drift")
				}
			}
		})
	}
	extras := map[string]any{"null_rate_boundaries": map[string]any{"249_of_10000": profile.NullRate(249, 10000), "250_of_10000": profile.NullRate(250, 10000), "9749_of_10000": profile.NullRate(9749, 10000), "9750_of_10000": profile.NullRate(9750, 10000), "zero_rows": profile.NullRate(0, 0)}, "default_display_name": ids.DisplayName("0123456789abcdef0123456789abcdef", "text/csv"), "inclusive_intervals": map[string]int64{"byte_zero": (wire.Interval{0, 0}).Length(), "byte_one": (wire.Interval{1, 1}).Length(), "last_byte": (wire.Interval{99, 99}).Length(), "suffix_10_of_100": (wire.Interval{90, 99}).Length(), "open_ended_from_10_of_100": (wire.Interval{10, 99}).Length()}}
	canonical, e := wire.Canonical(extras)
	if e != nil {
		t.Fatal(e)
	}
	v := vector{Label: "TEST ONLY - synthetic golden vector", TestOnlySeedHex: hex.EncodeToString(seed), TestOnlyPublicHex: hex.EncodeToString(pub), Input: canonical, Canonical: string(canonical), ExpectedVerdict: "valid"}
	data, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	data = append(data, '\n')
	path := filepath.Join("vectors", "boundaries.json")
	if os.Getenv("UPDATE_VECTORS") == "1" {
		if e = os.WriteFile(path, data, 0600); e != nil {
			t.Fatal(e)
		}
	} else {
		got, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("boundary vector drift")
		}
	}
}
