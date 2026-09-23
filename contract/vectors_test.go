package contract

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/ids"
	"github.com/aidotmarket/aim-data-gateway/internal/inventory"
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
type fixture struct {
	typ  string
	body any
	kind string
}

const (
	gate       = "11111111-1111-4111-8111-111111111111"
	order      = "22222222-2222-4222-8222-222222222222"
	listing    = "33333333-3333-4333-8333-333333333333"
	request    = "44444444-4444-4444-8444-444444444444"
	confirm    = "55555555-5555-4555-8555-555555555555"
	fileID     = "0123456789abcdef0123456789abcdef"
	sha        = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	commitment = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestGoldenVectors(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, 32)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	keys := map[string]ed25519.PublicKey{"test-only-kid": pub}
	base := wire.Instruction{Audience: gate, IID: request, IssuedAt: 1767225600}
	inst := func(op string) wire.Instruction { i := base; i.Op = op; return i }
	offer := inst("offer")
	offer.FileID = fileID
	offer.SHA256 = sha
	offer.ListingVersionID = listing
	unoffer := offer
	unoffer.Op = "unoffer"
	describe := inst("describe")
	describe.IssuedAt = 4102443900 // Exactly 15 minutes before the synthetic expiry.
	describe.FileID = fileID
	describe.ConfirmationID = confirm
	describe.ExpiresAt = 4102444800
	revoke := inst("revoke")
	revoke.JTI = request
	prepare := inst("prepare")
	prepare.OrderID = order
	prepare.FileID = fileID
	prepare.SHA256 = sha
	rotation := inst("key_rotation")
	rotation.Keys = []wire.Key{{KID: "next-test-only-kid", Alg: "EdDSA", Key: base64.RawURLEncoding.EncodeToString(pub)}}
	minver := inst("minimum_version")
	minver.Version = "1.2.3"
	refusal := "file_changed"
	prepareRefusal := "coverage_exhausted"
	zero := 0
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fs := map[string]fixture{
		"permission": {"aim-permission+jwt", wire.Permission{Audience: gate, OrderID: order, ListingVersionID: listing, FileID: fileID, SHA256: sha, JTI: request, IssuedAt: 1767225600, StartDeadline: 1767226500, TransferDeadline: 1767226600}, "permission"},
		"offer":      {"aim-offer+jwt", offer, "instruction"}, "unoffer": {"aim-offer+jwt", unoffer, "instruction"},
		"describe": {"aim-describe+jwt", describe, "instruction"}, "revoke": {"aim-revoke+jwt", revoke, "instruction"},
		"prepare": {"aim-prepare+jwt", prepare, "instruction"}, "key_rotation": {"aim-keys+jwt", rotation, "instruction"},
		"minimum_version":     {"aim-minver+jwt", minver, "instruction"},
		"revoke_ack":          {"aim-revoke_ack+jwt", wire.RevokeAck{Op: "revoke_ack", JTI: request, StateBefore: "unknown"}, "revoke_ack"},
		"revocation_ack":      {"aim-revoke_ack+jwt", wire.RevokeAck{Op: "revoke_ack", JTI: request, StateBefore: "active"}, "revoke_ack"},
		"prepare_ack":         {"aim-prepare_ack+jwt", wire.PrepareAck{Op: "prepare_ack", IID: request, OrderID: order, FileID: fileID, Ready: true}, "prepare_ack"},
		"prepare_ack_refusal": {"aim-prepare_ack+jwt", wire.PrepareAck{Op: "prepare_ack", IID: request, OrderID: order, FileID: fileID, Refusal: &prepareRefusal}, "prepare_ack"},
		"receipt":             {"aim-receipt+jwt", wire.Receipt{Op: "receipt", OrderID: order, FileID: fileID, SHA256: sha, SizeBytes: 2, JTIs: []string{request}, Transmitted: []wire.Interval{{0, 1}}, TransmittedBytes: 2, Outcome: "complete", BlocksVerified: true, FirstByteAt: now.Format(time.RFC3339), LastByteAt: now.Add(time.Second).Format(time.RFC3339), Seq: 1}, "receipt"},
		"hello":               {"aim-hello+jwt", wire.Hello{GatewayID: gate, Nonce: "test-only-nonce", Version: "1.0.0", Time: now.Format(time.RFC3339)}, "hello"},
		"inventory":           {"aim-inventory+jwt", inventory.Batch{Generation: 1, Files: []inventory.Phase1{{FileID: fileID, DisplayName: "file-01234567.csv", SizeBytes: 2, MediaType: "text/csv", ContentCommitment: commitment, FirstSeenAt: now, ChangedAt: now, Present: true}}}, "inventory"},
		"description":         {"aim-description+jwt", wire.Description{FileID: fileID, SHA256: sha, RowCount: 2, Columns: []wire.Column{{Name: "safe", Type: "integer", NullRatePct: &zero, DistinctBucket: "2-10"}}}, "description"},
		"canary_result":       {"aim-canary_result+jwt", wire.CanaryResult{State: "closed", DNS: "closed", TCP: "closed", Proxy: "closed", Label: "test-only", At: now.Format(time.RFC3339)}, "canary_result"},
		"offer_ack":           {"aim-offer_ack+jwt", wire.OfferAck{IID: request, FileID: fileID, Ready: true}, "offer_ack"},
		"offer_ack_refusal":   {"aim-offer_ack+jwt", wire.OfferAck{IID: request, FileID: fileID, Refusal: &refusal}, "offer_ack"},
		"error":               {"aim-error+jwt", wire.GatewayError{Code: "read_error", Message: "test only"}, "error"},
	}
	fs["permission_wrong_key"] = fs["permission"]
	fs["offer_wrong_typ"] = fs["offer"]
	fs["hello_tampered"] = fs["hello"]
	names := make([]string, 0, len(fs))
	for n := range fs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			f := fs[name]
			canonical, err := wire.Canonical(f.body)
			if err != nil {
				t.Fatal(err)
			}
			v := vector{Label: "TEST ONLY - synthetic golden vector", TestOnlySeedHex: hex.EncodeToString(seed), TestOnlyPublicHex: hex.EncodeToString(pub), Input: canonical, Canonical: string(canonical), ExpectedVerdict: "valid"}
			v.Token, err = wire.Sign(f.typ, "test-only-kid", f.body, priv)
			if err != nil {
				t.Fatal(err)
			}
			verifyKeys := keys
			switch name {
			case "permission_wrong_key":
				v.ExpectedVerdict = "invalid"
				v.Token, err = wire.Sign(f.typ, "test-only-kid", f.body, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x43}, 32)))
				if err != nil {
					t.Fatal(err)
				}
			case "offer_wrong_typ":
				v.ExpectedVerdict = "invalid"
				v.Token, err = wire.Sign("aim-describe+jwt", "test-only-kid", f.body, priv)
				if err != nil {
					t.Fatal(err)
				}
			case "hello_tampered":
				v.ExpectedVerdict = "invalid"
				parts := strings.Split(v.Token, ".")
				parts[1] = strings.Repeat("A", len(parts[1]))
				v.Token = strings.Join(parts, ".")
			}
			data, err := json.MarshalIndent(v, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			data = append(data, '\n')
			path := filepath.Join("vectors", name+".json")
			if os.Getenv("UPDATE_VECTORS") == "1" {
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, data) {
				t.Fatal("golden vector byte drift")
			}
			var committed vector
			if err := json.Unmarshal(got, &committed); err != nil {
				t.Fatal(err)
			}
			input, err := wire.Canonical(committed.Input)
			if err != nil {
				t.Fatal(err)
			}
			if committed.ExpectedVerdict != v.ExpectedVerdict || committed.Canonical != string(canonical) || !bytes.Equal(input, canonical) {
				t.Fatal("vector metadata drift")
			}
			err = verify(f.kind, committed.Token, verifyKeys)
			if (err == nil) != (committed.ExpectedVerdict == "valid") {
				t.Fatalf("expected %s, got %v", committed.ExpectedVerdict, err)
			}
		})
	}
	extras := struct {
		NullRateBoundaries map[string]*int  `json:"null_rate_boundaries"`
		DefaultDisplayName string           `json:"default_display_name"`
		InclusiveIntervals map[string]int64 `json:"inclusive_intervals"`
	}{map[string]*int{"249_of_10000": profile.NullRate(249, 10000), "250_of_10000": profile.NullRate(250, 10000), "9749_of_10000": profile.NullRate(9749, 10000), "9750_of_10000": profile.NullRate(9750, 10000), "zero_rows": profile.NullRate(0, 0)}, ids.DisplayName(fileID, "text/csv"), map[string]int64{"byte_zero": (wire.Interval{0, 0}).Length(), "byte_one": (wire.Interval{1, 1}).Length(), "last_byte": (wire.Interval{99, 99}).Length(), "suffix_10_of_100": (wire.Interval{90, 99}).Length(), "open_ended_from_10_of_100": (wire.Interval{10, 99}).Length()}}
	canonical, err := wire.Canonical(extras)
	if err != nil {
		t.Fatal(err)
	}
	v := vector{Label: "TEST ONLY - synthetic golden vector", TestOnlySeedHex: hex.EncodeToString(seed), TestOnlyPublicHex: hex.EncodeToString(pub), Input: canonical, Canonical: string(canonical), ExpectedVerdict: "valid"}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	path := filepath.Join("vectors", "boundaries.json")
	if os.Getenv("UPDATE_VECTORS") == "1" {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("boundary vector drift")
	}
}

func verify(kind, token string, keys map[string]ed25519.PublicKey) error {
	switch kind {
	case "permission":
		_, err := wire.VerifyPermission(token, keys)
		return err
	case "instruction":
		_, err := wire.VerifyInstruction(token, keys)
		return err
	default:
		return wire.VerifyGatewayAnswer(token, kind, keys, newAnswer(kind))
	}
}
func newAnswer(kind string) any {
	switch kind {
	case "revoke_ack":
		return new(wire.RevokeAck)
	case "prepare_ack":
		return new(wire.PrepareAck)
	case "receipt":
		return new(wire.Receipt)
	case "hello":
		return new(wire.Hello)
	case "inventory":
		return new(inventory.Batch)
	case "description":
		return new(wire.Description)
	case "canary_result":
		return new(wire.CanaryResult)
	case "offer_ack":
		return new(wire.OfferAck)
	default:
		return new(wire.GatewayError)
	}
}
