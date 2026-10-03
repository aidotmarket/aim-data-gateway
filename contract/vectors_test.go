package contract

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
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
	"github.com/aidotmarket/aim-data-gateway/verification"
)

type verificationSource struct {
	members []verification.Member
	data    map[string][]byte
}

func (s verificationSource) Members() []verification.Member { return s.members }
func (s verificationSource) Open(_ context.Context, stringID string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(s.data[stringID])), nil
}
func (s verificationSource) OpenAt(context.Context, string) (verification.RandomAccess, error) {
	panic("Parquet not present in this fixture")
}
func TestVerificationSourceBindingVector(t *testing.T) {
	raw, e := os.ReadFile("vectors/verification/source_bindings.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		Source map[string]string `json:"source_hex"`
		Input  struct {
			Gateway  string `json:"gateway_id"`
			Snapshot string `json:"snapshot_hash"`
			Key      string `json:"commitment_key_hex"`
			Members  []struct {
				ID   string `json:"file_id"`
				SHA  string `json:"sha256"`
				Size int64  `json:"size_bytes"`
			}
			Objects     []verification.Object
			Coverage    verification.Coverage
			Content     string `json:"content_sha256"`
			Locator     string `json:"artifact_locator_commitment"`
			Fingerprint string `json:"fingerprint_hash"`
			Legacy      struct {
				Root            string            `json:"root_path"`
				Key             string            `json:"commitment_key_hex"`
				LocatorPreimage string            `json:"locator_preimage_hex"`
				Locator         string            `json:"artifact_locator_commitment"`
				Content         string            `json:"content_sha256"`
				ObjectIDs       map[string]string `json:"object_ids"`
				Members         []struct {
					Path string `json:"relative_path"`
					Size int64  `json:"size_bytes"`
					SHA  string `json:"sha256"`
					Role string
				}
			} `json:"legacy_directory"`
		}
	}
	if e = json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	src := verificationSource{data: map[string][]byte{}}
	for _, m := range v.Input.Members {
		data, e := hex.DecodeString(v.Source[m.ID])
		if e != nil {
			t.Fatal(e)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != m.SHA || int64(len(data)) != m.Size {
			t.Fatal("source digest")
		}
		src.data[m.ID] = data
		src.members = append(src.members, verification.Member{Identity: m.ID, Size: m.Size, SHA256: sum, Format: "csv"})
	}
	key, e := hex.DecodeString(v.Input.Key)
	if e != nil {
		t.Fatal(e)
	}
	p := verification.Policy{CanonicalizationVersion: "python-json-sort-compact-v1", RowCountAlgorithmVersion: "exact-v1", DistinctAlgorithmVersion: "hll-sha256-v1", HistogramVersion: "fixed-buckets-v1", NumericBucketVersion: "fixed-buckets-v1", MinimumAggregateOccupancy: 10, LengthBounds: []int{0, 1, 4, 8, 16, 32, 64, 128, 256}, NumericBoundaries: []float64{-1000, -100, -10, 0, 10, 100, 1000}, GatewayID: v.Input.Gateway, SnapshotHash: v.Input.Snapshot}
	copy(p.CommitmentKey[:], key)
	facts, e := verification.Scan(context.Background(), src, p)
	if e != nil {
		t.Fatal(e)
	}
	actual, e := wire.Canonical(facts.Objects)
	if e != nil {
		t.Fatal(e)
	}
	expected, e := wire.Canonical(v.Input.Objects)
	if e != nil || !bytes.Equal(actual, expected) {
		t.Fatalf("Python source fact bytes differ: %v", e)
	}
	actual, _ = wire.Canonical(facts.Coverage)
	expected, _ = wire.Canonical(v.Input.Coverage)
	if !bytes.Equal(actual, expected) || facts.ContentSHA256 != v.Input.Content || facts.LocatorCommitment != v.Input.Locator || facts.FingerprintHash != v.Input.Fingerprint {
		t.Fatal("gateway source binding drift")
	}
	// Version-only republishing preserves object/content commitments; key rotation
	// preserves content but changes keyed identities.
	p.SnapshotHash = strings.Repeat("b", 64)
	republished, e := verification.Scan(context.Background(), src, p)
	if e != nil || republished.ContentSHA256 != facts.ContentSHA256 || republished.Objects[0].ObjectID != facts.Objects[0].ObjectID || republished.LocatorCommitment == facts.LocatorCommitment {
		t.Fatal("version-only binding", e)
	}
	p.CommitmentKey[0] ^= 1
	rotated, e := verification.Scan(context.Background(), src, p)
	if e != nil || rotated.ContentSHA256 != facts.ContentSHA256 || rotated.Objects[0].ObjectID == facts.Objects[0].ObjectID {
		t.Fatal("key binding", e)
	}
	// The unchanged old-directory vector uses its own framing and preimages.
	legacy := v.Input.Legacy
	legacyKey, e := hex.DecodeString(legacy.Key)
	if e != nil {
		t.Fatal(e)
	}
	mac := func(pre []byte) string {
		h := hmac.New(sha256.New, legacyKey)
		h.Write(pre)
		return hex.EncodeToString(h.Sum(nil))
	}
	pre, e := hex.DecodeString(legacy.LocatorPreimage)
	if e != nil || mac(pre) != legacy.Locator {
		t.Fatal("legacy locator")
	}
	members := legacy.Members
	sort.Slice(members, func(i, j int) bool { return members[i].Path < members[j].Path })
	content := sha256.New()
	var frame [8]byte
	for _, m := range members {
		if m.Role != "data" {
			continue
		}
		sha, e := hex.DecodeString(m.SHA)
		if e != nil {
			t.Fatal(e)
		}
		binary.BigEndian.PutUint64(frame[:], uint64(len(m.Path)))
		content.Write(frame[:])
		content.Write([]byte(m.Path))
		binary.BigEndian.PutUint64(frame[:], uint64(m.Size))
		content.Write(frame[:])
		content.Write(sha)
		if mac([]byte("object\x00local_directory_object\x00"+legacy.Root+"\x00member\x00"+m.Path+"\x00"+m.SHA)) != legacy.ObjectIDs[m.Path] {
			t.Fatal("legacy object commitment")
		}
	}
	if hex.EncodeToString(content.Sum(nil)) != legacy.Content {
		t.Fatal("legacy directory content")
	}
}

// These fixtures are transport contracts only. No scan wire, ledger or channel
// handler is added in chunk 1a; the later chunks enforce admission semantics.
func TestVerificationSharedVectors(t *testing.T) {
	paths, e := filepath.Glob("vectors/verification/*.json")
	if e != nil || len(paths) != 13 {
		t.Fatalf("shared fixture inventory: %v %d", e, len(paths))
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			raw, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			var v struct {
				TestOnlySeedHex   string `json:"test_only_seed_hex"`
				TestOnlyPublicHex string `json:"test_only_public_hex"`
				Canonical         string
				CanonicalSHA      string `json:"canonical_sha256"`
				Input             json.RawMessage
				Token, Typ        string
				Negative          []struct {
					Name, Token string
					Verdict     string `json:"expected_verdict"`
				} `json:"negative_cases"`
			}
			if e = json.Unmarshal(raw, &v); e != nil {
				t.Fatal(e)
			}
			sum := sha256.Sum256([]byte(v.Canonical))
			if hex.EncodeToString(sum[:]) != v.CanonicalSHA {
				t.Fatal("canonical hash drift")
			}
			if !json.Valid([]byte(v.Canonical)) {
				t.Fatal("invalid canonical JSON")
			}
			seed, e := hex.DecodeString(v.TestOnlySeedHex)
			if e != nil {
				t.Fatal(e)
			}
			private := ed25519.NewKeyFromSeed(seed)
			public, e := hex.DecodeString(v.TestOnlyPublicHex)
			if e != nil || !bytes.Equal(private.Public().(ed25519.PublicKey), public) {
				t.Fatal("synthetic key binding")
			}
			if v.Token != "" {
				var body map[string]any
				d := json.NewDecoder(bytes.NewReader(v.Input))
				d.UseNumber()
				if e = d.Decode(&body); e != nil {
					t.Fatal(e)
				}
				token, e := wire.Sign(v.Typ, "test-only-scan-key", body, private)
				if e != nil || token != v.Token {
					t.Fatalf("Python/Go JWS bytes differ: %v", e)
				}
				valid := func(token string) bool {
					parts := strings.Split(token, ".")
					if len(parts) != 3 {
						return false
					}
					header, e := base64.RawURLEncoding.DecodeString(parts[0])
					if e != nil {
						return false
					}
					var h struct{ Alg, Kid, Typ string }
					if json.Unmarshal(header, &h) != nil || h.Alg != "EdDSA" || h.Kid != "test-only-scan-key" || h.Typ != v.Typ {
						return false
					}
					signature, e := base64.RawURLEncoding.DecodeString(parts[2])
					return e == nil && ed25519.Verify(public, []byte(parts[0]+"."+parts[1]), signature)
				}
				if !valid(v.Token) {
					t.Fatal("valid shared JWS refused")
				}
				for _, n := range v.Negative {
					if n.Token != "" && valid(n.Token) {
						t.Fatalf("accepted %s", n.Name)
					}
				}
			}
		})
	}
}

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
		"hello":               {"aim-hello+jwt", wire.Hello{GatewayID: gate, Nonce: strings.Repeat("a", 64), Version: "1.0.0", Time: now.Format(time.RFC3339)}, "hello"},
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
