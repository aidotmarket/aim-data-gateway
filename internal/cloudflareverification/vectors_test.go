package cloudflareverification

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aidotmarket/aim-data-gateway/verification"
)

func TestSharedR2Vectors(t *testing.T) {
	paths, err := filepath.Glob("../../contract/vectors/verification/r2_listing/*.json")
	if err != nil || len(paths) < 12 {
		t.Fatal(paths, err)
	}
	for _, path := range paths {
		if filepath.Base(path) == "refusals.json" || filepath.Base(path) == "bridge_cases.json" || filepath.Base(path) == "control.json" {
			continue
		}
		t.Run(filepath.Base(path), func(t *testing.T) {
			raw, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			var v struct {
				Snapshot struct {
					Bucket  string
					Members []struct {
						Key, ETag, Format string
						Version           string `json:"version_id"`
						Size              int64  `json:"size_bytes"`
					}
				}
				SnapshotCanonical string          `json:"snapshot_canonical"`
				SnapshotHash      string          `json:"snapshot_sha256"`
				SnapshotJWS       string          `json:"snapshot_jws"`
				SnapshotClaims    json.RawMessage `json:"snapshot_claims"`
				Seed              string          `json:"seed_hex"`
				Members           []struct {
					Identity string
					Order    string `json:"ordering_key_hex"`
					Source   string `json:"source_hex"`
					SHA      string `json:"sha256"`
				}
				ContentPreimage  string   `json:"content_preimage_hex"`
				LocatorPreimage  string   `json:"locator_preimage_hex"`
				ObjectPreimages  []string `json:"object_preimages_hex"`
				FactsCanonical   string   `json:"facts_canonical"`
				ReceiptCanonical string   `json:"receipt_canonical"`
				ReceiptSignature string   `json:"receipt_signature"`
			}
			if e = json.Unmarshal(raw, &v); e != nil {
				t.Fatal(e)
			}
			digest := sha256.Sum256([]byte(v.SnapshotCanonical))
			if hex.EncodeToString(digest[:]) != v.SnapshotHash {
				t.Fatal("snapshot hash")
			}
			if _, e = verification.ParseCanonical([]byte(v.SnapshotCanonical)); e != nil {
				t.Fatal("snapshot canonical", e)
			}
			segments := strings.Split(v.SnapshotJWS, ".")
			if len(segments) != 3 {
				t.Fatal("JWS")
			}
			sig, e := base64.RawURLEncoding.DecodeString(segments[2])
			if e != nil {
				t.Fatal(e)
			}
			scanKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{66}, 32))
			if !ed25519.Verify(scanKey.Public().(ed25519.PublicKey), []byte(segments[0]+"."+segments[1]), sig) {
				t.Fatal("snapshot signature")
			}
			claimsRaw, e := base64.RawURLEncoding.DecodeString(segments[1])
			if e != nil {
				t.Fatal(e)
			}
			var claims struct {
				Payload string `json:"payload_b64"`
				Hash    string `json:"manifest_hash"`
				Aud     string
			}
			if e = json.Unmarshal(claimsRaw, &claims); e != nil {
				t.Fatal(e)
			}
			payload, e := base64.RawURLEncoding.DecodeString(claims.Payload)
			if e != nil || string(payload) != v.SnapshotCanonical || claims.Hash != v.SnapshotHash || claims.Aud != "66666666-6666-4666-8666-666666666666" {
				t.Fatal("JWS binding", e)
			}
			f := &fakeBridge{objects: map[string][]byte{}}
			objects := []Object{}
			var frame bytes.Buffer
			for i, m := range v.Snapshot.Members {
				input := v.Members[i]
				data, e := hex.DecodeString(input.Source)
				if e != nil {
					t.Fatal(e)
				}
				f.objects[m.Key] = data
				objects = append(objects, Object{
					Key:    m.Key,
					ETag:   m.ETag,
					Format: m.Format,
					Size:   m.Size,
				})
				pin := m.ETag
				id, e := Identity(m.Key, pin)
				if e != nil || id != input.Identity || hex.EncodeToString([]byte(id)) != input.Order {
					t.Fatal("identity/order", e)
				}
				h := sha256.Sum256(data)
				if hex.EncodeToString(h[:]) != input.SHA {
					t.Fatal("member digest")
				}
				binary.Write(&frame, binary.BigEndian, uint64(len(id)))
				frame.WriteString(id)
				binary.Write(&frame, binary.BigEndian, uint64(len(data)))
				frame.Write(h[:])
				preimage := "object\x00r2_listing\x00" + v.Snapshot.Bucket + "\x00" + id + "\x00" + input.SHA
				if hex.EncodeToString([]byte(preimage)) != v.ObjectPreimages[i] {
					t.Fatal("object preimage")
				}
			}
			if hex.EncodeToString(frame.Bytes()) != v.ContentPreimage {
				t.Fatal("content preimage")
			}
			if hex.EncodeToString([]byte("r2_listing\x00"+v.Snapshot.Bucket+"\x00"+v.SnapshotHash)) != v.LocatorPreimage {
				t.Fatal("locator preimage")
			}
			var envelope struct {
				ConnectionID     string `json:"connection_id"`
				ListingID        string `json:"listing_id"`
				ListingVersionID string `json:"listing_version_id"`
				SourceHandleID   string `json:"source_handle_id"`
			}
			if e := json.Unmarshal([]byte(v.SnapshotCanonical), &envelope); e != nil {
				t.Fatal(e)
			}
			parsed, e := ParseSnapshot([]byte(v.SnapshotCanonical), v.SnapshotHash, SnapshotBinding{envelope.ConnectionID, v.Snapshot.Bucket, envelope.ListingID, envelope.ListingVersionID, envelope.SourceHandleID})
			if e != nil || len(parsed) != len(objects) {
				t.Fatal("snapshot", e)
			}
			for i := range parsed {
				if parsed[i] != objects[i] {
					t.Fatal("parsed members")
				}
			}
			s, e := NewSource(f, v.Snapshot.Bucket, parsed)
			if e != nil {
				t.Fatal(e)
			}
			p := policy()
			p.Commitments = Commitments{Bucket: v.Snapshot.Bucket, ManifestHash: v.SnapshotHash, Key: [32]byte(bytes.Repeat([]byte{99}, 32))}
			if v.Seed != "" {
				seed, e := hex.DecodeString(v.Seed)
				if e != nil {
					t.Fatal(e)
				}
				copy(p.Seed[:], seed)
			}
			for _, present := range []bool{false, true} {
				for i := range s.members {
					s.members[i].DigestPresent = present
					data := f.objects[objects[i].Key]
					s.members[i].SHA256 = sha256.Sum256(data)
				}
				facts, e := verification.Scan(context.Background(), s, p)
				if e != nil {
					t.Fatal(e)
				}
				encoded, e := verification.Canonical(facts)
				if e != nil || string(encoded) != v.FactsCanonical {
					t.Fatalf("oracle bytes present=%v error=%v\ngot=%s\nwant=%s", present, e, encoded, v.FactsCanonical)
				}
			}
			receiptSig, e := base64.StdEncoding.DecodeString(v.ReceiptSignature)
			if e != nil {
				t.Fatal(e)
			}
			receiptKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
			if !ed25519.Verify(receiptKey.Public().(ed25519.PublicKey), []byte(v.ReceiptCanonical), receiptSig) {
				t.Fatal("receipt signature")
			}
			if _, e = verification.ParseCanonical([]byte(v.ReceiptCanonical)); e != nil {
				t.Fatal("receipt canonical")
			}
		})
	}
}

func TestSharedR2Refusals(t *testing.T) {
	raw, e := os.ReadFile("../../contract/vectors/verification/r2_listing/refusals.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		Cases []struct {
			Name    string
			Members []struct {
				Key, ETag string
				Version   string `json:"version_id"`
			}
		}
	}
	if e = json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			objects := []Object{}
			for _, m := range c.Members {
				objects = append(objects, Object{
					Key:    m.Key,
					ETag:   m.ETag,
					Format: "csv",
				})
			}
			f := &fakeBridge{}
			if _, e = NewSource(f, "fixture", objects); e == nil || len(f.requests)+len(f.heads) != 0 {
				t.Fatal("must refuse before provider access", e)
			}
		})
	}
}
