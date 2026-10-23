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

	"github.com/aidotmarket/aim-data-gateway/internal/config"
	"github.com/aidotmarket/aim-data-gateway/internal/ids"
	"github.com/aidotmarket/aim-data-gateway/internal/inventory"
	"github.com/aidotmarket/aim-data-gateway/internal/profile"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
)

// Source bytes and the signed description travel together for the backend copy.
func TestOpaqueDescriptionVectors(t *testing.T) {
	for name, source := range map[string]string{
		"description_opaque":         "%PDF-1.7\nopaque document\n",
		"description_minified_array": "[{\"x\":1},{\"x\":2}]\n",
		"description_comma_quote":    "Hello, reader\nA bare \"quote in prose\n",
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if e := os.WriteFile(filepath.Join(root, "fixture.bin"), []byte(source), 0600); e != nil {
				t.Fatal(e)
			}
			k, _ := ids.Derive(make([]byte, 32))
			records, e := inventory.Scan(config.Config{Sources: []config.Source{{Name: "data", Path: root}}}, k)
			if e != nil || len(records) != 1 {
				t.Fatal("inventory", e)
			}
			d, e := profile.File(records[0], config.Columns{})
			if e != nil {
				t.Fatal(e)
			}
			sum := sha256.Sum256([]byte(source))
			// Expected independently of the profiler, including the non-null columns.
			expected := wire.Description{FileID: fileID, SHA256: hex.EncodeToString(sum[:]), Columns: []wire.Column{}}
			actual := wire.Description{FileID: fileID, SHA256: d.SHA256, RowCount: d.RowCount, Columns: []wire.Column{}}
			if len(d.Columns) != 0 || d.Columns == nil {
				t.Fatal("not opaque", d)
			}
			canonical, e := wire.Canonical(actual)
			if e != nil {
				t.Fatal(e)
			}
			want, _ := wire.Canonical(expected)
			if !bytes.Equal(canonical, want) {
				t.Fatalf("opaque description: %s", canonical)
			}
			seed := bytes.Repeat([]byte{0x42}, 32)
			key := ed25519.NewKeyFromSeed(seed)
			token, e := wire.Sign("aim-description+jwt", "test-only-kid", actual, key)
			if e != nil {
				t.Fatal(e)
			}
			v := struct {
				vector
				SourceHex    string `json:"source_hex"`
				DetectedType string `json:"detected_type"`
			}{vector: vector{Label: "TEST ONLY - synthetic opaque description", TestOnlySeedHex: hex.EncodeToString(seed), TestOnlyPublicHex: hex.EncodeToString(key.Public().(ed25519.PublicKey)), Input: canonical, Canonical: string(canonical), Token: token, ExpectedVerdict: "valid"}, SourceHex: hex.EncodeToString([]byte(source)), DetectedType: records[0].Phase1.MediaType}
			raw, e := json.MarshalIndent(v, "", "  ")
			if e != nil {
				t.Fatal(e)
			}
			raw = append(raw, 10)
			path := filepath.Join("vectors", name+".json")
			if os.Getenv("UPDATE_VECTORS") == "1" {
				if e := os.WriteFile(path, raw, 0600); e != nil {
					t.Fatal(e)
				}
			}
			committed, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(committed, raw) {
				t.Fatal("opaque golden drift")
			}
			if e := verify("description", token, map[string]ed25519.PublicKey{"test-only-kid": key.Public().(ed25519.PublicKey)}); e != nil {
				t.Fatal(e)
			}
		})
	}
}
