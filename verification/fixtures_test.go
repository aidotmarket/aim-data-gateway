package verification

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
	"testing"
)

// Gate 2 section 7: the S1590 reference fixtures are byte-identical copies
// pinned to their source commit and SHA-256.
func TestS1590FixtureCopiesMatchPinnedDigests(t *testing.T) {
	var manifest struct {
		Repository string `json:"repository"`
		SourcePin  string `json:"source_pin"`
		Files      []struct {
			File   string `json:"file"`
			SHA256 string `json:"sha256"`
			Source string `json:"source"`
		} `json:"files"`
	}
	if e := json.Unmarshal(read(t, "testdata/s1590/manifest.json"), &manifest); e != nil {
		t.Fatal(e)
	}
	if manifest.Repository != "aidotmarket/aim-data" || manifest.SourcePin != "1edd9bfdab112517896c8026510b88ca0168c33e" {
		t.Fatalf("unexpected source pin %s@%s", manifest.Repository, manifest.SourcePin)
	}
	want := []string{"directory_verification_golden.json", "hostile_d6.json", "hostile_reports.json", "lifecycle_client_contract.json", "report.json", "scan_spec.json", "schema_digests.json"}
	var got []string
	for _, f := range manifest.Files {
		got = append(got, f.File)
		sum := sha256.Sum256(read(t, "testdata/s1590/"+f.File))
		if hex.EncodeToString(sum[:]) != f.SHA256 {
			t.Errorf("%s digest drifted from %s", f.File, f.Source)
		}
	}
	sort.Strings(got)
	if len(got) != len(want) {
		t.Fatalf("manifest files %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("manifest files %v, want %v", got, want)
		}
	}
	entries, e := os.ReadDir("testdata/s1590")
	if e != nil {
		t.Fatal(e)
	}
	if len(entries) != len(want)+1 {
		t.Fatalf("unpinned file in testdata/s1590: %d entries", len(entries))
	}
}
