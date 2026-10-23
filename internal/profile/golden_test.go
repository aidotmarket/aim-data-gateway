package profile

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aidotmarket/aim-data-gateway/internal/config"
	"github.com/aidotmarket/aim-data-gateway/internal/ids"
	"github.com/aidotmarket/aim-data-gateway/internal/inventory"
)

// Generated only at ff578372, then compared byte for byte at the chunk A head.
func TestExistingTableDescriptionsGolden(t *testing.T) {
	records := map[string]inventory.Record{}
	for name, body := range map[string]string{
		"csv": "keep,secret\n1,marker\n2,marker\n", "tsv": "keep\tsecret\n3\tmarker\n",
		"jsonl":      "{\"keep\":1,\"secret\":\"marker\"}\n{\"keep\":null}\n",
		"ragged_csv": "keep,secret\n1\n2,marker,extra\n", "bom_csv": "\ufeffkeep,secret\n1,marker\n",
		"header_only": "keep,secret\n",
	} {
		records[name] = profileRecord(t, body)
	}
	k, _ := ids.Derive(make([]byte, 32))
	parquet, e := inventory.Scan(config.Config{Sources: []config.Source{{Name: "pq", Path: "testdata"}}}, k)
	if e != nil {
		t.Fatal(e)
	}
	for _, r := range parquet {
		records[filepath.Base(r.Path)] = r
	}
	got := map[string]Description{}
	for name, r := range records {
		for ruleName, rule := range map[string]config.Columns{
			"none": {}, "filtered": {Drop: []string{"secret", "s"}, Rename: map[string]string{"keep": "public", "i": "public"}},
		} {
			d, e := File(r, rule)
			if e != nil {
				t.Fatalf("%s: %v", name, e)
			}
			got[name+"/"+ruleName] = d
		}
	}
	raw, e := json.MarshalIndent(got, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	raw = append(raw, 10)
	path := "golden/descriptions.json"
	if os.Getenv("UPDATE_PROFILE_GOLDENS") == "1" {
		if e := os.MkdirAll("golden", 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(path, raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	want, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(raw, want) {
		t.Fatal("existing table descriptions changed from ff578372")
	}
}
