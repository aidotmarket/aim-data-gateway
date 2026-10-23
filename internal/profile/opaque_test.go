package profile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aidotmarket/aim-data-gateway/internal/config"
	"github.com/aidotmarket/aim-data-gateway/internal/ids"
	"github.com/aidotmarket/aim-data-gateway/internal/inventory"
)

func profileRecord(t *testing.T, body string) inventory.Record {
	t.Helper()
	root := t.TempDir()
	if e := os.WriteFile(filepath.Join(root, "fixture.bin"), []byte(body), 0600); e != nil {
		t.Fatal(e)
	}
	k, _ := ids.Derive(make([]byte, 32))
	records, e := inventory.Scan(config.Config{Sources: []config.Source{{Name: "data", Path: root}}}, k)
	if e != nil || len(records) != 1 {
		t.Fatalf("inventory: %v %d", e, len(records))
	}
	return records[0]
}

func TestOpaqueDescriptions(t *testing.T) {
	many := map[string]int{}
	for i := 0; i < 1001; i++ {
		many[fmt.Sprintf("k%d", i)] = i
	}
	keys, _ := json.Marshal(many)
	for name, body := range map[string]string{
		"pdf": "%PDF-1.7\nopaque document", "zip": "PK\x03\x04\x00opaque", "binary": "\x00\xff\x01\x02",
		"pretty_json": "{\n  \"x\": 1\n}\n", "array": "[{\"x\":1},{\"x\":2}]\n",
		"csv_header_quote": "bad\"header,other\n1,2\n", "csv_body_quote": "a,b\n1,bad\"quote\n",
		"prose_quote": "Hello, reader\nA bare \"quote in prose\n",
		"long_line":   "{\"x\":1}\n{\"x\":\"" + strings.Repeat("x", 16<<20) + "\"}\n",
		"many_keys":   "{\"x\":1}\n" + string(keys) + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			r := profileRecord(t, body)
			d, e := File(r, config.Columns{})
			if e != nil {
				t.Fatal(e)
			}
			sum := sha256.Sum256([]byte(body))
			want := `{"sha256":"` + hex.EncodeToString(sum[:]) + `","row_count":0,"columns":[]}`
			raw, _ := json.Marshal(d)
			if string(raw) != want {
				t.Fatalf("opaque bytes: %s", raw)
			}
		})
	}
}

func TestDocumentedTableLimitsAndBlankNDJSON(t *testing.T) {
	for name, body := range map[string]string{
		"prose":  "Hello, reader\nThis is still treated as a row\n",
		"object": "{\"x\":1}\n", "blank_ndjson": "{\"x\":1}\n\n \t \r\n{\"x\":2}\n",
	} {
		t.Run(name, func(t *testing.T) {
			d, e := File(profileRecord(t, body), config.Columns{})
			wantRows := int64(1)
			if name == "blank_ndjson" {
				wantRows = 2
			}
			if e != nil || d.RowCount != wantRows || len(d.Columns) == 0 {
				t.Fatalf("%+v %v", d, e)
			}
		})
	}
}

func TestProfileOpenFailureAndBrokenParquet(t *testing.T) {
	r := profileRecord(t, "a,b\n1,2\n")
	if e := os.Remove(filepath.Join(r.Root, r.RelativePath)); e != nil {
		t.Fatal(e)
	}
	if d, e := File(r, config.Columns{}); e == nil || d.Columns != nil {
		t.Fatalf("open failure stored description: %+v %v", d, e)
	}
	r = profileRecord(t, "PAR1broken")
	if d, e := FileContext(context.Background(), r, config.Columns{}); e == nil || d.Columns != nil {
		t.Fatalf("broken parquet: %+v %v", d, e)
	}
}
