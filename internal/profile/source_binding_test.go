package profile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aidotmarket/aim-data-gateway/internal/config"
	"github.com/aidotmarket/aim-data-gateway/internal/ids"
	"github.com/aidotmarket/aim-data-gateway/internal/inventory"
)

func inventoryBody(t *testing.T, body []byte) inventory.Record {
	t.Helper()
	root := t.TempDir()
	if e := os.WriteFile(filepath.Join(root, "data"), body, 0600); e != nil {
		t.Fatal(e)
	}
	k, _ := ids.Derive(make([]byte, 32))
	records, e := inventory.Scan(config.Config{Sources: []config.Source{{Name: "binding", Path: root}}}, k)
	if e != nil {
		t.Fatal(e)
	}
	return records[0]
}

func TestSourceBindingChangedAfterInventory(t *testing.T) {
	for _, sameStat := range []bool{false, true} {
		t.Run(map[bool]string{false: "new_rows", true: "same_size_mtime"}[sameStat], func(t *testing.T) {
			r := inventoryBody(t, []byte("a,b\n1,2\n"))
			body := []byte("a,b\n1,2\n3,4\n")
			if sameStat {
				body = []byte("a,b\nx,y\n")
			}
			if e := os.WriteFile(r.Path, body, 0600); e != nil {
				t.Fatal(e)
			}
			if sameStat {
				if e := os.Chtimes(r.Path, r.Mtime, r.Mtime); e != nil {
					t.Fatal(e)
				}
			}
			d, e := File(r, config.Columns{})
			if e == nil {
				t.Fatalf("changed bytes returned metadata under inventory hash: %+v", d)
			}
			if d.SHA256 != "" || d.Columns != nil {
				t.Fatalf("failure leaked description: %+v", d)
			}
		})
	}
}

// Freeze complete D9 payloads for text and every existing Parquet codec fixture.
func TestSourceBindingUnchangedPayloads(t *testing.T) {
	for _, body := range []string{"a,b\n1,x\n2,\n", "a\tb\n1\tx\n2\t\n", "{\"a\":1,\"b\":\"x\"}\n{\"a\":2,\"b\":null}\n"} {
		r := inventoryBody(t, []byte(body))
		d, e := File(r, config.Columns{Rename: map[string]string{"a": "public"}})
		if e != nil {
			t.Fatal(e)
		}
		sum := sha256.Sum256([]byte(body))
		if d.SHA256 != hex.EncodeToString(sum[:]) || d.RowCount != 2 {
			t.Fatal(d)
		}
		raw, e := json.Marshal(d)
		if e != nil {
			t.Fatal(e)
		}
		want := `{"sha256":"` + hex.EncodeToString(sum[:]) + `","row_count":2,"columns":[{"name":"public","type":"integer","null_rate_pct":0,"distinct_bucket":"2-10"},{"name":"b","type":"string","null_rate_pct":50,"distinct_bucket":"1"}]}`
		if string(raw) != want {
			t.Fatalf("payload changed: %s", raw)
		}
		t.Logf("PAYLOAD %s %s", r.Phase1.MediaType, raw)
	}
	k, _ := ids.Derive(make([]byte, 32))
	records, e := inventory.Scan(config.Config{Sources: []config.Source{{Name: "fixtures", Path: "testdata"}}}, k)
	if e != nil {
		t.Fatal(e)
	}
	for _, r := range records {
		for _, rule := range []config.Columns{{}, {Drop: []string{"i", "f", "s", "b", "d", "ts"}}} {
			d, e := FileContext(context.Background(), r, rule)
			if e != nil {
				t.Fatal(e)
			}
			raw, e := json.Marshal(d)
			if e != nil {
				t.Fatal(e)
			}
			columns := `[{"name":"i","type":"integer","null_rate_pct":25,"distinct_bucket":"2-10"},{"name":"f","type":"float","null_rate_pct":25,"distinct_bucket":"2-10"},{"name":"s","type":"string","null_rate_pct":25,"distinct_bucket":"2-10"},{"name":"b","type":"boolean","null_rate_pct":25,"distinct_bucket":"2-10"},{"name":"d","type":"date","null_rate_pct":25,"distinct_bucket":"2-10"},{"name":"ts","type":"timestamp","null_rate_pct":25,"distinct_bucket":"2-10"}]`
			if len(rule.Drop) > 0 {
				columns = "[]"
			}
			want := `{"sha256":"` + inventory.SHAHex(r) + `","row_count":4,"columns":` + columns + `}`
			if string(raw) != want {
				t.Fatalf("%s payload changed: %s", r.RelativePath, raw)
			}
			t.Logf("PAYLOAD %s drop=%d %s", r.RelativePath, len(rule.Drop), raw)
		}
	}
}
