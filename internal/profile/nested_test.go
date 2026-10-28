package profile

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/aidotmarket/aim-data-gateway/internal/config"
	"github.com/apache/arrow-go/v18/parquet/file"
)

func TestNestedParquetOpaque(t *testing.T) {
	for _, name := range []string{"list", "fixed_size_list", "nullable_struct", "zero_row_list", "drop_list", "corrupt_pages_list"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", "nested", name+".parquet"))
			if err != nil {
				t.Fatal(err)
			}
			r := profileRecord(t, string(raw))
			f, err := os.Open(r.Path)
			if err != nil {
				t.Fatal(err)
			}
			pf, err := file.NewParquetReader(f)
			if err != nil {
				t.Fatal(err)
			}
			col := pf.MetaData().Schema.Column(0)
			if col.MaxRepetitionLevel() == 0 && col.MaxDefinitionLevel() <= 1 {
				t.Fatal("fixture does not exercise non-flat predicate")
			}
			if name == "nullable_struct" && (col.MaxRepetitionLevel() != 0 || col.MaxDefinitionLevel() <= 1) {
				t.Fatal("struct must exercise definition-level branch alone")
			}
			if name == "zero_row_list" && pf.NumRows() != 0 {
				t.Fatal("fixture is not empty")
			}
			pf.Close()
			rule := config.Columns{}
			if name == "drop_list" {
				// Match the leaf name used by dropped(), so ordering is exercised.
				rule.Drop = []string{col.Name(), "nested"}
			}
			d, err := File(r, rule)
			sum := sha256.Sum256(raw)
			if err != nil || d.SHA256 != hex.EncodeToString(sum[:]) || d.RowCount != 0 || d.Columns == nil || len(d.Columns) != 0 {
				t.Fatalf("opaque description: %+v, %v", d, err)
			}
		})
	}
}
