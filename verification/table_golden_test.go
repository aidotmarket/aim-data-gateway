package verification

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/apache/arrow-go/v18/parquet"
	"github.com/apache/arrow-go/v18/parquet/file"
	"github.com/apache/arrow-go/v18/parquet/schema"
	"os"
	"strings"
	"testing"
)

// Small generated fixtures preserve the six-column S1888 rehearsal shapes.
func rehearsalSource(t *testing.T, nameWidth int) *memorySource {
	t.Helper()
	names := []string{"id", "region", "sku", "qty", "price", "note"}
	if nameWidth > 0 {
		for i := range names {
			names[i] = fmt.Sprintf("%0*d", nameWidth, i)
		}
	}
	var csv, lines strings.Builder
	csv.WriteString(strings.Join(names, ",") + "\n")
	for n := 0; n < 20; n++ {
		fmt.Fprintf(&csv, "%d,eu,SKU-%05d,%d,12.5,generated note\n", n, n, n+1)
		fmt.Fprintf(&lines, "{\"%s\":%d,\"%s\":\"eu\",\"%s\":\"SKU-%05d\",\"%s\":%d,\"%s\":12.5,\"%s\":\"generated note\"}\n", names[0], n, names[1], names[2], n, names[3], n+1, names[4], names[5])
	}
	var fields schema.FieldList
	for i, n := range names {
		typ := parquet.Types.Int64
		if i == 1 || i == 2 || i == 5 {
			typ = parquet.Types.ByteArray
		}
		if i == 4 {
			typ = parquet.Types.Double
		}
		v, e := schema.NewPrimitiveNode(n, parquet.Repetitions.Required, typ, -1, -1)
		if e != nil {
			t.Fatal(e)
		}
		fields = append(fields, v)
	}
	root, e := schema.NewGroupNode("schema", parquet.Repetitions.Required, fields, -1)
	if e != nil {
		t.Fatal(e)
	}
	var buf bytes.Buffer
	w := file.NewParquetWriter(&buf, root)
	g := w.AppendRowGroup()
	for i := range names {
		c, e := g.NextColumn()
		if e != nil {
			t.Fatal(e)
		}
		switch i {
		case 1, 2, 5:
			values := make([]parquet.ByteArray, 20)
			for n := range values {
				values[n] = parquet.ByteArray(fmt.Sprintf("generated-%d", n))
			}
			_, e = c.(*file.ByteArrayColumnChunkWriter).WriteBatch(values, nil, nil)
		case 4:
			values := make([]float64, 20)
			for n := range values {
				values[n] = float64(n) + 0.5
			}
			_, e = c.(*file.Float64ColumnChunkWriter).WriteBatch(values, nil, nil)
		default:
			values := make([]int64, 20)
			for n := range values {
				values[n] = int64(n + 1)
			}
			_, e = c.(*file.Int64ColumnChunkWriter).WriteBatch(values, nil, nil)
		}
		if e != nil {
			t.Fatal(e)
		}
		if e = c.Close(); e != nil {
			t.Fatal(e)
		}
	}

	if e = g.Close(); e != nil {
		t.Fatal(e)
	}
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	s := &memorySource{data: map[string][]byte{}, opens: map[string]int{}}
	for i, x := range []struct {
		name, format string
		data         []byte
	}{{"orders-01.csv", "csv", []byte(csv.String())}, {"events-01.jsonl", "jsonl", []byte(lines.String())}, {"accounts-01.parquet", "parquet", buf.Bytes()}, {"accounts-02.parquet", "parquet", buf.Bytes()}} {
		id := fmt.Sprintf("%032x", i+1)
		s.members = append(s.members, Member{Identity: id, Size: int64(len(x.data)), Format: x.format, SHA256: sha256.Sum256(x.data)})
		s.data[id] = x.data
	}
	return s
}
func TestTableV1Golden(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    *memorySource
	}{{"existing", sourceFor(read(t, "testdata/oracle/distinct_100_reverse.csv"), "csv")}, {"s1888", rehearsalSource(t, 0)}} {
		p := testPolicy()
		p.ScanMode = "table_v1"
		f, e := Scan(context.Background(), tc.s, p)
		if e != nil {
			t.Fatal(e)
		}
		raw, e := canonical(f)
		if e != nil {
			t.Fatal(e)
		}
		path := "testdata/census/" + tc.name + "-table-v1.json"
		if os.Getenv("C1_WRITE_BASELINE") == "1" {
			if e = os.MkdirAll("testdata/census", 0755); e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(path, raw, 0644); e != nil {
				t.Fatal(e)
			}
		}
		if !bytes.Equal(raw, read(t, path)) {
			t.Fatalf("%s table bytes changed", tc.name)
		}
	}
}
