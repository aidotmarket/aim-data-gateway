package profile

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/aidotmarket/aim-data-gateway/internal/config"
	"github.com/aidotmarket/aim-data-gateway/internal/ids"
	"github.com/aidotmarket/aim-data-gateway/internal/inventory"
)

func TestDistinctBuckets(t *testing.T) {
	cases := []struct {
		count  int
		bucket string
	}{{1, "1"}, {5, "2-10"}, {50, "11-100"}, {500, "101-1000"}, {2000, ">1000"}}
	for _, tc := range cases {
		var a accumulator
		for i := 0; i < tc.count; i++ {
			a.hllAdd(strconv.Itoa(i))
		}
		if got := a.bucket(); got != tc.bucket {
			t.Fatalf("%d distinct: %s want %s", tc.count, got, tc.bucket)
		}
	}
}
func TestAllNullAndDeadline(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "empty.csv"), []byte("a,b\n,\n"), 0600)
	c := config.Config{Sources: []config.Source{{Name: "a", Path: root}}}
	k, _ := ids.Derive(make([]byte, 32))
	records, e := inventory.Scan(c, k)
	if e != nil {
		t.Fatal(e)
	}
	d, e := File(records[0], config.Columns{})
	if e != nil {
		t.Fatal(e)
	}
	for _, col := range d.Columns {
		if col.Type != "string" {
			t.Fatal(col)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := FileContext(ctx, records[0], config.Columns{}); e == nil || e.Error() != "gateway_timeout" {
		t.Fatal(e)
	}
}

func TestNullRateBoundaries(t *testing.T) {
	cases := []struct {
		n, r int64
		want *int
	}{{249, 10000, ptr(0)}, {250, 10000, ptr(5)}, {9749, 10000, ptr(95)}, {9750, 10000, ptr(100)}, {0, 0, nil}}
	for _, c := range cases {
		got := NullRate(c.n, c.r)
		if (got == nil) != (c.want == nil) || got != nil && *got != *c.want {
			t.Fatalf("%d/%d: %v", c.n, c.r, got)
		}
	}
}
func ptr(n int) *int { return &n }
func TestTextProfiles(t *testing.T) {
	root := t.TempDir()
	for name, body := range map[string]string{"a.csv": "keep,secret\n1,marker\n2,marker\n", "b.tsv": "keep\tsecret\n3\tmarker\n", "c.jsonl": "{\"keep\":1,\"secret\":\"marker\"}\n{\"keep\":null}\n"} {
		os.WriteFile(filepath.Join(root, name), []byte(body), 0600)
	}
	c := config.Config{Sources: []config.Source{{Name: "a", Path: root}}}
	k, _ := ids.Derive(make([]byte, 32))
	records, e := inventory.Scan(c, k)
	if e != nil {
		t.Fatal(e)
	}
	for _, r := range records {
		d, e := File(r, config.Columns{Rename: map[string]string{"keep": "public"}, Drop: []string{"secret"}})
		if e != nil {
			t.Fatal(e)
		}
		if len(d.Columns) != 1 || d.Columns[0].Name != "public" {
			t.Fatalf("%s: %+v", r.Path, d)
		}
		if d.RowCount == 0 {
			t.Fatal("no rows")
		}
	}
}
func TestParquetFixtures(t *testing.T) {
	root := "testdata"
	c := config.Config{Sources: []config.Source{{Name: "pq", Path: root}}}
	k, _ := ids.Derive(make([]byte, 32))
	records, e := inventory.Scan(c, k)
	if e != nil {
		t.Fatal(e)
	}
	if len(records) != 5 {
		t.Fatal(len(records))
	}
	for _, r := range records {
		d, e := File(r, config.Columns{})
		if e != nil {
			t.Fatalf("%s: %v", r.Path, e)
		}
		if d.RowCount != 4 || len(d.Columns) != 6 {
			t.Fatalf("%s: %+v", r.Path, d)
		}
		for _, col := range d.Columns {
			if col.NullRatePct == nil || *col.NullRatePct != 25 {
				t.Fatalf("%s %s null=%v", r.Path, col.Name, col.NullRatePct)
			}
			want := map[string]string{"i": "integer", "f": "float", "s": "string", "b": "boolean", "d": "date", "ts": "timestamp"}[col.Name]
			if col.Type != want {
				t.Fatalf("%s %s type=%s want=%s", r.Path, col.Name, col.Type, want)
			}
		}
	}
}
func TestProfileRejectsSymlinkSwap(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "safe.csv")
	if e := os.WriteFile(p, []byte("a,b\n1,2\n"), 0600); e != nil {
		t.Fatal(e)
	}
	c := config.Config{Sources: []config.Source{{Name: "a", Path: root}}}
	k, _ := ids.Derive(make([]byte, 32))
	records, e := inventory.Scan(c, k)
	if e != nil {
		t.Fatal(e)
	}
	outside := filepath.Join(t.TempDir(), "private.csv")
	os.WriteFile(outside, []byte("secret,value\nmarker,1\n"), 0600)
	if e := os.Remove(p); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(outside, p); e != nil {
		t.Fatal(e)
	}
	if _, e := File(records[0], config.Columns{}); e == nil {
		t.Fatal("followed symlink outside source")
	}
}
