package inventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aidotmarket/aim-data-gateway/internal/config"
	"github.com/aidotmarket/aim-data-gateway/internal/ids"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPhase1Boundary(t *testing.T) {
	root := t.TempDir()
	marker := "PRIVATE_PATH_MARKER"
	p := filepath.Join(root, marker+".csv")
	if e := os.WriteFile(p, []byte("column_MARKER,value\nSECRET_CELL,1\n"), 0600); e != nil {
		t.Fatal(e)
	}
	outside := filepath.Join(t.TempDir(), "outside.csv")
	os.WriteFile(outside, []byte("a,b\n1,2\n"), 0600)
	if e := os.Symlink(outside, filepath.Join(root, "escape.csv")); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(filepath.Join(root, "special"), 0700); e != nil {
		t.Fatal(e)
	}
	c := config.Config{Sources: []config.Source{{Name: "a", Path: root}}}
	k, _ := ids.Derive(make([]byte, 32))
	recs, e := Scan(c, k)
	if e != nil {
		t.Fatal(e)
	}
	if len(recs) != 1 {
		t.Fatalf("records=%d", len(recs))
	}
	b, _ := json.Marshal(recs[0])
	for _, s := range []string{marker, "SECRET_CELL", "column_MARKER", root, SHAHex(recs[0])} {
		if bytes.Contains(b, []byte(s)) {
			t.Fatalf("phase 1 leaked %s", s)
		}
	}
	if !strings.HasPrefix(recs[0].Phase1.DisplayName, "file-") {
		t.Fatal(recs[0].Phase1.DisplayName)
	}
	if recs[0].Phase1.MediaType != "text/csv" {
		t.Fatal(recs[0].Phase1.MediaType)
	}
	if len(recs[0].BlockHashes) != 1 {
		t.Fatal("block list")
	}
	h := sha256.Sum256([]byte("column_MARKER,value\nSECRET_CELL,1\n"))
	if recs[0].SHA256 != h {
		t.Fatal("hash")
	}
	if e := os.WriteFile(filepath.Join(root, "second.csv"), []byte("a,b\n1,2\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := ScanLimit(c, k, 1); !errors.Is(e, ErrTooLarge) {
		t.Fatal("cap not enforced", e)
	}
}
func TestDeletionOnceAcrossBatches(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 1001; i++ {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("f%04d.csv", i)), []byte("a,b\n1,2\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	c := config.Config{Sources: []config.Source{{Name: "one", Path: root}}}
	k, _ := ids.Derive(make([]byte, 32))
	first, err := Scan(c, k)
	if err != nil {
		t.Fatal(err)
	}
	deleted := first[0].Phase1.FileID
	if err = os.Remove(filepath.Join(root, "f0000.csv")); err != nil {
		t.Fatal(err)
	}
	second, err := ScanWithPrevious(c, k, first)
	if err != nil {
		t.Fatal(err)
	}
	batches := Batches(second, 2)
	if len(batches) != 2 || len(batches[0].Files) != 1000 || len(batches[1].Files) != 1 {
		t.Fatalf("batches: %d", len(batches))
	}
	missing := 0
	for _, batch := range batches {
		for _, f := range batch.Files {
			if !f.Present {
				missing++
				if f.FileID != deleted {
					t.Fatalf("wrong deletion %s", f.FileID)
				}
			}
		}
	}
	if missing != 1 {
		t.Fatalf("deletions=%d", missing)
	}
	third, err := ScanWithPrevious(c, k, second)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range third {
		if !r.Phase1.Present {
			t.Fatal("repeated deletion")
		}
	}
}
func TestTwoSourcesAndBatches(t *testing.T) {
	roots := []string{t.TempDir(), t.TempDir()}
	for _, root := range roots {
		if e := os.WriteFile(filepath.Join(root, "same.csv"), []byte("a,b\n1,2\n"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	c := config.Config{Sources: []config.Source{{Name: "one", Path: roots[0]}, {Name: "two", Path: roots[1]}}}
	k, _ := ids.Derive(make([]byte, 32))
	r, e := Scan(c, k)
	if e != nil {
		t.Fatal(e)
	}
	if len(r) != 2 || r[0].Phase1.FileID == r[1].Phase1.FileID {
		t.Fatal("source ids collided")
	}
	b := Batches(r, 42)
	if len(b) != 1 || b[0].Generation != 42 || len(b[0].Files) != 2 {
		t.Fatal(b)
	}
	empty := Batches(nil, 43)
	if len(empty) != 1 || len(empty[0].Files) != 0 {
		t.Fatal(empty)
	}
	many := make([]Record, 1001)
	chunks := Batches(many, 44)
	if len(chunks) != 2 || len(chunks[0].Files) != 1000 || len(chunks[1].Files) != 1 {
		t.Fatal("batch limit")
	}
}
func TestRescanUsesSizeAndMtime(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "data.csv")
	os.WriteFile(p, []byte("a,b\n1,2\n"), 0600)
	c := config.Config{Sources: []config.Source{{Name: "a", Path: root}}}
	k, _ := ids.Derive(make([]byte, 32))
	first, e := Scan(c, k)
	if e != nil {
		t.Fatal(e)
	}
	second, e := ScanWithPrevious(c, k, first)
	if e != nil {
		t.Fatal(e)
	}
	if second[0].SHA256 != first[0].SHA256 || !second[0].Phase1.ChangedAt.Equal(first[0].Phase1.ChangedAt) {
		t.Fatal("unchanged file rehashed")
	}
	os.WriteFile(p, []byte("a,b\n1,2\n3,4\n"), 0600)
	third, e := ScanWithPrevious(c, k, second)
	if e != nil {
		t.Fatal(e)
	}
	if third[0].SHA256 == second[0].SHA256 || !third[0].Phase1.FirstSeenAt.Equal(first[0].Phase1.FirstSeenAt) {
		t.Fatal("changed file not detected")
	}
}
func TestBlockBoundary(t *testing.T) {
	root := t.TempDir()
	data := bytes.Repeat([]byte("x"), BlockSize+1)
	os.WriteFile(filepath.Join(root, "big.csv"), data, 0600)
	c := config.Config{Sources: []config.Source{{Name: "a", Path: root}}}
	k, _ := ids.Derive(make([]byte, 32))
	r, e := Scan(c, k)
	if e != nil {
		t.Fatal(e)
	}
	if len(r[0].BlockHashes) != 2 {
		t.Fatal(len(r[0].BlockHashes))
	}
	if r[0].BlockHashes[0] != sha256.Sum256(data[:BlockSize]) || r[0].BlockHashes[1] != sha256.Sum256(data[BlockSize:]) {
		t.Fatal("block digest")
	}
}
