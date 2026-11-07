package verification

import (
	"context"
	"github.com/aidotmarket/aim-data-gateway/internal/inventory"
	"testing"
)

func TestSharedContentDetection(t *testing.T) {
	for _, v := range []struct{ body, name, class string }{{"", "x", "empty"}, {"a,b\n1,2\n", "x.txt", "table_like_csv"}, {"a\tb\n", "x.txt", "table_like_tsv"}, {"{\"a\":1}\n{\"a\":2}\n", "x.txt", "table_like_jsonl"}, {"{\"a\":1}", "x", "json_document"}, {"package example\n", "x.go", "source_code"}, {"# Heading", "x.md", "markdown"}, {"words only", "x", "plain_text"}, {"<html>", "x", "html_xml"}, {"%PDF-1.7", "x", "pdf"}, {"\x89PNG\r\n\x1a\n", "x", "image"}, {"\x00\xff", "x", "other_binary"}} {
		got := detectContent([]byte(v.body), v.name)
		if got.Class != v.class {
			t.Fatalf("%s: %+v", v.class, got)
		}
		if shared := inventory.DetectContent([]byte(v.body), v.name); got != shared {
			t.Fatal("different classifiers")
		}
	}
}
func TestSnapshotFormatSelectsTablePath(t *testing.T) {
	s := censusFor([]byte("a,b\n1,2\n"), "txt")
	f, e := ScanForTest(s)
	if e != nil || len(f.Objects) != 0 || f.Coverage.InCensus != 1 {
		t.Fatal(f, e)
	}
}
func ScanForTest(s Source) (Facts, error) { return Scan(context.Background(), s, censusPolicy()) }
