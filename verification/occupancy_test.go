package verification

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOccupancyPartitionMergesAndJointBytes(t *testing.T) {
	for _, counts := range []map[string]int64{{"a": 10, "b": 1}, {"a": 10, "b": 10, "c": 1}, {"a": 9, "b": 1, "c": 20}, {"a": 1, "b": 2, "c": 3}} {
		var n int64
		for _, v := range counts {
			n += v
		}
		p := partition(counts, n, false)
		if p.State == "checked" {
			for _, c := range p.Cells {
				if c.Members.(int64) < 10 {
					t.Fatal(p)
				}
			}
		}
		if len(p.Cells) == 1 {
			t.Fatal("singleton partition", p)
		}
	}
	for _, tc := range []struct{ total, fully, partly, unread int64 }{{10, 1, 0, 9}, {11, 10, 0, 1}, {21, 10, 10, 1}} {
		r := newCensusRaw(nil)
		r.members = tc.total
		r.fully = tc.fully
		r.partly = tc.partly
		r.unread = tc.unread
		r.stored = 123456
		r.storedRead = 12345
		r.processed = 12345
		c := r.finish()
		if _, ok := c.CoverageContent.StoredBytesRead.(int64); ok {
			t.Fatal("exact bytes exposed", c)
		}
		if c.CoverageContent.ReadState.State != "suppressed_low_occupancy" {
			t.Fatal(c.CoverageContent.ReadState)
		}
	}
}
func maximalCensus() *ContentCensus {
	r := newCensusRaw(nil)
	n := int64(math.MaxInt64 / 4)
	r.members = n * 3
	r.stored = math.MaxInt64
	r.fully = n
	r.partly = n
	r.unread = n
	r.storedRead = math.MaxInt64 / 2
	r.processed = math.MaxInt64
	r.archives = n
	r.opened = n / 2
	r.partial = n / 4
	r.entries = n
	r.entryBytes = math.MaxInt64
	for _, name := range []string{"table", "json", "source_code", "markdown", "text", "html_xml", "pdf", "image", "archive_zip", "archive_tar_gz", "other"} {
		r.extensions[name] = n / 11
	}
	for _, name := range []string{"0", "<1KB", "<10KB", "<100KB", "<1MB", "<10MB", "<100MB", ">=100MB"} {
		r.sizes[name] = n / 8
	}
	for _, name := range []string{"archive_encrypted", "archive_corrupt", "archive_over_cap", "nested_archive", "not_sampled", "budget_exhausted", "read_error"} {
		r.reasons[name] = n / 7
		r.interiorReasons[name] = n / 7
	}
	a := &r.inspected
	a.init()
	a.files = n
	a.empty = n
	a.garbage = n
	for _, name := range []string{"table_like_csv", "table_like_tsv", "table_like_jsonl", "json_document", "source_code", "markdown", "plain_text", "html_xml", "pdf", "image", "other_binary", "empty"} {
		a.classes[name] = n / 12
	}
	for _, name := range []string{"utf8", "utf8_bom", "utf16", "latin1_like", "binary"} {
		a.encodings[name] = n / 5
	}
	for _, name := range []string{"latin", "cyrillic", "cjk", "arabic", "other"} {
		a.scripts[name] = n / 5
	}
	for _, l := range licencePatterns {
		a.licences[l.family] = n
	}
	for i := range a.hits {
		a.hits[i] = n
		a.hitFiles[i] = n
	}
	a.exact[[32]byte{}] = n
	a.near[0] = n
	a.nearFiles = n
	return r.finish()
}
func TestCensusWorstCaseCanonical8KiB(t *testing.T) {
	c := maximalCensus()
	b, e := canonical(c)
	if e != nil || len(b) > 8192 {
		t.Fatal(len(b), e)
	}
	var decoded ContentCensus
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if e = d.Decode(&decoded); e != nil {
		t.Fatal(e)
	}
	b2, e := canonical(decoded)
	if e != nil || string(b) != string(b2) {
		t.Fatal("round trip")
	}
	t.Logf("all enum cells, 19-digit counters: %d canonical bytes", len(b))
	if dir := os.Getenv("C1_EVIDENCE_DIR"); dir != "" {
		tables, e := Scan(context.Background(), rehearsalSource(t, 24), testPolicy())
		if e != nil {
			t.Fatal(e)
		}
		payload := map[string]any{"content_census": c, "coverage": tables.Coverage, "objects": tables.Objects, "schema_preview": preview(tables.Objects), "fingerprint_hash": strings.Repeat("a", 64)}
		raw, e := canonical(payload)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, "maximal-narration-input.json"), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
}
