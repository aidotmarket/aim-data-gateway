package verification

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestOccupancyReconstructionVersions(t *testing.T) {
	for _, n := range []int{1, 2, 3, 9, 10, 11, 15007} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			s := censusFor([]byte("generated private text 0"), "txt")
			for i := 1; i < n; i++ {
				addCensus(s, []byte(fmt.Sprintf("generated private text %d", i)), "txt")
			}
			f, e := Scan(context.Background(), s, censusPolicy())
			if e != nil {
				t.Fatal(e)
			}
			wire, e := canonical(f)
			if e != nil {
				t.Fatal(e)
			}
			for _, forbidden := range []string{"generated private text", "member_sha256s", "ETag", "VersionID", "zip_entries", "decoded_prefix"} {
				if bytes.Contains(wire, []byte(forbidden)) {
					t.Fatal("local data on wire", forbidden)
				}
			}
			if f.Coverage.InCensus != n || f.Coverage.Discovered != n {
				t.Fatal(f.Coverage)
			}
			if n < 10 {
				c := f.ContentCensus
				if c.Inventory.Members != countBand(int64(n)) || c.Inspected.Detectors[0].State != suppressed || c.Inspected.Duplicates.ExactRatePPM != nil {
					t.Fatal(c)
				}
			}
		})
	}
}
func TestOccupancyReconstructionComplements(t *testing.T) {
	for _, tc := range []struct {
		name                                    string
		total, fully, partly, unread, inspected int64
		classes                                 map[string]int64
	}{
		{"11_one_class_10", 11, 11, 0, 0, 11, map[string]int64{"text": 10, "source_code": 1}},
		{"10_two_inspected", 10, 2, 0, 8, 2, nil},
		{"10_one_read", 10, 1, 0, 9, 1, nil},
		{"11_ten_read", 11, 10, 0, 1, 10, nil},
		{"21_ten_full_ten_partial_one_unread", 21, 10, 10, 1, 20, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newCensusRaw(nil)
			r.members = tc.total
			r.fully = tc.fully
			r.partly = tc.partly
			r.unread = tc.unread
			r.extensions = tc.classes
			r.stored = 987654
			r.storedRead = 12345
			r.processed = 12345
			r.inspected.init()
			r.inspected.files = tc.inspected
			c := r.finish()
			if tc.classes != nil && len(c.Inventory.ByExtensionClass.Cells) != 0 {
				t.Fatal(c)
			}
			if tc.unread > 0 {
				if _, ok := c.CoverageContent.StoredBytesRead.(int64); ok {
					t.Fatal("reconstructible byte complement")
				}
			}
			if tc.inspected < 10 && c.Inspected.Detectors[0].FilesWithHitsBand != "" {
				t.Fatal(c)
			}
		})
	}
}
func TestOccupancyReconstructionDuplicatePair(t *testing.T) {
	r := newCensusRaw(nil)
	r.members = 2
	r.fully = 2
	file := inspectChunks([]byte(strings.Repeat("duplicate generated ", 20)), "x.txt", 17)
	r.inspected.addFile(file)
	r.inspected.addFile(file)
	c := r.finish()
	if c.Inspected.Duplicates.State != suppressed || c.Inspected.Duplicates.ExactRatePPM != nil || c.Inspected.Duplicates.NearRatePPM != nil {
		t.Fatal(c)
	}
}
func TestOccupancyReconstructionSingleArchiveAndOneEntryDifference(t *testing.T) {
	makeCensus := func(entries int) *ContentCensus {
		r := newCensusRaw([]Member{{Size: 2048, Format: "zip"}})
		r.fully = 1
		r.opened = 1
		r.entries = int64(entries)
		r.entryBytes = int64(entries) * 71
		for i := 0; i < entries; i++ {
			r.inspected.addFile(inspectChunks([]byte(fmt.Sprintf("private-%d", i)), "x", 5))
		}
		return r.finish()
	}
	a, b := makeCensus(10), makeCensus(11)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("single-archive entry count leaked\n%+v\n%+v", a, b)
	}
	if a.Interiors.State != suppressed || a.Interiors.EntriesRead != nil {
		t.Fatal(a)
	}
}
func TestOccupancyReconstructionCredentialAndEmailText(t *testing.T) {
	build := func(email string) *ContentCensus {
		r := newCensusRaw(nil)
		r.members = 10
		r.fully = 10
		for i := 0; i < 10; i++ {
			s := fmt.Sprintf("generated body %d", i)
			if i == 0 {
				s += " " + email + " " + fixtureAccessID()
			}
			r.inspected.addFile(inspectChunks([]byte(s), "x.txt", 7))
		}
		return r.finish()
	}
	a, b := build("alice@example.org"), build("bravo@example.org")
	if !reflect.DeepEqual(a, b) {
		t.Fatal("hit text changed aggregates")
	}
	if a.Inspected.Detectors[2].FilesWithHitsBand != "1-9" {
		t.Fatal(a.Inspected.Detectors)
	}
	raw, _ := canonical(a)
	for _, secret := range []string{"alice", "bravo", "example.org", fixtureAccessID()} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("hit text escaped")
		}
	}
}
