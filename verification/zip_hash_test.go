package verification

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
	"unsafe"
)

func reversedZip(t *testing.T, entries, size int) []byte {
	t.Helper()
	b := fixtureZip(t, entries, size, zip.Store, []byte("generated words\n"), false)
	cdOff, cd := zipDirectory(b)
	original := bytes.Clone(b[cdOff : len(b)-22])
	at := cdOff
	for i := len(cd) - 1; i >= 0; i-- {
		end := len(b) - 22
		if i+1 < len(cd) {
			end = cd[i+1]
		}
		at += copy(b[at:], original[cd[i]-cdOff:end-cdOff])
	}
	return b
}

// Inspect actual retained slice capacities and node sizes after every mutation,
// including every single-byte Write. This is deliberately test-only accounting.
func checkZipHashAccounting(t *testing.T, h *zipFullHash) {
	var retained int64
	currentFound := h.current == nil
	for v := h.pending; v != nil; v = v.next {
		retained += int64(cap(v.data)) + int64(unsafe.Sizeof(*v))
		currentFound = currentFound || v == h.current
	}
	if !currentFound || h.held < retained || h.held > h.limit || h.memory.used.Load() != h.held {
		t.Fatalf("charge=%d retained=%d limit=%d shared=%d", h.held, retained, h.limit, h.memory.used.Load())
	}
}

func TestZipFullHashFragmentationAccounting(t *testing.T) {
	b := reversedZip(t, 2, 8<<20)
	cdOff, cd := zipDirectory(b)
	for _, chunk := range []int{1, 65536} {
		h := &zipFullHash{h: sha256.New(), limit: 128 << 20, memory: &censusMemory{limit: 128 << 20}}
		for _, at := range cd {
			off := int64(binary.LittleEndian.Uint32(b[at+42:]))
			bound := int64(cdOff)
			for _, other := range cd {
				next := int64(binary.LittleEndian.Uint32(b[other+42:]))
				if next > off {
					bound = min(bound, next)
				}
			}
			if err := h.start(off, bound-off); err != nil {
				t.Fatal(err)
			}
			checkZipHashAccounting(t, h)
			for pos := off; pos < bound; {
				end := min(bound, pos+int64(chunk))
				if _, err := h.Write(b[pos:end]); err != nil {
					t.Fatal(err)
				}
				checkZipHashAccounting(t, h)
				pos = end
			}
		}
		h.h.Write(b[cdOff:])
		if h.next != int64(cdOff) || [32]byte(h.h.Sum(nil)) != sha256.Sum256(b) || h.held != 0 {
			t.Fatal("fragmented full digest or release changed", chunk, h.held)
		}
		h.release()
		checkZipHashAccounting(t, h)
	}
}

func TestZipFullHashReservesBeforeAllocation(t *testing.T) {
	const charge = (32 << 10) + zipHashBookkeeping
	for _, shared := range []bool{false, true} {
		limit := int64(2 * charge)
		memoryLimit := limit
		if shared {
			memoryLimit--
		} else {
			limit--
		}
		h := &zipFullHash{h: sha256.New(), limit: limit, memory: &censusMemory{limit: memoryLimit}}
		if err := h.start(100, 1); err != nil {
			t.Fatal(err)
		}
		if _, err := h.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
		checkZipHashAccounting(t, h)
		before := h.pending
		if err := h.start(200, 1); !errors.Is(err, ErrResourceLimit) {
			t.Fatal("expected refusal before allocating second block", err)
		}
		checkZipHashAccounting(t, h)
		if h.pending != before || h.pending.next != nil || h.held != charge {
			t.Fatal("refused reservation retained another allocation")
		}
		h.release()
		checkZipHashAccounting(t, h)
	}
}

func TestZipReorderedShortReadsAndMemoryFallback(t *testing.T) {
	b := reversedZip(t, 2, 8<<20)
	want := MemberCommitment{"full", sha256.Sum256(b)}
	for _, chunk := range []int{1, 65536} {
		for _, limit := range []int64{128 << 20, 8 << 20} {
			s := censusFor(b, "zip")
			s.chunk = chunk
			p := censusPolicy()
			p.MaxMemoryBytes = limit
			p.censusMemory = &censusMemory{limit: limit}
			stats := &RunStats{}
			r := readZip(context.Background(), s, s.members[0], p, stats)
			if limit == 128<<20 {
				if r.err != nil || r.state != "fully_read" || r.commitment != want || stats.GETs.Load() != 3 {
					t.Fatal("fragmentation changed digest or transport", chunk, r, stats.GETs.Load())
				}
			} else if r.err != nil || r.commitment.Tag != "zip_entries" || r.state != "partly_read" || r.reason != "read_error" || r.entries != 2 || r.readable != 16<<20 || stats.GETs.Load() != 3 || p.censusMemory.failed.Load() {
				t.Fatal("expected entry credit after optional buffer exhaustion", chunk, r, stats.GETs.Load())
			}
			if p.censusMemory.used.Load() > 256*2 {
				t.Fatal("extent reservation leaked", p.censusMemory.used.Load())
			}
		}
	}
}

func TestZipReorderedScanPublishesEntryFallback(t *testing.T) {
	// Individually tiny extents still spend their entire allocated capacity.
	s := censusFor(reversedZip(t, 4100, 1), "zip")
	f, err := Scan(context.Background(), s, censusPolicy())
	if err != nil || f.ContentCensus == nil || f.ContentSHA256 == "" {
		t.Fatal("optional full hash exhaustion refused the scan", err, f)
	}
}
