package verification

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

func fixtureZip(t *testing.T, n, size int, method uint16, block []byte, longNames bool) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("%05d.txt", i)
		if longNames {
			name += strings.Repeat("n", 100)
		}
		h := &zip.FileHeader{Name: name, Method: method}
		f, e := w.CreateHeader(h)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = io.CopyN(f, &repeatReader{block, 0}, int64(size)); e != nil {
			t.Fatal(e)
		}
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}

type repeatReader struct {
	block []byte
	off   int
}

func (r *repeatReader) Read(b []byte) (int, error) {
	filled := copy(b, r.block[r.off:])
	filled += copy(b[filled:], r.block[:r.off])
	for filled < len(b) {
		filled += copy(b[filled:], b[:filled])
	}
	r.off = (r.off + len(b)) % len(r.block)
	return len(b), nil
}
func fixtureTar(t *testing.T, n, size, level int, block []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	gz, e := gzip.NewWriterLevel(&b, level)
	if e != nil {
		t.Fatal(e)
	}
	tw := tar.NewWriter(gz)
	for i := 0; i < n; i++ {
		h := &tar.Header{Name: fmt.Sprintf("entry-%05d.txt", i), Mode: 0600, Size: int64(size)}
		if e = tw.WriteHeader(h); e != nil {
			t.Fatal(e)
		}
		if _, e = io.CopyN(tw, &repeatReader{block, 0}, int64(size)); e != nil {
			t.Fatal(e)
		}
	}
	if e = tw.Close(); e != nil {
		t.Fatal(e)
	}
	if e = gz.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}
func randomBlock(n int) []byte {
	r := rand.New(rand.NewSource(1888))
	b := make([]byte, n)
	r.Read(b)
	return b
}

// Boundary fixtures need transport entropy, not millions of incidental words
// and simhash shingles. Keep a broad byte alphabet but exclude ASCII letters
// and digits; detector correctness has separate planted-text fixtures.
func archiveNoise(n int) []byte {
	var alphabet []byte
	for i := 0; i < 256; i++ {
		if i >= 'a' && i <= 'z' || i >= 'A' && i <= 'Z' || i >= '0' && i <= '9' {
			continue
		}
		alphabet = append(alphabet, byte(i))
	}
	b := randomBlock(n)
	for i, v := range b {
		b[i] = alphabet[int(v)%len(alphabet)]
	}
	return b
}

func archiveRun(t *testing.T, b []byte, format string, p Policy, chunk int) censusMemberResult {
	t.Helper()
	s := censusFor(b, format)
	s.chunk = chunk
	r := readCensusMember(context.Background(), s, s.members[0], p, &RunStats{})
	return r
}
func assertArchiveDeterminism(t *testing.T, b []byte, format string, p Policy, check func(censusMemberResult)) {
	t.Helper()
	var want censusMemberResult
	for i, n := range []int{4096, 65536, 1 << 20, 4093} {
		r := archiveRun(t, b, format, p, n)
		check(r)
		if i > 0 && (r.commitment != want.commitment || r.readable != want.readable || r.unreadable != want.unreadable || r.processed != want.processed || r.entries != want.entries || r.reason != want.reason || r.state != want.state || !reflect.DeepEqual(r.findings, want.findings)) {
			t.Fatalf("buffer-dependent outcome %d: %+v vs %+v", n, r, want)
		}
		want = r
	}
}
func TestArchiveFullSmallAndNested(t *testing.T) {
	for _, format := range []string{"zip", "tar.gz"} {
		t.Run(format, func(t *testing.T) {
			var b []byte
			if format == "zip" {
				b = fixtureZip(t, 2, 1024, zip.Deflate, []byte("generated words "), false)
			} else {
				b = fixtureTar(t, 2, 1024, gzip.DefaultCompression, []byte("generated words "))
			}
			assertArchiveDeterminism(t, b, format, censusPolicy(), func(r censusMemberResult) {
				if r.state != "fully_read" || r.commitment.Tag != "full" || r.commitment.Digest != sha256.Sum256(b) || r.entries != 2 || r.unreadable != 0 {
					t.Fatalf("%+v", r)
				}
			})
		})
	}
	inner := fixtureZip(t, 1, 16, zip.Store, []byte("generated"), false)
	outer := fixtureZip(t, 1, len(inner), zip.Store, inner, false)
	r := archiveRun(t, outer, "zip", censusPolicy(), 1)
	if r.reasons["nested_archive"] != 1 || r.findings.files != 0 {
		t.Fatal(r)
	}
}
func TestZipOversizedEntryAndCaps(t *testing.T) {
	t.Run("96MiB_entry", func(t *testing.T) {
		b := fixtureZip(t, 1, 96<<20, zip.Deflate, randomBlock(4096), false)
		assertArchiveDeterminism(t, b, "zip", censusPolicy(), func(r censusMemberResult) {
			if r.processed != 0 || r.reason != "budget_exhausted" || r.commitment.Tag != "zip_entries" || r.readable != 0 || r.unreadable != 0 {
				t.Fatal(r)
			}
		})
	})
	t.Run("ratio_cap_unopened", func(t *testing.T) {
		b := fixtureZip(t, 1, 8<<20, zip.Deflate, []byte{'a'}, false)
		r := archiveRun(t, b, "zip", censusPolicy(), 4096)
		if r.opened || r.reason != "archive_over_cap" || r.commitment.Tag != "unread" || r.unreadable != int64(len(b)) {
			t.Fatal(r)
		}
	})
	t.Run("central_directory_over_1MiB", func(t *testing.T) {
		b := fixtureZip(t, 8000, 1, zip.Store, []byte{'a'}, true)
		s := censusFor(b, "zip")
		r := readZip(context.Background(), s, s.members[0], censusPolicy(), &RunStats{})
		if r.opened || r.reason != "archive_over_cap" || r.unreadable != int64(len(b)) || r.commitment.Tag != "unread" || len(s.calls) != 1 {
			t.Fatal(r, len(s.calls))
		}
	})
	t.Run("12000_entries_84percent_floor", func(t *testing.T) {
		b := fixtureZip(t, 12000, 64, zip.Store, []byte("generated words "), false)
		r := archiveRun(t, b, "zip", censusPolicy(), 65536)
		if r.entries != 10000 || r.readable != 10000*64 || r.unreadable != 2000*64 || r.reason != "archive_over_cap" {
			t.Fatal(r)
		}
		raw := newCensusRaw(nil)
		raw.members = 2
		raw.add(Member{Format: "zip"}, r)
		raw.add(Member{Format: "txt"}, censusMemberResult{state: "fully_read", readable: 64 << 10})
		if raw.finish().CoverageContent.LimitedCoverage {
			t.Fatal("84.6% marked limited")
		}
	})
	t.Run("over_256MiB", func(t *testing.T) {
		b := fixtureZip(t, 257, 1<<20, zip.Deflate, archiveNoise(32768), false)
		r := archiveRun(t, b, "zip", censusPolicy(), 65536)
		if r.processed != 64<<20 || r.unreadable != 0 || r.entries != 64 || r.reason != "budget_exhausted" {
			t.Fatal(r)
		}
	})
}
func TestArchiveAllowanceProcessedBytes(t *testing.T) {
	p := censusPolicy()
	t.Run("1to1_zip_65MiB", func(t *testing.T) {
		b := fixtureZip(t, 65, 1<<20, zip.Store, []byte{0}, false)
		assertArchiveDeterminism(t, b, "zip", p, func(r censusMemberResult) {
			if r.processed != 64<<20 || r.entries != 64 || r.reason != "budget_exhausted" || r.unreadable != 0 {
				t.Fatal(r)
			}
		})
	})
	// Deterministically varying the random block fraction produces the requested
	// realistic 3:1,4:1,5:1 streams without block-repeating compressor artifacts.
	for _, ratio := range []int{1, 3, 4, 5, 65} {
		t.Run(fmt.Sprintf("tar_ratio_%d", ratio), func(t *testing.T) {
			block := archiveNoise(64 << 10)
			if ratio > 1 {
				copy(block[len(block)/ratio:], bytes.Repeat([]byte{0}, len(block)-len(block)/ratio))
			}
			b := fixtureTar(t, 65, 1<<20, gzip.DefaultCompression, block)
			assertArchiveDeterminism(t, b, "tar.gz", p, func(r censusMemberResult) {
				if r.processed != 64<<20 || r.reason != "budget_exhausted" || r.commitment.Tag != "decoded_prefix" || r.unreadable != 0 {
					t.Fatal(r)
				}
				if r.entries >= 64 {
					t.Fatal("straddling entry counted", r.entries)
				}
			})
		})
	}
	t.Run("64MiB_stored_is_full", func(t *testing.T) {
		b := fixtureTar(t, 1, (64<<20)-16<<10, gzip.NoCompression, []byte{0})
		if len(b) >= 64<<20 {
			t.Fatal(len(b))
		}
		r := archiveRun(t, b, "tar.gz", p, 4096)
		if r.state != "fully_read" {
			t.Fatal(r)
		}
	})
}
func corruptZipData(b []byte, index int) []byte {
	b = append([]byte(nil), b...)
	pos := 0
	for i := 0; i <= index; i++ {
		at := bytes.Index(b[pos:], []byte("PK\x03\x04"))
		if at < 0 {
			panic("header")
		}
		pos += at
		data := pos + 30 + int(binary.LittleEndian.Uint16(b[pos+26:])) + int(binary.LittleEndian.Uint16(b[pos+28:]))
		if i == index {
			b[data] ^= 1
			return b
		}
		pos = data + 1
	}
	return b
}
func TestZipValidThenCorruptAndExtentValidation(t *testing.T) {
	original := fixtureZip(t, 2, 1024, zip.Store, []byte("generated "), false)
	t.Run("valid_then_corrupt", func(t *testing.T) {
		b := corruptZipData(original, 1)
		assertArchiveDeterminism(t, b, "zip", censusPolicy(), func(r censusMemberResult) {
			if r.readable != 1024 || r.unreadable != 1024 || r.entries != 1 || r.commitment.Tag != "zip_entries" {
				t.Fatal(r)
			}
		})
	})
	for _, kind := range []string{"inflated_size_trailing_junk", "overlap_corrupt", "overlap_encrypted"} {
		t.Run(kind, func(t *testing.T) {
			b := append([]byte(nil), original...)
			cd := bytes.Index(b, []byte("PK\x01\x02"))
			next := cd + 46 + int(binary.LittleEndian.Uint16(b[cd+28:]))
			switch kind {
			case "inflated_size_trailing_junk":
				b = corruptZipData(b, 1)
				binary.LittleEndian.PutUint32(b[cd+20:], 1028)
			case "overlap_corrupt", "overlap_encrypted":
				binary.LittleEndian.PutUint32(b[cd+20:], 1100)
				if kind == "overlap_encrypted" {
					binary.LittleEndian.PutUint16(b[next+8:], 1)
				}
			}
			r := archiveRun(t, b, "zip", censusPolicy(), 17)
			if r.readable != 0 || r.unreadable == 0 {
				t.Fatal("invalid extent credited", r)
			}
		})
	}
	t.Run("mostly_encrypted", func(t *testing.T) {
		b := append([]byte(nil), original...)
		cd := bytes.Index(b, []byte("PK\x01\x02"))
		binary.LittleEndian.PutUint16(b[cd+8:], 1)
		binary.LittleEndian.PutUint16(b[6:], 1)
		r := archiveRun(t, b, "zip", censusPolicy(), 4096)
		if r.readable != 1024 || r.unreadable != 1024 || r.reasons["archive_encrypted"] != 1 {
			t.Fatal(r)
		}
	})
}
func TestTarLateCorruptionFloorAndStoredBlock(t *testing.T) {
	for _, level := range []int{gzip.NoCompression, gzip.DefaultCompression} {
		t.Run(fmt.Sprint(level), func(t *testing.T) {
			b := fixtureTar(t, 2, 1024, level, []byte("words "))
			b[len(b)-8] ^= 1
			assertArchiveDeterminism(t, b, "tar.gz", censusPolicy(), func(r censusMemberResult) {
				if r.readable != 0 || r.unreadable != int64(len(b)) || r.commitment.Tag != "decoded_prefix" {
					t.Fatal(r)
				}
			})
		})
	}
	// A tiny completed entry followed by a malformed tar header and padding in
	// the same stored DEFLATE block must earn no floor credit at any buffer size.
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	tw.WriteHeader(&tar.Header{Name: "tiny", Mode: 0600, Size: 1})
	tw.Write([]byte{'x'})
	tw.Close()
	data := append([]byte(nil), raw.Bytes()[:1024]...)
	data = append(data, bytes.Repeat([]byte{0xff}, 8192)...)
	var b bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&b, gzip.NoCompression)
	gz.Write(data)
	gz.Close()
	assertArchiveDeterminism(t, b.Bytes(), "tar.gz", censusPolicy(), func(r censusMemberResult) {
		if r.readable != 0 || r.unreadable != int64(b.Len()) || r.entries != 1 {
			t.Fatal(r)
		}
	})
}

type failingReader struct {
	r    io.Reader
	left int64
}

func (f *failingReader) Read(b []byte) (int, error) {
	if f.left <= 0 {
		return 0, io.ErrClosedPipe
	}
	n, e := f.r.Read(b[:min(int64(len(b)), f.left)])
	f.left -= int64(n)
	return n, e
}
func TestArchiveCancellationAndTransportErrors(t *testing.T) {
	for _, format := range []string{"zip", "tar.gz"} {
		for _, stop := range []string{"cancel", "transport"} {
			t.Run(format+"_"+stop, func(t *testing.T) {
				var b []byte
				if format == "zip" {
					b = fixtureZip(t, 2, 4096, zip.Store, []byte("content "), false)
				} else {
					b = fixtureTar(t, 2, 4096, gzip.NoCompression, []byte("content "))
				}
				s := censusFor(b, format)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				s.read = func(ctx context.Context, c rangeCall, b []byte) (io.ReadCloser, error) {
					if format == "zip" && c.n <= archiveTransportSlack && c.off == 0 && c.n == int64(len(b)) {
						return io.NopCloser(bytes.NewReader(b)), nil
					}
					if format == "zip" && c.n == 30 {
						return io.NopCloser(bytes.NewReader(b)), nil
					}
					if stop == "cancel" {
						cancel()
						return io.NopCloser(bytes.NewReader(b)), nil
					}
					return io.NopCloser(&failingReader{bytes.NewReader(b), 700}), nil
				}
				// Zip's directory request may contain the whole small object. Only payload
				// reads are faulted; tar.gz has just one request, which is faulted directly.
				r := readCensusMember(ctx, s, s.members[0], censusPolicy(), &RunStats{})
				if stop == "cancel" {
					if r.reason != "budget_exhausted" || r.unreadable != 0 {
						t.Fatal(r)
					}
				} else {
					if format == "tar.gz" && r.unreadable != int64(len(b)) || format == "zip" && r.unreadable == 0 {
						t.Fatal(r)
					}
				}
			})
		}
	}
}
func TestErrorAndAllowanceMixedFloor(t *testing.T) {
	for _, success := range []string{"1MiB_plain", "10MiB_allowance_tar"} {
		raw := newCensusRaw(nil)
		raw.members = 10
		raw.add(Member{Format: "tar.gz"}, censusMemberResult{state: "partly_read", unreadable: 90 << 20, reason: "read_error"})
		if success == "1MiB_plain" {
			raw.add(Member{Format: "txt"}, censusMemberResult{state: "fully_read", readable: 1 << 20})
		} else {
			raw.add(Member{Format: "tar.gz"}, censusMemberResult{state: "partly_read", reason: "budget_exhausted"})
		}
		if !raw.finish().CoverageContent.LimitedCoverage {
			t.Fatal(success)
		}
	}
}
func TestTarOneRangeIgnoringProviderRange(t *testing.T) {
	b := fixtureTar(t, 1, 4096, gzip.NoCompression, []byte("content "))
	s := censusFor(b, "tar.gz")
	s.ignoreRange = true
	p := censusPolicy()
	stats := &RunStats{}
	r := readTarGzip(context.Background(), s, s.members[0], p, stats)
	if r.state != "fully_read" || len(s.calls) != 1 || s.calls[0].off != 0 || s.calls[0].n != p.ArchiveAllowanceBytes+1<<20 || stats.GETs.Load() != 1 {
		t.Fatal(r, s.calls)
	}
}

// This complete dynamic tree gives literals 7..262 fifteen-bit codes: seven
// shorter codes consume 127/128 of the tree, the 256 long codes the remainder.
// It is valid DEFLATE whose literal encoding expands stored transport bytes.
type bitSink struct {
	b    []byte
	bits uint64
	n    uint
}

func (w *bitSink) put(v uint64, n uint) {
	w.bits |= v << w.n
	w.n += n
	for w.n >= 8 {
		w.b = append(w.b, byte(w.bits))
		w.bits >>= 8
		w.n -= 8
	}
}
func reverseBits(v, n uint64) uint64 {
	var out uint64
	for range n {
		out = out<<1 | v&1
		v >>= 1
	}
	return out
}
func fifteenBitGzip(t *testing.T, decoded []byte) []byte {
	t.Helper()
	w := &bitSink{}
	w.put(1, 1)
	w.put(2, 2)
	w.put(6, 5)
	w.put(0, 5)
	w.put(15, 4)
	order := []int{16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15}
	for _, v := range order {
		length := uint64(4)
		if v >= 16 {
			length = 0
		}
		w.put(length, 3)
	}
	lengths := make([]int, 263)
	for i := 0; i < 7; i++ {
		lengths[i] = i + 1
	}
	for i := 7; i < 263; i++ {
		lengths[i] = 15
	}
	for _, n := range append(lengths, 1) {
		w.put(reverseBits(uint64(n), 4), 4)
	}
	codes := make([]uint64, 263)
	var counts, next [16]int
	for _, n := range lengths {
		counts[n]++
	}
	code := 0
	for n := 1; n <= 15; n++ {
		code = (code + counts[n-1]) << 1
		next[n] = code
	}
	for i, n := range lengths {
		codes[i] = reverseBits(uint64(next[n]), uint64(n))
		next[n]++
	}
	for _, b := range decoded {
		w.put(codes[int(b)], uint(lengths[int(b)]))
	}
	w.put(codes[256], 15)
	if w.n > 0 {
		w.b = append(w.b, byte(w.bits))
	}
	out := append([]byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255}, w.b...)
	var trailer [8]byte
	binary.LittleEndian.PutUint32(trailer[:], crc32.ChecksumIEEE(decoded))
	binary.LittleEndian.PutUint32(trailer[4:], uint32(len(decoded)))
	return append(out, trailer[:]...)
}
func TestTarAdversarialTransportPolicy(t *testing.T) {
	p := censusPolicy()
	t.Run("2MiB_FNAME", func(t *testing.T) {
		b := fixtureTar(t, 65, 1<<20, gzip.NoCompression, []byte{0})
		b[3] |= 8
		withName := append(append(append([]byte(nil), b[:10]...), bytes.Repeat([]byte{'n'}, 2<<20)...), 0)
		withName = append(withName, b[10:]...)
		assertArchiveDeterminism(t, withName, "tar.gz", p, func(r censusMemberResult) {
			if r.reason != "read_error" || r.unreadable != int64(len(withName)) || r.commitment.Tag != "decoded_prefix" || r.processed >= p.ArchiveAllowanceBytes {
				t.Fatal(r)
			}
		})
	})
	t.Run("15_bit_literals", func(t *testing.T) {
		var raw bytes.Buffer
		tw := tar.NewWriter(&raw)
		tw.WriteHeader(&tar.Header{Name: "large.txt", Mode: 0600, Size: 40 << 20})
		io.CopyN(tw, &repeatReader{[]byte(" "), 0}, 40<<20)
		tw.Close()
		b := fifteenBitGzip(t, raw.Bytes())
		// Validate the adversarial compressor independently of the scanner first.
		gz, e := gzip.NewReader(bytes.NewReader(b))
		if e != nil {
			t.Fatal(e)
		}
		n, e := io.Copy(io.Discard, gz)
		gz.Close()
		if e != nil || n != int64(raw.Len()) {
			t.Fatal("invalid fixture", n, e)
		}
		assertArchiveDeterminism(t, b, "tar.gz", p, func(r censusMemberResult) {
			if r.reason != "read_error" || r.unreadable != int64(len(b)) || r.commitment.Tag != "decoded_prefix" {
				t.Fatal(r)
			}
		})
	})
}
func TestTarCapsAndCompletedEntryBoundary(t *testing.T) {
	for _, tc := range []struct {
		name           string
		n, size, level int
		block          []byte
	}{{"entry_count", 10001, 0, gzip.DefaultCompression, []byte("x")}, {"ratio", 3, 5 << 20, gzip.BestCompression, []byte("a")}} {
		t.Run(tc.name, func(t *testing.T) {
			b := fixtureTar(t, tc.n, tc.size, tc.level, tc.block)
			r := archiveRun(t, b, "tar.gz", censusPolicy(), 4096)
			if r.reason != "archive_over_cap" || r.unreadable != 0 || r.readable != 0 || r.commitment.Tag != "decoded_prefix" {
				t.Fatal(r)
			}
			if tc.name == "entry_count" && r.entries != 10000 {
				t.Fatal(r.entries)
			}
		})
	}
}
func TestTarFourToOne64MiBStored(t *testing.T) {
	block := archiveNoise(65536)
	for i := len(block) / 4; i < len(block); i++ {
		block[i] = 0
	}
	b := fixtureTar(t, 256, 1<<20, gzip.DefaultCompression, block)
	if len(b) < 60<<20 || len(b) > 70<<20 {
		t.Fatal("not near 64MiB stored", len(b))
	}
	r := archiveRun(t, b, "tar.gz", censusPolicy(), 65536)
	if r.reason != "budget_exhausted" || r.processed != 64<<20 || r.unreadable != 0 {
		t.Fatal(r)
	}
}

func TestTarNinetyMiBTransportFailuresPlusPlainLimited(t *testing.T) {
	b := fixtureTar(t, 2, 4096, gzip.NoCompression, []byte("content "))
	s := censusFor(b, "tar.gz")
	s.members[0].Size = 10 << 20
	for i := 1; i < 9; i++ {
		addCensus(s, b, "tar.gz")
		s.members[i].Size = 10 << 20
	}
	addCensus(s, bytes.Repeat([]byte("p"), 1<<20), "txt")
	s.read = func(ctx context.Context, c rangeCall, b []byte) (io.ReadCloser, error) {
		if c.id == s.members[9].Identity {
			return io.NopCloser(bytes.NewReader(b)), nil
		}
		return io.NopCloser(&failingReader{bytes.NewReader(b), 1536}), nil
	}
	f, e := Scan(context.Background(), s, censusPolicy())
	if e != nil || !f.ContentCensus.CoverageContent.LimitedCoverage || f.Coverage.InCensus != 10 {
		t.Fatal(f.ContentCensus, e)
	}
}

// Small fixtures cover the same stop rows across all read segmentations; the
// separate 64 MiB fixtures enforce the signed production allowance and caps.
func TestArchiveStopCommitmentDeterminism(t *testing.T) {
	for _, format := range []string{"zip", "tar.gz"} {
		for _, stop := range []string{"allowance", "entry_cap", "ratio_cap", "transport", "cancel", "preflight_cancel"} {
			t.Run(format+"/"+stop, func(t *testing.T) {
				var b []byte
				if format == "zip" {
					method := uint16(zip.Store)
					if stop == "ratio_cap" {
						method = zip.Deflate
					}
					b = fixtureZip(t, 3, 2048, method, []byte("generated words "), false)
				} else {
					b = fixtureTar(t, 3, 2048, gzip.NoCompression, []byte("generated words "))
				}
				var want censusMemberResult
				for i, chunk := range []int{4096, 65536, 1 << 20, 17} {
					s := censusFor(b, format)
					s.chunk = chunk
					p := censusPolicy()
					ctx, cancel := context.WithCancel(context.Background())
					if stop == "allowance" {
						p.ArchiveAllowanceBytes = 3072
					}
					if stop == "entry_cap" {
						p.ArchiveCaps.Entries = 1
					}
					if stop == "ratio_cap" {
						p.ArchiveCaps.CompressionRatio = 1
						if format == "tar.gz" {
							s.members[0].Size /= 2
						}
					}
					if stop == "preflight_cancel" {
						cancel()
					}
					if stop == "transport" || stop == "cancel" {
						s.read = func(ctx context.Context, c rangeCall, body []byte) (io.ReadCloser, error) {
							r := &shortReader{bytes.NewReader(body), chunk}
							if format == "zip" && (c.n == 30 || c.n == int64(len(b))) {
								return io.NopCloser(r), nil
							}
							if stop == "cancel" {
								cancel()
								return io.NopCloser(r), nil
							}
							return io.NopCloser(&failingReader{r, 1024}), nil
						}
					}
					r := readCensusMember(ctx, s, s.members[0], p, &RunStats{})
					cancel()
					if i > 0 && (r.commitment != want.commitment || r.reason != want.reason || r.readable != want.readable || r.unreadable != want.unreadable || r.entries != want.entries) {
						t.Fatalf("chunk %d: %+v vs %+v", chunk, r, want)
					}
					if stop == "preflight_cancel" && (r.reason != "budget_exhausted" || r.unreadable != 0) {
						t.Fatal(r)
					}
					wantReason := "budget_exhausted"
					if stop == "ratio_cap" || stop == "entry_cap" {
						wantReason = "archive_over_cap"
					}
					if stop == "transport" {
						wantReason = "read_error"
					}
					if r.reason != wantReason {
						t.Fatalf("stop %s: %+v", stop, r)
					}
					want = r
				}
			})
		}
	}
}

func TestGzipOptionalHeadersAndMultistream(t *testing.T) {
	b := fixtureTar(t, 2, 2048, gzip.NoCompression, []byte("generated words "))
	gz, e := gzip.NewReader(bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	raw, e := io.ReadAll(gz)
	gz.Close()
	if e != nil {
		t.Fatal(e)
	}
	var combined []byte
	for _, part := range [][]byte{raw[:777], raw[777:]} {
		var dst bytes.Buffer
		w := gzip.NewWriter(&dst)
		w.Name = strings.Repeat("n", 3000)
		w.Comment = strings.Repeat("c", 3000)
		w.Extra = []byte{1, 2, 3}
		w.Write(part)
		if e = w.Close(); e != nil {
			t.Fatal(e)
		}
		member := dst.Bytes()
		member[3] |= 2 // Add a valid FHCRC over the entire original header.
		headerEnd := 10 + 2 + len(w.Extra) + len(w.Name) + 1 + len(w.Comment) + 1
		var crc [2]byte
		binary.LittleEndian.PutUint16(crc[:], uint16(crc32.ChecksumIEEE(member[:headerEnd])))
		combined = append(combined, member[:headerEnd]...)
		combined = append(combined, crc[:]...)
		combined = append(combined, member[headerEnd:]...)
	}
	assertArchiveDeterminism(t, combined, "tar.gz", censusPolicy(), func(r censusMemberResult) {
		if r.state != "fully_read" || r.entries != 2 || r.commitment != (MemberCommitment{"full", sha256.Sum256(combined)}) {
			t.Fatal(r)
		}
	})
	combined[20] ^= 1 // Header corruption must still invalidate the member.
	r := archiveRun(t, combined, "tar.gz", censusPolicy(), 17)
	if r.unreadable != int64(len(combined)) || r.reason != "archive_corrupt" {
		t.Fatal(r)
	}
}

// Filename table admission is gateway-only: archive census facts retain the
// content-derived plain_text class even for entries named x.csv or x.tsv.
func TestArchivePlainTextTableNamesKeepCensusClass(t *testing.T) {
	for _, format := range []string{"zip", "tar.gz"} {
		for _, name := range []string{"x.csv", "x.tsv"} {
			t.Run(format+"/"+name, func(t *testing.T) {
				var b bytes.Buffer
				body := []byte("value\nv0\n")
				if format == "zip" {
					w := zip.NewWriter(&b)
					entry, err := w.Create(name)
					if err != nil {
						t.Fatal(err)
					}
					if _, err = entry.Write(body); err != nil {
						t.Fatal(err)
					}
					if err = w.Close(); err != nil {
						t.Fatal(err)
					}
				} else {
					gz := gzip.NewWriter(&b)
					w := tar.NewWriter(gz)
					if err := w.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(body))}); err != nil {
						t.Fatal(err)
					}
					if _, err := w.Write(body); err != nil {
						t.Fatal(err)
					}
					if err := w.Close(); err != nil {
						t.Fatal(err)
					}
					if err := gz.Close(); err != nil {
						t.Fatal(err)
					}
				}
				r := archiveRun(t, b.Bytes(), format, censusPolicy(), 3)
				if r.state != "fully_read" || r.entries != 1 || r.findings.files != 0 || len(r.findings.classes) != 0 {
					t.Fatalf("archive census = %+v", r)
				}
			})
		}
	}
}
