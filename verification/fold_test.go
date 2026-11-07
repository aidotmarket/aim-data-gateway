package verification

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"reflect"
	"sync/atomic"
	"syscall"
	"testing"
)

func zipDirectory(b []byte) (int, []int) {
	e := len(b) - 22
	start := int(binary.LittleEndian.Uint32(b[e+16:]))
	var entries []int
	for at := start; at < e; {
		entries = append(entries, at)
		at += 46 + int(binary.LittleEndian.Uint16(b[at+28:])) + int(binary.LittleEndian.Uint16(b[at+30:])) + int(binary.LittleEndian.Uint16(b[at+32:]))
	}
	return start, entries
}

func TestZipDeclaredSelectionSurvivesEntryFailure(t *testing.T) {
	original := fixtureZip(t, 2, 40<<20, zip.Deflate, randomBlock(4096), false)
	_, cd := zipDirectory(original)
	for _, kind := range []string{"encrypted", "corrupt", "unsupported"} {
		t.Run(kind, func(t *testing.T) {
			b := bytes.Clone(original)
			if kind == "encrypted" {
				binary.LittleEndian.PutUint16(b[cd[0]+8:], 1)
			} else if kind == "unsupported" {
				binary.LittleEndian.PutUint16(b[cd[0]+10:], 99)
			} else {
				b = corruptZipData(b, 0)
			}
			s := censusFor(b, "zip")
			stats := &RunStats{}
			r := readZip(context.Background(), s, s.members[0], censusPolicy(), stats)
			if stats.PlannedBytes.Load() != 40<<20 || r.entries != 0 || r.readable != 0 || r.unreadable == 0 || r.reasons["budget_exhausted"] != 1 || r.commitment != (MemberCommitment{"zip_entries", sha256.Sum256(nil)}) {
				t.Fatal(kind, r, stats.PlannedBytes.Load())
			}
			second := int64(binary.LittleEndian.Uint32(b[cd[1]+42:]))
			for _, c := range s.calls[1:] {
				if c.off >= second {
					t.Fatal("unplanned entry fetched", c)
				}
			}
		})
	}
}

func TestZipBadOffsetBeyondEntryCapKeepsPrefix(t *testing.T) {
	b := fixtureZip(t, 12000, 1024, zip.Store, []byte("generated words "), false)
	_, cd := zipDirectory(b)
	binary.LittleEndian.PutUint32(b[cd[10000]+42:], ^uint32(0))
	s := censusFor(b, "zip")
	stats := &RunStats{}
	r := readZip(context.Background(), s, s.members[0], censusPolicy(), stats)
	if r.entries != 10000 || r.readable != 10000*1024 || r.unreadable != 2000*1024 || stats.GETs.Load() != 10001 || r.reason != "archive_over_cap" {
		t.Fatal(r, stats.GETs.Load())
	}
	for _, c := range s.calls[1:] {
		if c.off == int64(^uint32(0)) {
			t.Fatal("unselected bad header fetched")
		}
	}
}

func TestZipTransportFormulaAndReorderedDirectory(t *testing.T) {
	for _, reorder := range []bool{false, true} {
		b := fixtureZip(t, 1000, 1024, zip.Store, []byte("generated words "), false)
		cdOff, cd := zipDirectory(b)
		if reorder {
			copyOfCD := bytes.Clone(b[cdOff : len(b)-22])
			for i, at := range cd {
				copy(b[at:at+len(copyOfCD)/1000], copyOfCD[(999-i)*len(copyOfCD)/1000:(1000-i)*len(copyOfCD)/1000])
			}
		}
		s := censusFor(b, "zip")
		stats := &RunStats{}
		p := censusPolicy()
		p.MaxMemoryBytes = 128 << 20
		p.censusMemory = &censusMemory{limit: p.MaxMemoryBytes}
		r := readZip(context.Background(), s, s.members[0], p, stats)
		if r.err != nil || r.state != "fully_read" || r.commitment != (MemberCommitment{"full", sha256.Sum256(b)}) || stats.GETs.Load() != 1001 || stats.StoredBytes.Load() != min(int64(len(b)), archiveTransportSlack)+int64(cdOff) || stats.RequestedBytes.Load() != stats.StoredBytes.Load() || p.censusMemory.used.Load() > 256*1000 {
			t.Fatal(reorder, r, stats.GETs.Load(), stats.StoredBytes.Load(), p.censusMemory.used.Load())
		}
		// Exactly one tail and one local-header-to-next-start request per entry.
		for i, c := range s.calls[1:] {
			at := cd[i]
			off := int64(binary.LittleEndian.Uint32(b[at+42:]))
			if c.off != off || c.n != int64(cdOff)/1000 {
				t.Fatal(c, off)
			}
		}
	}
}

func TestZipBadSelectedHeaderIsPerEntry(t *testing.T) {
	for _, kind := range []string{"signature", "offset", "local_crc", "local_size", "descriptor_flag", "method"} {
		t.Run(kind, func(t *testing.T) {
			b := fixtureZip(t, 3, 1024, zip.Store, []byte("generated "), false)
			_, cd := zipDirectory(b)
			switch kind {
			case "signature":
				b[0] = 'Q'
			case "offset":
				binary.LittleEndian.PutUint32(b[cd[0]+42:], ^uint32(0))
			case "local_crc":
				binary.LittleEndian.PutUint32(b[14:], 123)
			case "local_size":
				binary.LittleEndian.PutUint32(b[22:], 123)
			case "descriptor_flag":
				binary.LittleEndian.PutUint16(b[6:], 0)
			case "method":
				binary.LittleEndian.PutUint16(b[8:], zip.Deflate)
			}
			r := archiveRun(t, b, "zip", censusPolicy(), 17)
			if kind == "descriptor_flag" || kind == "method" {
				if r.state != "fully_read" {
					t.Fatal(r)
				}
				return
			}
			if r.entries != 2 || r.readable != 2048 || r.unreadable != 1024 || r.reasons["archive_corrupt"] != 1 {
				t.Fatal(kind, r)
			}
		})
	}
}

func TestZipRollbackCommitmentAndPrefixFormula(t *testing.T) {
	b := fixtureZip(t, 3, 1024, zip.Store, []byte("generated words "), false)
	b = corruptZipData(b, 1)
	_, cd := zipDirectory(b)
	h := sha256.New()
	for _, i := range []int{0, 2} {
		off := int64(binary.LittleEndian.Uint32(b[cd[i]+42:]))
		n := int64(30+binary.LittleEndian.Uint16(b[off+26:])+binary.LittleEndian.Uint16(b[off+28:])) + 1024
		writeU64(h, off)
		writeU64(h, n)
		h.Write(b[off : off+n])
	}
	r := archiveRun(t, b, "zip", censusPolicy(), 17)
	if r.commitment != (MemberCommitment{"zip_entries", [32]byte(h.Sum(nil))}) || r.entries != 2 {
		t.Fatal(r)
	}
	var dst bytes.Buffer
	dst.WriteString("self extracting prefix\n")
	w := zip.NewWriter(&dst)
	w.SetOffset(int64(dst.Len()))
	f, e := w.Create("a.txt")
	if e != nil {
		t.Fatal(e)
	}
	f.Write([]byte("generated words"))
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	s := censusFor(dst.Bytes(), "zip")
	stats := &RunStats{}
	r = readZip(context.Background(), s, s.members[0], censusPolicy(), stats)
	cdOff, _ := zipDirectory(dst.Bytes())
	if r.state != "fully_read" || r.commitment.Digest != sha256.Sum256(dst.Bytes()) || stats.GETs.Load() != 3 || stats.StoredBytes.Load() != int64(dst.Len()+cdOff) || stats.RequestedBytes.Load() != stats.StoredBytes.Load() {
		t.Fatal(r, stats.GETs.Load(), stats.StoredBytes.Load())
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.read = func(_ context.Context, c rangeCall, b []byte) (io.ReadCloser, error) {
		if c.off == 0 && c.n == int64(len("self extracting prefix\n")) {
			cancel()
			return nil, ctx.Err()
		}
		return io.NopCloser(bytes.NewReader(b)), nil
	}
	r = readZip(ctx, s, s.members[0], censusPolicy(), &RunStats{})
	if r.reason != "budget_exhausted" || r.readable != 0 || r.unreadable != 0 {
		t.Fatal(r)
	}
}

type faultSpoolFile struct {
	b                   []byte
	failWrite, failRead bool
	cancel              context.CancelFunc
}

func (f *faultSpoolFile) Write(b []byte) (int, error) {
	if f.failWrite {
		return 0, syscall.ENOSPC
	}
	f.b = append(f.b, b...)
	if f.cancel != nil && len(f.b) >= 5120 {
		f.cancel()
	}
	return len(b), nil
}
func (f *faultSpoolFile) ReadAt(b []byte, off int64) (int, error) {
	if f.failRead {
		return 0, syscall.EIO
	}
	return bytes.NewReader(f.b).ReadAt(b, off)
}
func (f *faultSpoolFile) Close() error { return nil }

func TestTarLocalStorageFailuresRefuse(t *testing.T) {
	b := fixtureTar(t, 2, 4096, gzip.NoCompression, []byte("generated words "))
	for _, kind := range []string{"create", "write", "flush", "read"} {
		t.Run(kind, func(t *testing.T) {
			p := censusPolicy()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p.censusSpool = func() (*decodedSpool, error) {
				if kind == "create" {
					return nil, syscall.ENOSPC
				}
				f := &faultSpoolFile{failWrite: kind == "write" || kind == "flush", failRead: kind == "read"}
				size := 256 << 10
				if kind == "write" || kind == "read" {
					size = 16
				}
				if kind == "read" {
					f.cancel = cancel
				}
				return &decodedSpool{f: f, w: bufio.NewWriterSize(f, size)}, nil
			}
			s := censusFor(b, "tar.gz")
			f, e := Scan(ctx, s, p)
			if !errors.Is(e, ErrScannerFailure) || !reflect.DeepEqual(f, Facts{}) {
				t.Fatal(kind, f, e)
			}
			// The internal sentinel survives until Scan's existing public error
			// sanitisation. No failing local resource gets seller credit.
			ctx2, cancel2 := context.WithCancel(context.Background())
			defer cancel2()
			cancel = cancel2
			r := readTarGzip(ctx2, s, s.members[0], p, &RunStats{})
			if !errors.Is(r.err, errLocalStorage) || r.unreadable != 0 || r.readable != 0 {
				t.Fatal(kind, r)
			}
		})
	}
}

func TestTarConcurrentSpoolBudget(t *testing.T) {
	b := fixtureTar(t, 2, 4096, gzip.NoCompression, []byte("generated words "))
	s := censusFor(b, "tar.gz")
	for i := 1; i < 16; i++ {
		addCensus(s, b, "tar.gz")
	}
	p := censusPolicy()
	p.RunStats = &RunStats{}
	var active, peak atomic.Int64
	p.censusSpool = func() (*decodedSpool, error) {
		n := active.Add(1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		spool, e := newSpool()
		active.Add(-1)
		return spool, e
	}
	if _, e := Scan(context.Background(), s, p); e != nil {
		t.Fatal(e)
	}
	if peak.Load() > 2 || p.RunStats.SpoolPeakBytes.Load() > 128<<20 || p.RunStats.SpoolPeakBytes.Load() < 64<<20 || p.RunStats.SpoolBytes.Load() != 0 {
		t.Fatal(peak.Load(), p.RunStats.SpoolPeakBytes.Load(), p.RunStats.SpoolBytes.Load())
	}
}

func TestUnopenedTarMetadataCommitment(t *testing.T) {
	for _, kind := range []string{"error", "cancel"} {
		var previous [32]byte
		var previousBinding string
		for _, metadata := range []struct{ etag, version string }{{"e1", "v1"}, {"e2", "v1"}, {"e2", "v2"}} {
			s := censusFor([]byte("unopened"), "tar.gz")
			s.members[0].ETag = metadata.etag
			s.members[0].VersionID = metadata.version
			ctx, cancel := context.WithCancel(context.Background())
			s.read = func(context.Context, rangeCall, []byte) (io.ReadCloser, error) {
				if kind == "cancel" {
					cancel()
					return nil, ctx.Err()
				}
				return nil, io.ErrClosedPipe
			}
			r := readTarGzip(ctx, s, s.members[0], censusPolicy(), &RunStats{})
			cancel()
			if r.opened || r.state != "unread" || r.commitment != unreadCommitment(s.members[0]) {
				t.Fatal(r)
			}
			binding, e := ContentBindingV2(s.members, map[string]MemberCommitment{s.members[0].Identity: r.commitment})
			if e != nil || previous == r.commitment.Digest || previousBinding == binding {
				t.Fatal("metadata not bound", e)
			}
			previous = r.commitment.Digest
			previousBinding = binding
		}
	}
}

func TestArchiveRuleGzipAndTgz(t *testing.T) {
	var dst bytes.Buffer
	gz := gzip.NewWriter(&dst)
	gz.Write([]byte("a,b\n1,2\n3,4\n"))
	gz.Close()
	for _, format := range []string{"gz", "tgz", "tar.gz"} {
		s := censusFor(dst.Bytes(), format)
		p := censusPolicy()
		r := readCensusMember(context.Background(), s, s.members[0], p, &RunStats{})
		if r.state != "fully_read" || r.commitment != (MemberCommitment{"full", sha256.Sum256(dst.Bytes())}) || r.readable != int64(dst.Len()) || r.processed != int64(dst.Len()) || r.unreadable != 0 {
			t.Fatal(format, r)
		}
		if detectContent(dst.Bytes(), "x."+format).Archive != "" {
			t.Fatal("non-tar gzip classified archive")
		}
		p.PlannedProcessedBytes = int64(dst.Len())
		if got := PlannedReadSet(p.Seed, s.members, p); format == "gz" && len(got) != 1 || format != "gz" && len(got) != 0 {
			t.Fatal(format, got)
		}
	}
	tar := fixtureTar(t, 1, 100, gzip.DefaultCompression, []byte("generated "))
	if detectContent(tar, "x.tgz").Archive != "tar.gz" {
		t.Fatal("tar content not confirmed")
	}
	r := archiveRun(t, tar, "tgz", censusPolicy(), 17)
	if r.state != "fully_read" || r.entries != 1 || r.plain {
		t.Fatal(r)
	}
	for _, format := range []string{"zip", "tgz", "tar.gz"} {
		r := archiveRun(t, []byte("plain text"), format, censusPolicy(), 17)
		if !r.plain || r.state != "fully_read" || r.commitment != (MemberCommitment{"full", sha256.Sum256([]byte("plain text"))}) {
			t.Fatal(format, r)
		}
	}
	// A .gz is always a plain member; archive names are conservative candidates.
	if r := archiveRun(t, tar, "gz", censusPolicy(), 17); r.entries != 0 || r.processed != int64(len(tar)) || r.state != "fully_read" {
		t.Fatal(r)
	}
}

func TestTarAllowanceCommitmentExactPrefix(t *testing.T) {
	b := fixtureTar(t, 65, 1<<20, gzip.NoCompression, randomBlock(4096))
	gz, e := gzip.NewReader(bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	prefix, e := io.ReadAll(io.LimitReader(gz, 64<<20))
	gz.Close()
	if e != nil {
		t.Fatal(e)
	}
	r := archiveRun(t, b, "tar.gz", censusPolicy(), 4093)
	if r.reason != "budget_exhausted" || r.commitment != decodedCommitment(prefix) {
		t.Fatal(r)
	}
}

func TestTarIgnoringRangeStopsAtTransportLimit(t *testing.T) {
	b := fixtureTar(t, 65, 1<<20, gzip.NoCompression, randomBlock(4096))
	b[3] |= 8
	withName := append(append(append([]byte(nil), b[:10]...), bytes.Repeat([]byte{'n'}, 2<<20)...), 0)
	withName = append(withName, b[10:]...)
	s := censusFor(withName, "tar.gz")
	s.ignoreRange = true
	stats := &RunStats{}
	p := censusPolicy()
	r := readTarGzip(context.Background(), s, s.members[0], p, stats)
	if r.reason != "read_error" || r.unreadable != int64(len(withName)) || stats.StoredBytes.Load() != p.ArchiveAllowanceBytes+archiveTransportSlack || stats.GETs.Load() != 1 {
		t.Fatal(r, stats.StoredBytes.Load())
	}
}

func TestLimitedCoverageTenPercentBoundary(t *testing.T) {
	for _, readable := range []int64{99, 100} {
		r := newCensusRaw(nil)
		r.readable = readable
		r.unreadable = 1000 - readable
		if got := r.finish().CoverageContent.LimitedCoverage; got != (readable == 99) {
			t.Fatal(readable, got)
		}
	}
}

func TestEmptyVersionAndNearDuplicateState(t *testing.T) {
	_, e := Scan(context.Background(), censusFor(nil, "txt").empty(), censusPolicy())
	if !errors.Is(e, ErrEmptyVersion) || RefusalReason(e) != "empty_version" {
		t.Fatal(e)
	}
	r := newCensusRaw(nil)
	r.inspected.files = 10
	r.inspected.nearFiles = 9
	d := r.finish().Inspected.Duplicates
	if d.NearRatePPM != nil || d.NearState != suppressed {
		t.Fatal(d)
	}
}

func (s *censusSource) empty() *censusSource { s.members = nil; return s }
