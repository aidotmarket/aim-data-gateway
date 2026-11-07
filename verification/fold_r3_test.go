package verification

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

func TestZipReordered17000MemberReservationFallsBack(t *testing.T) {
	b := reversedZip(t, 4, 16<<20)
	s := censusFor(b, "zip")
	p := censusPolicy()
	p.MaxMemoryBytes = 128 << 20
	p.censusMemory = &censusMemory{limit: p.MaxMemoryBytes}
	const reserved = 17000*1024 + 16*(4<<20)
	p.censusMemory.used.Store(reserved)
	var peak int64
	s.read = func(_ context.Context, _ rangeCall, data []byte) (io.ReadCloser, error) {
		used := p.censusMemory.used.Load()
		peak = max(peak, used)
		if used > p.MaxMemoryBytes {
			t.Fatal("over budget before GET", used)
		}
		return io.NopCloser(bytes.NewReader(data)), nil
	}
	r := readZip(context.Background(), s, s.members[0], p, &RunStats{})
	if r.err != nil || r.state != "partly_read" || r.reason != "read_error" || r.commitment.Tag != "zip_entries" || r.entries != 4 || r.readable != 64<<20 || r.unreadable != 0 || p.censusMemory.failed.Load() {
		t.Fatal(r, p.censusMemory.failed.Load())
	}
	if peak <= reserved || p.censusMemory.used.Load() > reserved+4*256 {
		t.Fatal("buffer not exercised or leaked", peak, p.censusMemory.used.Load())
	}
	// Pin the entry commitment independently of whether full hashing was tried.
	p.MaxMemoryBytes = 1
	p.censusMemory = nil
	s.read = nil
	want := readZip(context.Background(), s, s.members[0], p, &RunStats{})
	if r.commitment != want.commitment {
		t.Fatal("fallback lost entry commitment", r.commitment, want.commitment)
	}
}

func sfxZip(t *testing.T, stub int) []byte {
	t.Helper()
	var dst bytes.Buffer
	dst.Write(bytes.Repeat([]byte{'s'}, stub))
	w := zip.NewWriter(&dst)
	w.SetOffset(int64(stub))
	for _, name := range []string{"a.txt", "b.txt"} {
		f, err := w.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		f.Write([]byte("generated words"))
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return dst.Bytes()
}

func TestZipPrefixFailureStillCommitsEntries(t *testing.T) {
	b := sfxZip(t, 100)
	s := censusFor(b, "zip")
	s.read = func(_ context.Context, c rangeCall, data []byte) (io.ReadCloser, error) {
		if c.off == 0 && c.n == 100 {
			return nil, errors.New("prefix transport failure")
		}
		return io.NopCloser(bytes.NewReader(data)), nil
	}
	stats := &RunStats{}
	r := readZip(context.Background(), s, s.members[0], censusPolicy(), stats)
	if r.err != nil || r.state != "partly_read" || r.reason != "read_error" || r.entries != 2 || r.readable != 30 || r.commitment.Tag != "zip_entries" || stats.GETs.Load() != 4 {
		t.Fatal(r, stats.GETs.Load())
	}
	// Both complete local header+payload extents must be in the commitment.
	h := sha256.New()
	_, cd := zipDirectory(b)
	for _, at := range cd {
		off := int64(binary.LittleEndian.Uint32(b[at+42:]))
		length := int64(30 + len("a.txt") + 15)
		writeU64(h, off)
		writeU64(h, length)
		h.Write(b[off : off+length])
	}
	if r.commitment.Digest != [32]byte(h.Sum(nil)) {
		t.Fatal("entries missing from fallback commitment")
	}
}

func TestZipFullNonEntryAllowance(t *testing.T) {
	for _, gap := range []bool{false, true} {
		t.Run(map[bool]string{false: "stub", true: "gap"}[gap], func(t *testing.T) {
			p := censusPolicy()
			stub := int(p.ArchiveAllowanceBytes) + 1
			b := sfxZip(t, stub)
			if gap {
				// Move the stub to a gap before entry two, preserving valid offsets.
				_, cd := zipDirectory(b)
				second := int(binary.LittleEndian.Uint32(b[cd[1]+42:]))
				copy(b, b[stub:second])
				clear(b[second-stub : second])
				binary.LittleEndian.PutUint32(b[cd[0]+42:], 0)
			}
			s := censusFor(b, "zip")
			stats := &RunStats{}
			r := readZip(context.Background(), s, s.members[0], p, stats)
			if r.err != nil || r.state != "partly_read" || r.entries != 2 || r.readable != 30 || r.commitment.Tag != "zip_entries" || stats.GETs.Load() != 3 {
				t.Fatal(r, stats.GETs.Load())
			}
			// Only the fixed tail and two bounded entry requests, never a stub
			// GET or a gap-sized request. Tail overlap with the stub is unavoidable.
			if stats.RequestedBytes.Load() > archiveTransportSlack+2*(30+2*65535+15) || stats.StoredBytes.Load() != archiveTransportSlack+2*(30+5+15) {
				t.Fatal("non-entry bytes fetched for full hashing", stats.RequestedBytes.Load(), stats.StoredBytes.Load())
			}
		})
	}
}

type slotWaitContext struct {
	context.Context
	once    sync.Once
	waiting chan struct{}
}

func (c *slotWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func TestTarSpoolSlotBeforeOpen(t *testing.T) {
	s := censusFor(fixtureTar(t, 1, 1024, 0, []byte("generated words")), "tar.gz")
	p := censusPolicy()
	p.censusMemory = &censusMemory{spools: make(chan struct{}, 1)}
	p.censusMemory.spools <- struct{}{}
	base, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx := &slotWaitContext{Context: base, waiting: make(chan struct{})}
	opened := make(chan struct{}, 1)
	s.read = func(_ context.Context, _ rangeCall, data []byte) (io.ReadCloser, error) {
		opened <- struct{}{}
		return io.NopCloser(bytes.NewReader(data)), nil
	}
	done := make(chan censusMemberResult, 1)
	go func() { done <- readTarGzip(ctx, s, s.members[0], p, &RunStats{}) }()
	<-ctx.waiting
	select {
	case <-opened:
		t.Error("provider stream opened before spool slot was free")
	default:
	}
	<-p.censusMemory.spools
	r := <-done
	if r.err != nil || r.state != "fully_read" || len(p.censusMemory.spools) != 0 {
		t.Fatal(r, len(p.censusMemory.spools))
	}
}

type slotCheckingReader struct {
	io.Reader
	read  bool
	slots chan struct{}
	t     *testing.T
}

func (r *slotCheckingReader) Read(b []byte) (int, error) {
	if r.read && len(r.slots) != 0 {
		r.t.Error("plain candidate still holds spool slot while finishing")
	}
	r.read = true
	return r.Reader.Read(b)
}

func TestTarPlainCandidateReleasesSpoolSlot(t *testing.T) {
	s := censusFor(bytes.Repeat([]byte("plain words\n"), 4096), "tar.gz")
	p := censusPolicy()
	p.censusMemory = &censusMemory{spools: make(chan struct{}, 1)}
	s.read = func(_ context.Context, _ rangeCall, data []byte) (io.ReadCloser, error) {
		return io.NopCloser(&slotCheckingReader{Reader: bytes.NewReader(data), slots: p.censusMemory.spools, t: t}), nil
	}
	r := readTarGzip(context.Background(), s, s.members[0], p, &RunStats{})
	if r.err != nil || !r.plain || r.state != "fully_read" || len(p.censusMemory.spools) != 0 {
		t.Fatal(r, len(p.censusMemory.spools))
	}
}

func TestZipTailIgnoringRangeIsReadError(t *testing.T) {
	s := censusFor(fixtureZip(t, 1, 2<<20, zip.Store, []byte("words"), false), "zip")
	// Return an extra byte even though the requested tail ends at EOF.
	s.read = func(_ context.Context, _ rangeCall, data []byte) (io.ReadCloser, error) {
		return io.NopCloser(io.MultiReader(bytes.NewReader(data), bytes.NewReader([]byte{0}))), nil
	}
	stats := &RunStats{}
	r := readZip(context.Background(), s, s.members[0], censusPolicy(), stats)
	if r.err != nil || r.reason != "read_error" || r.opened || stats.StoredBytes.Load() != archiveTransportSlack+1 {
		t.Fatal(r, stats.StoredBytes.Load())
	}
}
