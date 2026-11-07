package verification

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/aidotmarket/aim-data-gateway/internal/inventory"
	"hash"
	"hash/crc32"
	"io"
	"os"
)

// Errors credit what failed as unreadable; not_examined arises only from
// deadline, cancellation and allowance stops, the tar.gz cap stop, and zip
// entries untouched when an error or timing stop ends the walk.
func archiveResult(m Member) censusMemberResult {
	r := unreadResult(m, "archive_corrupt")
	r.reasons = map[string]int64{}
	return r
}
func rangeRead(ctx context.Context, s CensusSource, m Member, off, n int64, stats *RunStats) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if off < 0 || n < 0 || off > m.Size || n > m.Size-off {
		return nil, io.ErrUnexpectedEOF
	}
	stats.GETs.Add(1)
	stats.RequestedBytes.Add(n)
	r, e := s.OpenRange(ctx, m.Identity, off, n)
	if e != nil {
		return nil, e
	}
	defer r.Close()
	stop := context.AfterFunc(ctx, func() { r.Close() })
	defer stop()
	b, e := io.ReadAll(io.LimitReader(&statsReader{r, stats}, n))
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if e == nil && int64(len(b)) != n {
		e = io.ErrUnexpectedEOF
	}
	return b, e
}

type tailAt struct {
	tail  []byte
	start int64
}

func (t tailAt) ReadAt(b []byte, off int64) (int, error) {
	if off < t.start {
		return 0, io.ErrUnexpectedEOF
	}
	n := copy(b, t.tail[min(int64(len(t.tail)), off-t.start):])
	if n < len(b) {
		return n, io.EOF
	}
	return n, nil
}

// decodedSpool holds at most one archive allowance on local temporary storage;
// it is mode 0600, unlinked immediately, and closed on every exit path.
type decodedSpool struct {
	name string
	f    interface {
		io.Writer
		io.ReaderAt
		io.Closer
	}
	n int64
	w *bufio.Writer
}

var errLocalStorage = errors.New("census local storage failure")

func storageError(e error) error {
	if e == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", errLocalStorage, e)
}

func newSpool() (*decodedSpool, error) {
	f, e := os.CreateTemp("", "aim-census-*")
	if e != nil {
		return nil, storageError(e)
	}
	name := f.Name()
	if os.Remove(name) == nil {
		name = ""
	}
	return &decodedSpool{f: f, name: name, w: bufio.NewWriterSize(f, 256<<10)}, nil
}
func (s *decodedSpool) Write(b []byte) (int, error) {
	n, e := s.w.Write(b)
	s.n += int64(n)
	return n, storageError(e)
}
func (s *decodedSpool) copyPrefix(w io.Writer, n int64) error {
	if e := s.w.Flush(); e != nil {
		return storageError(e)
	}
	got, e := io.Copy(w, io.NewSectionReader(s.f, 0, n))
	if e == nil && got != n {
		e = io.ErrUnexpectedEOF
	}
	return storageError(e)
}
func (s *decodedSpool) close() {
	s.f.Close()
	if s.name != "" {
		os.Remove(s.name)
	}
}
func (s *decodedSpool) commit(n int64) (MemberCommitment, error) {
	h := sha256.New()
	writeU64(h, n)
	h.Write([]byte("decoded_prefix"))
	e := s.copyPrefix(h, n)
	return MemberCommitment{"decoded_prefix", [32]byte(h.Sum(nil))}, e
}

type optionalInspection struct{ scan *fileInspection }

func (w *optionalInspection) Write(b []byte) (int, error) {
	if w.scan == nil {
		return len(b), nil
	}
	return w.scan.Write(b)
}

func readTarGzip(ctx context.Context, s CensusSource, m Member, p Policy, stats *RunStats) censusMemberResult {
	r := archiveResult(m)
	r.findings.memory = p.censusMemory
	stats.GETs.Add(1)
	stats.RequestedBytes.Add(p.ArchiveAllowanceBytes + archiveTransportSlack)
	stream, err := s.OpenRange(ctx, m.Identity, 0, p.ArchiveAllowanceBytes+archiveTransportSlack)
	if err != nil {
		r.reason = "read_error"
		if ctx.Err() != nil {
			r.reason = "budget_exhausted"
		} else {
			r.unreadable = m.Size
		}
		return r
	}
	r.opened = true
	r.state = "partly_read"
	r.commitment = decodedCommitment(nil)
	stop := context.AfterFunc(ctx, func() { stream.Close() })
	defer stop()
	defer stream.Close()
	storedHash := sha256.New()
	plainScan := newFileInspection("." + m.Format)
	plainSink := &optionalInspection{plainScan}
	stored := &countingReader{r: io.TeeReader(io.LimitReader(&statsReader{stream, stats}, p.ArchiveAllowanceBytes+archiveTransportSlack), io.MultiWriter(storedHash, plainSink))}
	failureReason := func(e error) string {
		if ctx.Err() != nil {
			return "budget_exhausted"
		}
		if stored.err != nil && !errors.Is(stored.err, io.EOF) || errors.Is(e, io.ErrUnexpectedEOF) && stored.n < m.Size {
			return "read_error"
		}
		return "archive_corrupt"
	}
	gz, err := newArchiveGzip(stored)
	if err != nil {
		if !bytes.HasPrefix(plainScan.prefix, []byte{0x1f, 0x8b}) && (stored.n == m.Size || errors.Is(err, gzip.ErrHeader)) {
			return finishPlainCandidate(ctx, m, p, r, stored, storedHash, plainScan)
		}
		r.reason = failureReason(err)
		if r.reason != "budget_exhausted" {
			r.unreadable = m.Size
		}
		return r
	}
	defer gz.Close()
	// A candidate name is insufficient: confirm a tar header before opening
	// interiors. A valid gzip of other data stays a stored-size plain member.
	peek := bufio.NewReaderSize(gz, 512)
	header, peekErr := peek.Peek(512)
	if peekErr == nil || errors.Is(peekErr, io.EOF) {
		if !inventory.IsTarHeader(header) {
			return finishPlainCandidate(ctx, m, p, r, stored, storedHash, plainScan)
		}
	}
	plainSink.scan = nil
	// Disk is separately bounded at two allowances (128 MiB), independent of
	// sixteen scan workers. Waiting does not change a member's byte selection.
	if p.censusMemory != nil && p.censusMemory.spools != nil {
		select {
		case p.censusMemory.spools <- struct{}{}:
			defer func() { <-p.censusMemory.spools }()
		case <-ctx.Done():
			r.reason = "budget_exhausted"
			return r
		}
	}
	reserved := stats.SpoolBytes.Add(p.ArchiveAllowanceBytes)
	for old := stats.SpoolPeakBytes.Load(); reserved > old; old = stats.SpoolPeakBytes.Load() {
		if stats.SpoolPeakBytes.CompareAndSwap(old, reserved) {
			break
		}
	}
	defer stats.SpoolBytes.Add(-p.ArchiveAllowanceBytes)
	create := p.censusSpool
	if create == nil {
		create = newSpool
	}
	spool, err := create()
	if err != nil {
		r.err = fmt.Errorf("%w: %w", ErrScannerFailure, storageError(err))
		return r
	}
	defer spool.close()
	limit := p.ArchiveAllowanceBytes
	capStop := false
	if m.Size <= mathMaxDiv(p.ArchiveCaps.CompressionRatio) && m.Size*p.ArchiveCaps.CompressionRatio < limit {
		limit = m.Size * p.ArchiveCaps.CompressionRatio
		capStop = true
	}
	decoded := io.TeeReader(io.LimitReader(peek, limit), spool)
	tr := tar.NewReader(decoded)
	var lastComplete, pendingEnd int64
	var pending *fileInspection
	completePending := func() {
		if pending == nil || spool.n < pendingEnd {
			return
		}
		lastComplete = pendingEnd
		r.entries++
		r.entryBytes += pending.size
		if detectContent(pending.prefix, pending.name).Archive != "" {
			r.reasons["nested_archive"]++
		} else {
			r.findings.addFile(pending.finish())
		}
		pending = nil
	}
	for i := 0; ; i++ {
		if ctx.Err() != nil {
			r.reason = "budget_exhausted"
			break
		}
		h, e := tr.Next()
		completePending()
		if e == io.EOF {
			// Tar EOF alone cannot earn credit: drain to and validate the gzip trailer.
			_, e = copyInspected(ctx, io.Discard, decoded)
			if e == nil && spool.n < limit {
				if stored.n == m.Size {
					if e := spool.w.Flush(); e != nil {
						r.err = fmt.Errorf("%w: %w", ErrScannerFailure, storageError(e))
						return r
					}
					r.state = "fully_read"
					r.reason = ""
					r.readable = m.Size
					r.storedRead = m.Size
					r.processed = spool.n
					r.commitment = MemberCommitment{"full", [32]byte(storedHash.Sum(nil))}
					return r
				}
				e = io.ErrUnexpectedEOF
			}
			if e == nil {
				r.reason = "budget_exhausted"
				if capStop {
					r.reason = "archive_over_cap"
				}
				break
			}
		}
		if e != nil {
			if errors.Is(e, errLocalStorage) {
				r.err = fmt.Errorf("%w: %w", ErrScannerFailure, e)
				return r
			}
			r.reason = failureReason(e)
			if spool.n >= limit {
				r.reason = "budget_exhausted"
				if capStop {
					r.reason = "archive_over_cap"
				}
			}
			break
		}
		if i >= p.ArchiveCaps.Entries {
			r.reason = "archive_over_cap"
			break
		}
		scan := newFileInspection(h.Name)
		_, e = copyInspected(ctx, scan, tr)
		if e != nil {
			if errors.Is(e, errLocalStorage) {
				r.err = fmt.Errorf("%w: %w", ErrScannerFailure, e)
				return r
			}
			r.reason = failureReason(e)
			if spool.n >= limit {
				r.reason = "budget_exhausted"
				if capStop {
					r.reason = "archive_over_cap"
				}
			}
			break
		}
		pendingEnd = (spool.n + 511) / 512 * 512
		if h.Typeflag == tar.TypeReg || h.Typeflag == tar.TypeRegA {
			pending = scan
			completePending()
		} else {
			lastComplete = pendingEnd
		}
	}
	if ctx.Err() != nil {
		r.reason = "budget_exhausted"
	}
	r.processed = spool.n
	r.storedRead = min(stored.n, m.Size)
	length := min(lastComplete, spool.n)
	if spool.n >= limit && r.reason == "budget_exhausted" {
		length = limit
	}
	r.commitment, err = spool.commit(length)
	if err != nil {
		r.err = fmt.Errorf("%w: %w", ErrScannerFailure, err)
		return r
	}
	if r.reason == "archive_corrupt" || r.reason == "read_error" {
		r.unreadable = m.Size
	}
	r.reasons[r.reason]++
	return r
}

// Candidate names reserve an archive allowance before content is available.
// If content proves plain, do not exceed that immutable reservation.
func finishPlainCandidate(ctx context.Context, m Member, p Policy, r censusMemberResult, stored *countingReader, h hash.Hash, scan *fileInspection) censusMemberResult {
	_, err := copyInspected(ctx, io.Discard, io.LimitReader(stored, max(0, p.ArchiveAllowanceBytes-stored.n)))
	r.plain = true
	r.state = "unread"
	r.commitment = unreadCommitment(m)
	r.processed = min(stored.n, p.ArchiveAllowanceBytes)
	if ctx.Err() != nil || stored.n < m.Size && stored.n >= p.ArchiveAllowanceBytes {
		r.reason = "budget_exhausted"
		return r
	}
	if err != nil || stored.n != m.Size {
		r.reason = "read_error"
		r.unreadable = m.Size
		return r
	}
	r.state = "fully_read"
	r.reason = ""
	r.commitment = MemberCommitment{"full", [32]byte(h.Sum(nil))}
	r.readable = m.Size
	r.storedRead = m.Size
	r.findings.addFile(scan.finish())
	return r
}

func mathMaxDiv(n int64) int64 { return int64(^uint64(0)>>1) / n }

type countingReader struct {
	r   io.Reader
	n   int64
	err error
}

func (c *countingReader) Read(b []byte) (int, error) {
	n, e := c.r.Read(b)
	c.err = e
	c.n += int64(n)
	return n, e
}

// Go's gzip.Reader limits optional name/comment fields to 512 bytes. Consume
// those fields with bounded memory, validating FHCRC, then give the decoder a
// header without metadata. The stored-byte counter/hash still sees every byte.
// This lets oversized headers reach the signed transport cap, as specified.
type archiveGzip struct {
	r  *bufio.Reader
	gz *gzip.Reader
}

func newArchiveGzip(r io.Reader) (*archiveGzip, error) {
	g := &archiveGzip{r: bufio.NewReaderSize(r, 4096)}
	return g, g.next()
}
func (g *archiveGzip) next() error {
	var header [10]byte
	if _, e := io.ReadFull(g.r, header[:]); e != nil {
		return e
	}
	if header[0] != 0x1f || header[1] != 0x8b || header[2] != 8 || header[3]&0xe0 != 0 {
		return gzip.ErrHeader
	}
	crc := crc32.NewIEEE()
	crc.Write(header[:])
	if header[3]&4 != 0 {
		var size [2]byte
		if _, e := io.ReadFull(g.r, size[:]); e != nil {
			return e
		}
		crc.Write(size[:])
		if _, e := io.CopyN(crc, g.r, int64(binary.LittleEndian.Uint16(size[:]))); e != nil {
			return e
		}
	}
	for _, flag := range []byte{8, 16} {
		if header[3]&flag == 0 {
			continue
		}
		for {
			part, e := g.r.ReadSlice(0)
			crc.Write(part)
			if e == nil {
				break
			}
			if e != bufio.ErrBufferFull {
				return e
			}
		}
	}
	if header[3]&2 != 0 {
		var want [2]byte
		if _, e := io.ReadFull(g.r, want[:]); e != nil {
			return e
		}
		if binary.LittleEndian.Uint16(want[:]) != uint16(crc.Sum32()) {
			return gzip.ErrHeader
		}
	}
	header[3] = 0
	var e error
	g.gz, e = gzip.NewReader(&gzipHeaderReader{header[:], g.r})
	if e == nil {
		g.gz.Multistream(false)
	}
	return e
}
func (g *archiveGzip) Read(b []byte) (int, error) {
	for {
		if g.gz == nil {
			if _, e := g.r.Peek(1); e != nil {
				return 0, e
			}
			if e := g.next(); e != nil {
				return 0, e
			}
		}
		n, e := g.gz.Read(b)
		if e != io.EOF {
			return n, e
		}
		g.gz.Close()
		g.gz = nil
		if n > 0 {
			return n, nil
		}
	}
}
func (g *archiveGzip) Close() error {
	if g.gz != nil {
		return g.gz.Close()
	}
	return nil
}

// Implement io.ByteReader so gzip/flate cannot read ahead into the next member.
type gzipHeaderReader struct {
	prefix []byte
	r      *bufio.Reader
}

func (r *gzipHeaderReader) Read(b []byte) (int, error) {
	if len(r.prefix) == 0 {
		return r.r.Read(b)
	}
	n := copy(b, r.prefix)
	r.prefix = r.prefix[n:]
	return n, nil
}
func (r *gzipHeaderReader) ReadByte() (byte, error) {
	if len(r.prefix) == 0 {
		return r.r.ReadByte()
	}
	b := r.prefix[0]
	r.prefix = r.prefix[1:]
	return b, nil
}
