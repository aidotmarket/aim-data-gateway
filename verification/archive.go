package verification

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"sort"
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
	r, e := s.OpenRange(ctx, m.Identity, off, n)
	if e != nil {
		return nil, e
	}
	defer r.Close()
	stop := context.AfterFunc(ctx, func() { r.Close() })
	defer stop()
	b, e := io.ReadAll(io.LimitReader(r, n+1))
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

type zipExtent struct {
	file           *zip.File
	off, data, end int64
	valid          bool
}

func readZip(ctx context.Context, s CensusSource, m Member, p Policy, stats *RunStats) (r censusMemberResult) {
	r = archiveResult(m)
	defer func() {
		if ctx.Err() != nil && !r.opened {
			r.reason = "budget_exhausted"
			r.unreadable = 0
		}
	}()
	r.findings.memory = p.censusMemory
	tail, e := rangeRead(ctx, s, m, max(0, m.Size-archiveTransportSlack), min(m.Size, archiveTransportSlack), stats)
	if e != nil {
		r.reason = "read_error"
		r.unreadable = m.Size
		return r
	}
	// EOCD must end exactly at the snapshot boundary, including its comment.
	end := -1
	for i := len(tail) - 22; i >= max(0, len(tail)-65557); i-- {
		if bytes.Equal(tail[i:i+4], []byte("PK\x05\x06")) && i+22+int(binary.LittleEndian.Uint16(tail[i+20:])) == len(tail) {
			end = i
			break
		}
	}
	if end < 0 {
		r.unreadable = m.Size
		return r
	}
	cdSize := int64(binary.LittleEndian.Uint32(tail[end+12:]))
	cdOff := int64(binary.LittleEndian.Uint32(tail[end+16:]))
	tailStart := m.Size - int64(len(tail))
	if cdSize > archiveTransportSlack || cdOff < tailStart {
		r.reason = "archive_over_cap"
		r.unreadable = m.Size
		return r
	} // LOW-H: unopened, whole stored size unreadable.
	if cdOff+cdSize > tailStart+int64(end) {
		r.unreadable = m.Size
		return r
	}
	zr, e := zip.NewReader(tailAt{tail, tailStart}, m.Size)
	if e != nil {
		r.unreadable = m.Size
		return r
	}
	var compressed, expanded uint64
	for _, f := range zr.File {
		if ^uint64(0)-compressed < f.CompressedSize64 || ^uint64(0)-expanded < f.UncompressedSize64 {
			r.reason = "archive_over_cap"
			r.unreadable = m.Size
			return r
		}
		compressed += f.CompressedSize64
		expanded += f.UncompressedSize64
	}
	if compressed == 0 && expanded > 0 || compressed > 0 && expanded/compressed > uint64(p.ArchiveCaps.CompressionRatio) || compressed > 0 && expanded%compressed > 0 && expanded/compressed == uint64(p.ArchiveCaps.CompressionRatio) {
		r.reason = "archive_over_cap"
		r.unreadable = m.Size
		return r
	}
	// zip.File exposes the data offset, but not its local header offset. The
	// bounded central directory gives the offsets used by zip_entries directly.
	offsets := make([]int64, 0, len(zr.File))
	cd := tail[cdOff-tailStart : cdOff-tailStart+cdSize]
	for len(cd) >= 46 && bytes.Equal(cd[:4], []byte("PK\x01\x02")) {
		offsets = append(offsets, int64(binary.LittleEndian.Uint32(cd[42:])))
		n := 46 + int(binary.LittleEndian.Uint16(cd[28:])) + int(binary.LittleEndian.Uint16(cd[30:])) + int(binary.LittleEndian.Uint16(cd[32:]))
		if n > len(cd) {
			break
		}
		cd = cd[n:]
	}
	if len(offsets) != len(zr.File) {
		r.unreadable = m.Size
		return r
	}
	xs := make([]zipExtent, len(zr.File))
	for i, f := range zr.File {
		off := offsets[i]
		header, err := rangeRead(ctx, s, m, off, 30, stats)
		if err != nil {
			r.reason = "read_error"
			r.unreadable = m.Size
			return r
		}
		data := off + 30 + int64(binary.LittleEndian.Uint16(header[26:])) + int64(binary.LittleEndian.Uint16(header[28:]))
		length := int64(f.CompressedSize64)
		valid := bytes.Equal(header[:4], []byte("PK\x03\x04")) && binary.LittleEndian.Uint16(header[8:]) == f.Method && binary.LittleEndian.Uint16(header[6:]) == f.Flags && length >= 0 && data >= off && data <= cdOff && length <= cdOff-data
		xs[i] = zipExtent{f, off, data, data + length, valid}
	}
	order := make([]int, len(xs))
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(i, j int) bool { return xs[order[i]].off < xs[order[j]].off })
	if len(order) > 0 {
		furthest := order[0]
		for _, b := range order[1:] {
			if xs[furthest].end > xs[b].off {
				xs[furthest].valid = false
				xs[b].valid = false
			}
			if xs[b].end > xs[furthest].end {
				furthest = b
			}
		}
	}

	r.opened = true
	r.state = "partly_read"
	r.reason = ""
	committed := sha256.New()
	var processed int64
	complete := true
	creditBad := func(n int64) {
		r.unreadable += min(func() int64 {
			if n < 0 {
				return m.Size
			}
			return n
		}(), m.Size-r.readable-r.unreadable)
	}
	for i, x := range xs {
		f := x.file
		if i >= p.ArchiveCaps.Entries {
			complete = false
			r.reason = "archive_over_cap"
			r.reasons[r.reason]++
			creditBad(int64(f.CompressedSize64))
			continue
		}
		if f.UncompressedSize64 > uint64(p.ArchiveAllowanceBytes-processed) {
			complete = false
			r.reason = "budget_exhausted"
			r.reasons[r.reason] += int64(len(xs) - i)
			break
		}
		if ctx.Err() != nil {
			complete = false
			r.reason = "budget_exhausted"
			r.reasons[r.reason] += int64(len(xs) - i)
			break
		}
		reason := ""
		if !x.valid {
			reason = "archive_corrupt"
		} else if f.Flags&1 != 0 {
			reason = "archive_encrypted"
		} else if f.Method != zip.Store && f.Method != zip.Deflate {
			reason = "archive_corrupt"
		}
		if reason != "" {
			complete = false
			r.reason = reason
			r.reasons[reason]++
			creditBad(int64(f.CompressedSize64))
			continue
		}
		// Stream a fixed extent; never allocate its declared compressed size.
		stats.GETs.Add(1)
		stream, err := s.OpenRange(ctx, m.Identity, x.off, x.end-x.off)
		if err != nil {
			complete = false
			r.reason = "read_error"
			r.reasons[r.reason]++
			creditBad(int64(f.CompressedSize64))
			break
		}
		stop := context.AfterFunc(ctx, func() { stream.Close() })
		// Hash into a temporary extent spool. It is appended to the aggregate hash
		// only after validation, so a corrupt entry never becomes a completed entry.
		spool, err := newSpool()
		if err != nil {
			stop()
			stream.Close()
			r.reason = "read_error"
			creditBad(int64(f.CompressedSize64))
			complete = false
			break
		}
		extent := io.TeeReader(io.LimitReader(stream, x.end-x.off), spool)
		_, err = io.CopyN(io.Discard, extent, x.data-x.off)
		br := bufio.NewReaderSize(io.LimitReader(extent, int64(f.CompressedSize64)), 4096)
		var decoder io.ReadCloser = io.NopCloser(br)
		if f.Method == zip.Deflate {
			decoder = flate.NewReader(br)
		}
		scan := newFileInspection(f.Name)
		crc := crc32.NewIEEE()
		var n int64
		if err == nil {
			n, err = copyInspected(ctx, io.MultiWriter(scan, crc), io.LimitReader(decoder, int64(f.UncompressedSize64)+1))
		}
		decoder.Close()
		// ByteReader prevents flate read-ahead hiding trailing compressed junk.
		consumed := spool.n - int64(br.Buffered()) - (x.data - x.off)
		if err == nil && (uint64(n) != f.UncompressedSize64 || consumed != int64(f.CompressedSize64) || crc.Sum32() != f.CRC32) {
			err = zip.ErrChecksum
		}
		stop()
		stream.Close()
		processed += min(n, int64(f.UncompressedSize64))
		r.processed = processed
		if ctx.Err() != nil {
			spool.close()
			complete = false
			r.reason = "budget_exhausted"
			r.reasons[r.reason] += int64(len(xs) - i)
			break
		}
		if err != nil {
			spool.close()
			complete = false
			r.reason = "archive_corrupt"
			var corrupt flate.CorruptInputError
			if !errors.Is(err, zip.ErrChecksum) && !errors.As(err, &corrupt) {
				r.reason = "read_error"
			}
			r.reasons[r.reason]++
			creditBad(int64(f.CompressedSize64))
			if r.reason == "read_error" {
				break
			}
			continue
		}
		writeU64(committed, x.off)
		writeU64(committed, x.end-x.off)
		spool.copyPrefix(committed, spool.n)
		spool.close()
		r.readable += min(int64(f.CompressedSize64), m.Size-r.readable-r.unreadable)
		r.storedRead += int64(f.CompressedSize64)
		if !f.FileInfo().IsDir() {
			r.entries++
			r.entryBytes += n
			finding := scan.finish()
			if detectContent(scan.prefix, f.Name).Archive != "" {
				r.reasons["nested_archive"]++
			} else {
				r.findings.addFile(finding)
			}
		}
	}
	r.commitment = MemberCommitment{"zip_entries", [32]byte(committed.Sum(nil))}
	if complete {
		// Completion is bound to every stored byte, including directory and headers.
		stats.GETs.Add(1)
		stream, err := s.OpenRange(ctx, m.Identity, 0, m.Size)
		if err == nil {
			h := sha256.New()
			stop := context.AfterFunc(ctx, func() { stream.Close() })
			n, e := copyInspected(ctx, h, io.LimitReader(stream, m.Size+1))
			stop()
			stream.Close()
			if e == nil && n == m.Size {
				r.commitment = MemberCommitment{"full", [32]byte(h.Sum(nil))}
				r.state = "fully_read"
				return r
			}
		}
		r.reason = "read_error"
		r.reasons[r.reason]++
	}
	return r
}

// decodedSpool holds at most one archive allowance on local temporary storage;
// it is mode 0600, unlinked immediately, and closed on every exit path.
type decodedSpool struct {
	name string
	f    *os.File
	n    int64
	w    *bufio.Writer
}

func newSpool() (*decodedSpool, error) {
	f, e := os.CreateTemp("", "aim-census-*")
	if e != nil {
		return nil, e
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
	return n, e
}
func (s *decodedSpool) copyPrefix(w io.Writer, n int64) error {
	if e := s.w.Flush(); e != nil {
		return e
	}
	_, e := io.Copy(w, io.NewSectionReader(s.f, 0, n))
	return e
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

func readTarGzip(ctx context.Context, s CensusSource, m Member, p Policy, stats *RunStats) censusMemberResult {
	r := archiveResult(m)
	r.findings.memory = p.censusMemory
	r.commitment = decodedCommitment(nil)
	stats.GETs.Add(1)
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
	stop := context.AfterFunc(ctx, func() { stream.Close() })
	defer stop()
	defer stream.Close()
	storedHash := sha256.New()
	stored := &countingReader{r: io.TeeReader(io.LimitReader(stream, p.ArchiveAllowanceBytes+archiveTransportSlack), storedHash)}
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
		r.reason = failureReason(err)
		if r.reason != "budget_exhausted" {
			r.unreadable = m.Size
		}
		return r
	}
	defer gz.Close()
	spool, err := newSpool()
	if err != nil {
		r.reason = "read_error"
		r.unreadable = m.Size
		return r
	}
	defer spool.close()
	limit := p.ArchiveAllowanceBytes
	capStop := false
	if m.Size <= mathMaxDiv(p.ArchiveCaps.CompressionRatio) && m.Size*p.ArchiveCaps.CompressionRatio < limit {
		limit = m.Size * p.ArchiveCaps.CompressionRatio
		capStop = true
	}
	decoded := io.TeeReader(io.LimitReader(gz, limit), spool)
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
		r.reason = "read_error"
	}
	if r.reason == "archive_corrupt" || r.reason == "read_error" {
		r.unreadable = m.Size
	}
	r.reasons[r.reason]++
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
