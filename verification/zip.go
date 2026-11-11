package verification

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/flate"
	"context"
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"errors"
	"hash"
	"hash/crc32"
	"io"
	"sort"
)

type zipExtent struct {
	file       *zip.File
	off, bound int64
	valid      bool
}

type zipPlan struct {
	extents  []zipExtent
	selected int
	planned  int64
	stop     string
}

func planZip(files []*zip.File, offsets []int64, cdOff int64, p Policy) zipPlan {
	plan := zipPlan{extents: make([]zipExtent, len(files))}
	for i, f := range files {
		plan.extents[i] = zipExtent{f, offsets[i], cdOff, offsets[i] >= 0 && offsets[i] <= cdOff-30}
		if plan.stop != "" {
			continue
		}
		if i >= p.ArchiveCaps.Entries {
			plan.stop = "archive_over_cap"
			continue
		}
		if f.UncompressedSize64 > uint64(p.ArchiveAllowanceBytes-plan.planned) {
			plan.stop = "budget_exhausted"
			continue
		}
		plan.selected++
		plan.planned += int64(f.UncompressedSize64)
	}
	order := make([]int, 0, len(files))
	for i, x := range plan.extents {
		if x.valid {
			order = append(order, i)
		}
	}
	sort.Slice(order, func(i, j int) bool { return offsets[order[i]] < offsets[order[j]] })
	for j, i := range order {
		x := &plan.extents[i]
		if j+1 < len(order) {
			x.bound = offsets[order[j+1]]
		}
		// Even the smallest possible local header must fit. Mark both sides of a provable overlap before execution, including encrypted neighbours.
		if x.file.CompressedSize64 > uint64(max(0, x.bound-x.off-30)) || x.bound-x.off < 30 {
			x.valid = false
			if j+1 < len(order) {
				plan.extents[order[j+1]].valid = false
			}
		}
	}
	return plan
}

type ZipPreflight struct {
	Reason     string
	CDOffset   int64
	Reader     *zip.Reader
	offsets    []int64
	compressed uint64
}

// PreflightZip shares directory/ratio/LOW-H decisions between free and paid reads; tail is the final <=1 MiB.
func PreflightZip(tail []byte, size int64, p Policy) (out ZipPreflight) {
	out.Reason = "archive_corrupt"
	if size < 0 || int64(len(tail)) != min(size, archiveTransportSlack) {
		return
	}
	end := -1
	for i := len(tail) - 22; i >= max(0, len(tail)-65557); i-- {
		if bytes.Equal(tail[i:i+4], []byte("PK\x05\x06")) && i+22+int(binary.LittleEndian.Uint16(tail[i+20:])) == len(tail) {
			end = i
			break
		}
	}
	if end < 0 {
		out.Reason = "not_zip"
		return
	}
	cdSize, cdOff := int64(binary.LittleEndian.Uint32(tail[end+12:])), int64(binary.LittleEndian.Uint32(tail[end+16:]))
	tailStart := size - int64(len(tail))
	if cdSize > archiveTransportSlack || cdOff < tailStart {
		out.Reason = "archive_over_cap"
		return
	}
	if cdOff+cdSize > tailStart+int64(end) {
		return
	}
	zr, err := zip.NewReader(tailAt{tail, tailStart}, size)
	if err != nil {
		return
	}
	var compressed, expanded uint64
	for _, f := range zr.File {
		if ^uint64(0)-compressed < f.CompressedSize64 || ^uint64(0)-expanded < f.UncompressedSize64 {
			out.Reason = "archive_over_cap"
			return
		}
		compressed += f.CompressedSize64
		expanded += f.UncompressedSize64
	}
	ratio := uint64(p.ArchiveCaps.CompressionRatio)
	if compressed == 0 && expanded > 0 || compressed > 0 && (expanded/compressed > ratio || expanded/compressed == ratio && expanded%compressed > 0) {
		out.Reason = "archive_over_cap"
		return
	}
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
		return
	}
	return ZipPreflight{Reader: zr, offsets: offsets, CDOffset: cdOff, compressed: compressed}
}
func readZip(ctx context.Context, s CensusSource, m Member, p Policy, stats *RunStats) (r censusMemberResult) {
	r = archiveResult(m)
	defer func() {
		if ctx.Err() != nil && !r.opened {
			r.reason = "budget_exhausted"
			r.unreadable = 0
		}
	}()
	tail, err := rangeRead(ctx, s, m, max(0, m.Size-archiveTransportSlack), min(m.Size, archiveTransportSlack), stats)
	if err != nil {
		r.reason = "read_error"
		r.unreadable = m.Size
		return
	}
	pre := PreflightZip(tail, m.Size, p)
	if pre.Reason == "not_zip" {
		prefix := tail
		if m.Size > int64(len(tail)) {
			prefix, err = rangeRead(ctx, s, m, 0, min(m.Size, 4), stats)
			if err != nil {
				r.reason = "read_error"
				r.unreadable = m.Size
				return
			}
		}
		if !bytes.HasPrefix(prefix, []byte("PK\x03\x04")) && !bytes.HasPrefix(prefix, []byte("PK\x05\x06")) {
			return readPlainZipCandidate(ctx, s, m, p, r, tail, stats)
		}
		r.unreadable = m.Size
		return
	}
	if pre.Reason != "" {
		r.reason, r.unreadable = pre.Reason, m.Size
		return
	}
	cdOff, tailStart := pre.CDOffset, m.Size-int64(len(tail))
	plan := planZip(pre.Reader.File, pre.offsets, cdOff, p)
	stats.PlannedBytes.Add(plan.planned)
	r.opened = true
	r.state = "partly_read"
	r.reason = ""
	committed := sha256.New()
	full := &zipFullHash{h: sha256.New(), memory: p.censusMemory, limit: p.MaxMemoryBytes}
	defer full.release()
	complete := plan.selected == len(plan.extents)
	for _, x := range plan.extents {
		if !x.valid || x.file.Flags&1 != 0 || x.file.Method != zip.Store && x.file.Method != zip.Deflate {
			complete = false
			full.release()
		}
	}
	dropFull := func() {
		complete = false
		full.release()
		r.reason = "read_error"
		// read_error + zip_entries + every entry credited means "full hash not attempted".
		if ctx.Err() == nil {
			r.reasons[r.reason]++
		}
	}
	if complete && cdOff-int64(pre.compressed) > p.ArchiveAllowanceBytes {
		dropFull()
	}
	creditBad := func(n uint64) { r.unreadable += int64(min(n, uint64(m.Size-r.readable-r.unreadable))) }
	first := cdOff
	for _, x := range plan.extents {
		first = min(first, x.off)
	}
	if complete && first > 0 {
		e := hashZipPrefix(ctx, s, m, first, full.h, stats)
		if e != nil {
			dropFull()
		}
		full.next = first
	}
	for i, x := range plan.extents {
		f := x.file
		if i >= plan.selected {
			r.reason = plan.stop
			r.reasons[plan.stop] += int64(len(plan.extents) - i)
			if plan.stop == "archive_over_cap" {
				for _, rest := range plan.extents[i:] {
					creditBad(rest.file.CompressedSize64)
				}
			}
			break
		}
		if ctx.Err() != nil {
			complete = false
			full.release()
			r.reason = "budget_exhausted"
			r.reasons[r.reason] += int64(len(plan.extents) - i)
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
			full.release()
			r.reason = reason
			r.reasons[reason]++
			creditBad(f.CompressedSize64)
			continue
		}
		if complete {
			if e := full.start(x.off, x.bound-x.off); e != nil {
				dropFull()
			}
		}
		length := x.bound - x.off
		if !complete {
			// Local name/extra lengths are uint16. Request enough for any local header and the payload; never drain descriptors or gaps for hashing.
			length = min(length, 30+2*65535+int64(f.CompressedSize64))
		}
		stats.GETs.Add(1)
		stats.RequestedBytes.Add(length)
		stream, e := s.OpenRange(ctx, m.Identity, x.off, length)
		if e != nil {
			complete = false
			full.release()
			r.reason = "read_error"
			if ctx.Err() != nil {
				r.reason = "budget_exhausted"
			} else {
				creditBad(f.CompressedSize64)
			}
			r.reasons[r.reason]++
			break
		}
		stop := context.AfterFunc(ctx, func() { stream.Close() })
		input := &countingReader{r: io.LimitReader(&statsReader{stream, stats}, length)}
		var reader io.Reader = input
		if complete {
			reader = io.TeeReader(input, full)
		}
		state, _ := committed.(encoding.BinaryMarshaler).MarshalBinary()
		n, scan, e := readZipEntry(ctx, reader, x, committed)
		r.processed += min(n, int64(f.UncompressedSize64))
		if e == nil && complete {
			_, e = copyInspected(ctx, io.Discard, reader)
			if input.n != x.bound-x.off && e == nil {
				e = io.ErrUnexpectedEOF
			}
		}
		stop()
		stream.Close()
		if e != nil || ctx.Err() != nil {
			committed.(encoding.BinaryUnmarshaler).UnmarshalBinary(state)
			complete = false
			full.release()
			if errors.Is(e, ErrResourceLimit) {
				r.err = e
				return
			}
			r.reason = "archive_corrupt"
			var corrupt flate.CorruptInputError
			if ctx.Err() != nil {
				r.reason = "budget_exhausted"
			} else if input.err != nil && !errors.Is(input.err, io.EOF) {
				r.reason = "read_error"
			} else if !errors.Is(e, zip.ErrFormat) && !errors.Is(e, zip.ErrChecksum) && !errors.As(e, &corrupt) {
				r.reason = "read_error"
			}
			r.reasons[r.reason]++
			if r.reason == "budget_exhausted" {
				break
			}
			creditBad(f.CompressedSize64)
			if r.reason == "read_error" {
				break
			}
			continue
		}
		r.readable += int64(min(f.CompressedSize64, uint64(m.Size-r.readable-r.unreadable)))
		r.storedRead += int64(f.CompressedSize64)
		if !f.FileInfo().IsDir() {
			r.entries++
			r.entryBytes += n
			if detectContent(scan.prefix, f.Name).Archive != "" {
				r.reasons["nested_archive"]++
			} else {
				_ = scan.finish()
			}
		}
	}
	r.commitment = MemberCommitment{"zip_entries", [32]byte(committed.Sum(nil))}
	if complete && full.next == cdOff {
		full.h.Write(tail[cdOff-tailStart:])
		r.commitment = MemberCommitment{"full", [32]byte(full.h.Sum(nil))}
		r.state = "fully_read"
	}
	return
}
func readPlainZipCandidate(ctx context.Context, s CensusSource, m Member, p Policy, r censusMemberResult, tail []byte, stats *RunStats) censusMemberResult {
	var reader io.Reader = bytes.NewReader(tail)
	if int64(len(tail)) != m.Size {
		stats.GETs.Add(1)
		stats.RequestedBytes.Add(min(m.Size, p.ArchiveAllowanceBytes))
		stream, e := s.OpenRange(ctx, m.Identity, 0, min(m.Size, p.ArchiveAllowanceBytes))
		if e != nil {
			r.reason = "read_error"
			r.unreadable = m.Size
			if ctx.Err() != nil {
				r.reason = "budget_exhausted"
				r.unreadable = 0
			}
			return r
		}
		defer stream.Close()
		stop := context.AfterFunc(ctx, func() { stream.Close() })
		defer stop()
		reader = &statsReader{stream, stats}
	}
	r.opened = true
	scan := newFileInspection("." + m.Format)
	stored := &countingReader{r: io.TeeReader(io.LimitReader(reader, p.ArchiveAllowanceBytes), scan)}
	return finishPlainCandidate(ctx, m, p, r, stored, scan.h, scan)
}
func hashZipPrefix(ctx context.Context, s CensusSource, m Member, n int64, h hash.Hash, stats *RunStats) error {
	stats.GETs.Add(1)
	stats.RequestedBytes.Add(n)
	r, e := s.OpenRange(ctx, m.Identity, 0, n)
	if e != nil {
		return e
	}
	defer r.Close()
	stop := context.AfterFunc(ctx, func() { r.Close() })
	defer stop()
	got, e := copyInspected(ctx, h, io.LimitReader(&statsReader{r, stats}, n))
	if e == nil && got != n {
		e = io.ErrUnexpectedEOF
	}
	return e
}
func readZipEntry(ctx context.Context, reader io.Reader, x zipExtent, committed hash.Hash) (int64, *fileInspection, error) {
	f := x.file
	scan := newFileInspection(f.Name)
	var header [30]byte
	if _, e := io.ReadFull(reader, header[:]); e != nil {
		return 0, scan, e
	}
	data := x.off + 30 + int64(binary.LittleEndian.Uint16(header[26:])) + int64(binary.LittleEndian.Uint16(header[28:]))
	length := int64(f.CompressedSize64)
	if !bytes.Equal(header[:4], []byte("PK\x03\x04")) || data > x.bound || length > x.bound-data {
		return 0, scan, zip.ErrFormat
	}
	// Descriptor flags may legitimately differ locally. Non-placeholder local CRC/sizes must agree; decoding, extent consumption and CRC decide credit.
	for _, v := range []struct {
		got  uint32
		want uint64
	}{{binary.LittleEndian.Uint32(header[14:]), uint64(f.CRC32)}, {binary.LittleEndian.Uint32(header[18:]), f.CompressedSize64}, {binary.LittleEndian.Uint32(header[22:]), f.UncompressedSize64}} {
		if v.got != 0 && uint64(v.got) != v.want {
			return 0, scan, zip.ErrFormat
		}
	}
	writeU64(committed, x.off)
	writeU64(committed, data+length-x.off)
	committed.Write(header[:])
	extent := io.TeeReader(io.LimitReader(reader, data+length-x.off-30), committed)
	if _, e := io.CopyN(io.Discard, extent, data-x.off-30); e != nil {
		return 0, scan, e
	}
	counted := &countingReader{r: io.LimitReader(extent, length)}
	br := bufio.NewReaderSize(counted, 4096)
	var decoder io.ReadCloser = io.NopCloser(br)
	if f.Method == zip.Deflate {
		decoder = flate.NewReader(br)
	}
	crc := crc32.NewIEEE()
	n, e := copyInspected(ctx, io.MultiWriter(scan, crc), io.LimitReader(decoder, int64(f.UncompressedSize64)+1))
	decoder.Close()
	if e == nil && (uint64(n) != f.UncompressedSize64 || counted.n-int64(br.Buffered()) != length || crc.Sum32() != f.CRC32) {
		e = zip.ErrChecksum
	}
	return n, scan, e
}

// Full hashes stream physical order, buffering reordered extents. Reserve before make: 32 KiB allocator pages + 128 B/node; exhaustion drops only the full attempt.
const zipHashBookkeeping = int64(128)

type zipHashBlock struct {
	off  int64
	data []byte
	next *zipHashBlock
}
type zipFullHash struct {
	h                      hash.Hash
	next, off, held, limit int64
	pending, current       *zipHashBlock
	memory                 *censusMemory
}

func (h *zipFullHash) start(off, size int64) error {
	h.off, h.current = off, nil
	if off == h.next {
		return nil
	}
	capacity := (size + (32 << 10) - 1) &^ ((32 << 10) - 1)
	charge := capacity + zipHashBookkeeping
	if !h.reserve(charge) {
		return ErrResourceLimit
	}
	h.held += charge
	link := &h.pending
	for *link != nil && (*link).off < off {
		link = &(*link).next
	}
	h.current = &zipHashBlock{off: off, data: make([]byte, 0, capacity), next: *link}
	*link = h.current
	return nil
}

// Full hashing is optional: unlike required census allocations, a failed reservation must not latch the shared run-level memory failure flag.
func (h *zipFullHash) reserve(n int64) bool {
	if n > h.limit-h.held {
		return false
	}
	if h.memory == nil {
		return true
	}
	headroom := max(int64(8<<20), h.memory.limit/8)
	for {
		v := h.memory.used.Load()
		if n > h.memory.limit-headroom-v || h.memory.failed.Load() {
			return false
		}
		if h.memory.used.CompareAndSwap(v, v+n) {
			return true
		}
	}
}
func (h *zipFullHash) Write(b []byte) (int, error) {
	n := len(b)
	if h.off == h.next {
		h.h.Write(b)
		h.next += int64(n)
		for h.pending != nil && h.pending.off == h.next {
			v := h.pending
			h.pending = v.next
			h.h.Write(v.data)
			h.next += int64(len(v.data))
			charge := int64(cap(v.data)) + zipHashBookkeeping
			v.data, v.next = nil, nil
			h.held -= charge
			if h.memory != nil {
				h.memory.used.Add(-charge)
			}
		}
	} else {
		if h.current == nil || n > cap(h.current.data)-len(h.current.data) {
			return 0, ErrResourceLimit
		}
		h.current.data = append(h.current.data, b...)
	}
	h.off += int64(n)
	return n, nil
}
func (h *zipFullHash) release() {
	h.pending, h.current = nil, nil
	if h.memory != nil {
		h.memory.used.Add(-h.held)
	}
	h.held = 0
}
