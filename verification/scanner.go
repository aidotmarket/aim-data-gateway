package verification

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"io"
	"math"
	"math/big"
	"math/bits"
	"sort"
	"time"
)

const blockSize = 64 << 10

type budget struct{ used, limit int64 }

func (b *budget) reserve(n int64) error {
	if n < 0 || n > b.limit-b.used {
		return ErrBudget
	}
	b.used += n
	return nil
}
func (p Policy) checked() (Policy, error) {
	if p.CanonicalizationVersion != "python-json-sort-compact-v1" || p.RowCountAlgorithmVersion != "exact-v1" || p.DistinctAlgorithmVersion != "hll-sha256-v1" || p.HistogramVersion != "fixed-buckets-v1" || p.NumericBucketVersion != "fixed-buckets-v1" || p.MinimumAggregateOccupancy != 10 {
		return p, ErrUnsupported
	}
	lb := []int{0, 1, 4, 8, 16, 32, 64, 128, 256}
	nb := []float64{-1000, -100, -10, 0, 10, 100, 1000}
	if len(p.LengthBounds) != len(lb) || len(p.NumericBoundaries) != len(nb) {
		return p, ErrUnsupported
	}
	for i, v := range lb {
		if p.LengthBounds[i] != v {
			return p, ErrUnsupported
		}
	}
	for i, v := range nb {
		if p.NumericBoundaries[i] != v {
			return p, ErrUnsupported
		}
	}
	if p.Commitments == nil && (!uuidASCII(p.GatewayID) || !hexASCII(p.SnapshotHash)) {
		return p, ErrUnsupported
	}
	if p.MaxMemoryBytes == 0 {
		p.MaxMemoryBytes = 128 << 20
	}
	if p.MaxRecordBytes == 0 {
		p.MaxRecordBytes = 16 << 20
	}
	if p.MaxScalarBytes == 0 {
		p.MaxScalarBytes = 16 << 20
	}
	if p.MaxColumns == 0 {
		p.MaxColumns = 1000
	}
	if p.MaxFactBytes == 0 {
		p.MaxFactBytes = 32768
	}
	if p.Deadline == 0 {
		p.Deadline = 30 * time.Minute
	}
	if p.MaxMemoryBytes < 1 || p.MaxMemoryBytes > 128<<20 || p.MaxRecordBytes < 1 || p.MaxRecordBytes > 16<<20 || p.MaxScalarBytes < 1 || p.MaxScalarBytes > 16<<20 || p.MaxColumns < 1 || p.MaxColumns > 1000 || p.MaxFactBytes < 1 || p.MaxFactBytes > 32768 || p.Deadline < 0 || p.Deadline > 30*time.Minute {
		return p, ErrBudget
	}
	return p, nil
}
func fileIDASCII(s string) bool {
	return len(s) == 32 && hexASCII(s+s)
}
func hexASCII(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func uuidASCII(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func keyed(key [32]byte, s string) string {
	h := hmac.New(sha256.New, key[:])
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}
func objectID(p Policy, m Member) string {
	if p.Commitments != nil {
		return p.Commitments.ObjectID(m)
	}
	return keyed(p.CommitmentKey, "object\x00gateway_listing\x00"+p.GatewayID+"\x00"+m.Identity+"\x00"+hex.EncodeToString(m.SHA256[:]))
}

type pinned struct {
	member       Member
	blocks       [][32]byte
	names, kinds []string
}

func prepare(ctx context.Context, s Source, p Policy, b *budget) ([]pinned, error) {
	members := append([]Member(nil), s.Members()...)
	if len(members) == 0 || len(members) > 100000 {
		return nil, ErrArtifactChanged
	}
	if e := b.reserve(int64(len(members)) * 512); e != nil {
		return nil, e
	}
	out := make([]pinned, 0, len(members))
	for i, m := range members {
		if !fileIDASCII(m.Identity) || m.Size < 0 || i > 0 && members[i-1].Identity >= m.Identity {
			return nil, ErrArtifactChanged
		}
		n := m.Size / blockSize
		if m.Size%blockSize != 0 {
			n++
		}
		if e := b.reserve(n * 32); e != nil {
			return nil, e
		}
		r, e := s.Open(ctx, m.Identity)
		if e != nil {
			return nil, ErrArtifactChanged
		}
		x := pinned{member: m, blocks: make([][32]byte, 0, n)}
		h := sha256.New()
		buf := make([]byte, blockSize)
		var size int64
		stop := context.AfterFunc(ctx, func() { r.Close() })
		hr := &hashBlocks{ctx: ctx, r: r, x: &x, h: h, buf: buf, size: &size}
		br := bufio.NewReaderSize(hr, blockSize)
		magic, _ := br.Peek(4)
		if len(magic) == 4 && string(magic[:2]) == "PK" {
			x.member.Format = "unsupported"
		}
		if supported(x.member.Format) && m.Format != "parquet" {
			e = inferText(ctx, br, &x, p, b)
		} else {
			_, e = io.CopyBuffer(io.Discard, br, make([]byte, blockSize))
		}
		// Resource refusal stops reading immediately; successful scans still
		// verify every byte, and shape errors drain to detect mutation.
		if e == ErrBudget {
			stop()
			r.Close()
			return nil, e
		}
		parserError := e
		if e != nil {
			_, e = io.CopyBuffer(io.Discard, br, make([]byte, blockSize))
		}
		stop()
		r.Close()
		if e != nil {
			return nil, e
		}
		if size != m.Size || !hmac.Equal(h.Sum(nil), m.SHA256[:]) {
			return nil, ErrArtifactChanged
		}
		if parserError != nil {
			return nil, parserError
		}
		out = append(out, x)
	}
	return out, nil
}

type hashBlocks struct {
	ctx     context.Context
	r       io.Reader
	x       *pinned
	h       hash.Hash
	buf     []byte
	size    *int64
	pending []byte
	end     bool
	verify  bool
	index   int
}

func (r *hashBlocks) Read(dst []byte) (int, error) {
	if r.ctx.Err() != nil {
		return 0, ErrTimeout
	}
	if len(r.pending) == 0 {
		if r.end {
			return 0, io.EOF
		}
		n, e := io.ReadFull(r.r, r.buf)
		if e != nil && e != io.EOF && e != io.ErrUnexpectedEOF {
			return 0, ErrArtifactChanged
		}
		r.end = e != nil
		*r.size += int64(n)
		if *r.size > r.x.member.Size {
			return 0, ErrArtifactChanged
		}
		if n == 0 {
			if *r.size != r.x.member.Size {
				return 0, ErrArtifactChanged
			}
			return 0, io.EOF
		}
		r.h.Write(r.buf[:n])
		digest := sha256.Sum256(r.buf[:n])
		if r.verify {
			if r.index >= len(r.x.blocks) || digest != r.x.blocks[r.index] {
				return 0, ErrArtifactChanged
			}
			r.index++
		} else {
			r.x.blocks = append(r.x.blocks, digest)
		}
		if r.end && *r.size != r.x.member.Size {
			return 0, ErrArtifactChanged
		}
		r.pending = r.buf[:n]
	}
	n := copy(dst, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

// verifiedAt checks the exact bytes returned to the decoder against pre-read blocks.
// It retains only one block and never asks the adapter for more than 64 KiB.
type verifiedAt struct {
	ctx context.Context
	r   io.ReaderAt
	x   *pinned
}

func (v verifiedAt) ReadAt(dst []byte, off int64) (int, error) {
	if off < 0 {
		return 0, ErrArtifactChanged
	}
	done := 0
	buf := make([]byte, blockSize)
	for len(dst) > 0 && off < v.x.member.Size {
		if v.ctx.Err() != nil {
			return done, ErrTimeout
		}
		idx := off / blockSize
		start := idx * blockSize
		n := int(min(int64(blockSize), v.x.member.Size-start))
		count, e := v.r.ReadAt(buf[:n], start)
		if count != n || e != nil && e != io.EOF || sha256.Sum256(buf[:n]) != v.x.blocks[idx] {
			return done, ErrArtifactChanged
		}
		take := copy(dst, buf[off-start:n])
		done += take
		off += int64(take)
		dst = dst[take:]
	}
	if len(dst) > 0 {
		return done, io.EOF
	}
	return done, nil
}

func openText(ctx context.Context, s Source, x *pinned) (io.ReadCloser, io.Reader, error) {
	r, e := s.Open(ctx, x.member.Identity)
	if e != nil {
		return nil, nil, ErrArtifactChanged
	}
	var size int64
	v := &hashBlocks{ctx: ctx, r: r, x: x, h: sha256.New(), buf: make([]byte, blockSize), size: &size, verify: true}
	return r, v, nil
}

func Scan(ctx context.Context, s Source, p Policy) (Facts, error) {
	p, e := p.checked()
	if e != nil {
		return Facts{}, e
	}
	ctx, cancel := context.WithTimeout(ctx, p.Deadline)
	defer cancel()
	b := &budget{limit: p.MaxMemoryBytes}
	if e = b.reserve(int64(p.MaxRecordBytes)*4 + int64(p.MaxFactBytes)*4 + 4<<20); e != nil {
		return Facts{}, e
	}
	xs, e := prepare(ctx, s, p, b)
	if e != nil {
		return Facts{}, e
	}
	result := Facts{Coverage: Coverage{Discovered: len(xs), Reasons: map[string]int{}, Skipped: []Skip{}}, Objects: []Object{}}
	content := sha256.New()
	var frame [8]byte
	for i := range xs {
		x := &xs[i]
		m := x.member
		binary.BigEndian.PutUint64(frame[:], uint64(len(m.Identity)))
		content.Write(frame[:])
		content.Write([]byte(m.Identity))
		binary.BigEndian.PutUint64(frame[:], uint64(m.Size))
		content.Write(frame[:])
		content.Write(m.SHA256[:])
		id := objectID(p, m)
		if !hexASCII(id) {
			return Facts{}, ErrUnsupported
		}
		if !supported(m.Format) {
			if (len(result.Coverage.Skipped)+1)*128 > p.MaxFactBytes {
				return Facts{}, ErrBudget
			}
			r, reader, err := openText(ctx, s, x)
			if err != nil {
				return Facts{}, err
			}
			stop := context.AfterFunc(ctx, func() { r.Close() })
			_, err = io.CopyBuffer(io.Discard, reader, make([]byte, blockSize))
			stop()
			r.Close()
			if err != nil {
				return Facts{}, err
			}
			result.Coverage.Reasons["unsupported_type"]++
			result.Coverage.Skipped = append(result.Coverage.Skipped, Skip{id, "unsupported_type"})
			continue
		}
		baseline := b.used
		var o Object
		if m.Format == "parquet" {
			o, e = parquetObject(ctx, s, x, p, b)
		} else {
			o, e = textObject(ctx, s, x, p, b)
		}
		b.used = baseline
		if e != nil {
			if ctx.Err() != nil {
				e = ErrTimeout
			}
			return Facts{}, e
		}
		o.ObjectID = id
		result.Objects = append(result.Objects, o)
		result.Coverage.Scanned++
		raw, e := canonical(map[string]any{"coverage": result.Coverage, "objects": result.Objects, "schema_preview": preview(result.Objects)})
		if e != nil || len(raw) > p.MaxFactBytes {
			return Facts{}, ErrBudget
		}
	}
	raw, e := canonical(map[string]any{"coverage": result.Coverage, "objects": result.Objects, "schema_preview": preview(result.Objects)})
	if e != nil || len(raw) > p.MaxFactBytes {
		return Facts{}, ErrBudget
	}
	sort.Slice(result.Objects, func(i, j int) bool { return result.Objects[i].ObjectID < result.Objects[j].ObjectID })
	sort.Slice(result.Coverage.Skipped, func(i, j int) bool { return result.Coverage.Skipped[i].ObjectID < result.Coverage.Skipped[j].ObjectID })
	result.ContentSHA256 = hex.EncodeToString(content.Sum(nil))
	result.LocatorCommitment = keyed(p.CommitmentKey, "gateway_listing\x00"+p.GatewayID+"\x00"+p.SnapshotHash)
	if p.Commitments != nil {
		result.LocatorCommitment = p.Commitments.LocatorCommitment()
	}
	if !hexASCII(result.LocatorCommitment) {
		return Facts{}, ErrUnsupported
	}
	result.FingerprintHash, e = fingerprint(result, p)
	if e != nil {
		return Facts{}, e
	}
	return result, nil
}
func supported(f string) bool { return f == "csv" || f == "tsv" || f == "jsonl" || f == "parquet" }
func preview(objects []Object) []any {
	a := []any{}
	for _, o := range objects {
		a = append(a, map[string]any{"object_id": o.ObjectID, "column_names": o.Names, "column_types": o.Types, "row_count": o.Rows, "row_count_method": o.RowMethod})
	}
	return a
}
func fingerprint(f Facts, p Policy) (string, error) {
	raw, e := canonical(map[string]any{"coverage": f.Coverage, "objects": f.Objects, "depth_class": "complete_standard_v1", "row_count_algorithm_version": p.RowCountAlgorithmVersion, "distinct_algorithm_version": p.DistinctAlgorithmVersion, "histogram_version": p.HistogramVersion, "numeric_bucket_version": p.NumericBucketVersion, "canonicalization_version": p.CanonicalizationVersion})
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:]), e
}
func Probe(ctx context.Context, s Source, p Policy) (ProbeResult, error) {
	// Full complete-or-refuse validation is free; it releases all local values.
	f, e := Scan(ctx, s, p)
	if e != nil {
		return ProbeResult{}, e
	}
	raw, e := canonical(map[string]any{"coverage": f.Coverage, "objects": f.Objects, "schema_preview": preview(f.Objects)})
	if e != nil {
		return ProbeResult{}, e
	}
	tokens := (len(raw) + 2) / 3
	if tokens > 8192 {
		return ProbeResult{}, ErrBudget
	}
	var size int64
	for _, m := range s.Members() {
		if m.Size > math.MaxInt64-size {
			return ProbeResult{}, ErrBudget
		}
		size += m.Size
	}
	class := "large"
	if size < 10000000 {
		class = "small"
	} else if size < 100000000 {
		class = "medium"
	}
	// Reserve a conservative upper envelope for the actual schemas: estimates and
	// rates can grow; histograms have at most ten int64 entries per column.
	bound := 512
	for _, o := range f.Objects {
		for _, name := range o.Names {
			bound += len(name)*6 + 768
		}
		bound += 512
	}
	tokens = max(1, (bound+2)/3)
	if tokens > 8192 {
		return ProbeResult{}, ErrBudget
	}
	return ProbeResult{len(f.Objects) + len(f.Coverage.Skipped), class, tokens, []string{"complete_traversal", "deterministic_object_order", "fixed_bucket_aggregates", "exact_or_declared_estimated_row_counts"}}, nil
}

type aggregate struct {
	kind    string
	nulls   int64
	exact   map[string]struct{}
	hll     [128]uint8
	lengths [10]int64
	numeric [8]int64
	seed    [36]byte
}

func newAggregate(kind string, i int, p Policy) *aggregate {
	a := &aggregate{kind: kind, exact: map[string]struct{}{}}
	copy(a.seed[:32], p.Seed[:])
	binary.BigEndian.PutUint32(a.seed[32:], uint32(i))
	return a
}
func (a *aggregate) add(raw []byte, length int, number float64, valid bool, p Policy, b *budget) error {
	if !valid {
		a.nulls++
		return nil
	}
	if len(raw) > p.MaxScalarBytes {
		return ErrBudget
	}
	if len(a.exact) < 10 {
		if _, ok := a.exact[string(raw)]; !ok {
			if e := b.reserve(int64(len(raw) + 64)); e != nil {
				return e
			}
			a.exact[string(raw)] = struct{}{}
		}
	}
	h := sha256.New()
	h.Write(a.seed[:])
	h.Write([]byte{0})
	h.Write(raw)
	sum := h.Sum(nil)
	x := binary.BigEndian.Uint64(sum)
	rem := x >> 7
	rank := 58 - bits.Len64(rem)
	a.hll[x&127] = max(a.hll[x&127], uint8(rank))
	if a.kind == "string" || a.kind == "binary" {
		i := 0
		for i < len(p.LengthBounds) && length > p.LengthBounds[i] {
			i++
		}
		a.lengths[i]++
	}
	if a.kind == "integer" || a.kind == "float" || a.kind == "decimal" {
		if math.IsNaN(number) || math.IsInf(number, 0) {
			return ErrUnsupported
		}
		i := 0
		for i < len(p.NumericBoundaries) && number >= p.NumericBoundaries[i] {
			i++
		}
		a.numeric[i]++
	}
	return nil
}
func (a *aggregate) estimate() *big.Int {
	sum := 0.0
	zeros := 0
	for _, r := range a.hll {
		sum += math.Ldexp(1, -int(r))
		if r == 0 {
			zeros++
		}
	}
	v := 0.7213 / (1 + 1.079/128) * 128 * 128 / sum
	if zeros > 0 {
		v = 128 * math.Log(128/float64(zeros))
	}
	estimate, _ := new(big.Float).SetFloat64(math.RoundToEven(v)).Int(nil)
	return estimate
}
func low(counts []int64) bool {
	for _, c := range counts {
		if c > 0 && c < 10 {
			return true
		}
	}
	return false
}
func rateUnits(c, n int64) int64 { // avoid overflow for signed int64 row counts.
	var x, q, r big.Int
	x.Mul(big.NewInt(c), big.NewInt(1000000))
	q.QuoRem(&x, big.NewInt(n), &r)
	r.Mul(&r, big.NewInt(2))
	cmp := r.Cmp(big.NewInt(n))
	v := q.Int64()
	if cmp > 0 || cmp == 0 && v%2 != 0 {
		v++
	}
	return v
}
func ambiguousRate(c, n int64) bool {
	v := rateUnits(c, n)
	first := func(target int64) int64 {
		lo, hi := int64(0), n
		for lo < hi {
			m := lo + (hi-lo)/2
			if rateUnits(m, n) < target {
				lo = m + 1
			} else {
				hi = m
			}
		}
		return lo
	}
	left := first(v)
	right := first(v+1) - 1
	if v == 1000000 {
		right = n
	}
	return max(left, int64(1)) <= min(right, int64(9)) || max(left, n-9) <= min(right, n-1)
}
func ambiguousDistinct(e int64) bool {
	// The Python interval intersects [1,9] exactly for integer estimates 1..9.
	// Comparing first avoids overflowing either ppm product for large estimates.
	return e > 0 && e <= 9
}
func finish(names []string, acc []*aggregate, rows int64) Object {
	o := Object{Names: names, Types: []string{}, NullRate: []any{}, Distinct: []any{}, Length: []any{}, Numeric: []any{}, Rows: rows, RowMethod: "exact"}
	for _, a := range acc {
		o.Types = append(o.Types, a.kind)
		var rate any = suppressed
		if rows >= 10 && !low([]int64{a.nulls, rows - a.nulls}) && !ambiguousRate(a.nulls, rows) {
			q := rateUnits(a.nulls, rows)
			rate = rateString(q)
		}
		o.NullRate = append(o.NullRate, rate)
		var distinct any = suppressed
		e := a.estimate()
		if rows >= 10 && (len(a.exact) == 0 || len(a.exact) == 10) && (!e.IsInt64() || !ambiguousDistinct(e.Int64())) {
			var value any = e
			if e.IsInt64() {
				value = e.Int64()
			}
			distinct = map[string]any{"estimate": value, "algorithm": "hll-sha256-v1", "relative_error_ppm": 91924}
		}
		o.Distinct = append(o.Distinct, distinct)
		var l, n any
		if a.kind == "string" || a.kind == "binary" {
			l = a.lengths
			if rows < 10 || low(a.lengths[:]) {
				l = suppressed
			}
		}
		if a.kind == "integer" || a.kind == "float" || a.kind == "decimal" {
			n = a.numeric
			if rows < 10 || low(a.numeric[:]) {
				n = suppressed
			}
		}
		o.Length = append(o.Length, l)
		o.Numeric = append(o.Numeric, n)
	}
	return o
}
