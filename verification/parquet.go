package verification

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata"
	"unicode/utf8"

	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/ipc"
	"github.com/apache/arrow-go/v18/arrow/memory"
	"github.com/apache/arrow-go/v18/parquet"
	"github.com/apache/arrow-go/v18/parquet/file"
	"github.com/apache/arrow-go/v18/parquet/schema"
)

type boundedAllocator struct {
	b     *budget
	inner memory.Allocator
}

func (a boundedAllocator) Allocate(n int) []byte {
	if e := a.b.reserve(int64(n)); e != nil {
		panic(ErrBudget)
	}
	return a.inner.Allocate(n)
}
func (a boundedAllocator) Reallocate(n int, old []byte) []byte {
	if e := a.b.reserve(int64(max(n-len(old), 0))); e != nil {
		panic(ErrBudget)
	}
	v := a.inner.Reallocate(n, old)
	a.b.used -= int64(max(len(old)-n, 0))
	return v
}
func (a boundedAllocator) Free(v []byte) { a.b.used -= int64(len(v)); a.inner.Free(v) }
func parquetKind(c *schema.Column) (string, error) {
	if c.MaxRepetitionLevel() != 0 || c.MaxDefinitionLevel() > 1 {
		return "", ErrUnsupported
	}
	switch c.LogicalType().(type) {
	case schema.StringLogicalType:
		return "string", nil
	case schema.DecimalLogicalType:
		return "decimal", nil
	case schema.DateLogicalType:
		return "date", nil
	case schema.TimestampLogicalType:
		return "datetime", nil
	case schema.NullLogicalType:
		return "unknown", nil
	case schema.IntLogicalType:
		return "integer", nil
	case schema.NoLogicalType:
	default:
		return "", ErrUnsupported
	}
	switch c.PhysicalType() {
	case parquet.Types.Boolean:
		return "boolean", nil
	case parquet.Types.Int32, parquet.Types.Int64:
		return "integer", nil
	case parquet.Types.Float, parquet.Types.Double:
		return "float", nil
	case parquet.Types.ByteArray, parquet.Types.FixedLenByteArray:
		return "binary", nil
	}
	return "", ErrUnsupported
}
func parquetObject(ctx context.Context, s Source, x *pinned, p Policy, b *budget) (o Object, err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(error); ok && errors.Is(e, ErrBudget) {
				err = ErrBudget
			} else {
				err = ErrUnsupported
			}
			o = Object{}
		}
	}()
	r, e := s.OpenAt(ctx, x.member.Identity)
	if e != nil {
		return o, ErrArtifactChanged
	}
	defer r.Close()
	stop := context.AfterFunc(ctx, func() { r.Close() })
	defer stop()
	if r.Size() != x.member.Size || r.Size() < 12 {
		return o, ErrArtifactChanged
	}
	v := verifiedAt{ctx: ctx, r: r, x: x}
	var tail [8]byte
	if _, e = v.ReadAt(tail[:], r.Size()-8); e != nil {
		return o, e
	}
	footer := int64(binary.LittleEndian.Uint32(tail[:4]))
	if string(tail[4:]) != "PAR1" || footer > 1<<20 || footer > r.Size()-12 {
		return o, ErrBudget
	}
	// Reserve non-allocator decoder structures and codec workspaces before opening
	// pages. The existing Arrow reader rejects page headers above these caps before
	// allocating/decompressing. No full row group buffering or pqarrow import.
	pageLimit := min(int64(4<<20), (b.limit-b.used)/10)
	if pageLimit < 64<<10 {
		return o, ErrBudget
	}
	if e = b.reserve(pageLimit * 6); e != nil {
		return o, e
	}
	props := parquet.NewReaderProperties(boundedAllocator{b, memory.NewGoAllocator()})
	props.BufferedStreamEnabled = true
	props.PageStreamingEnabled = true
	props.BufferSize = blockSize
	props.MaxCompressedPageSize = pageLimit
	props.MaxUncompressedPageSize = pageLimit
	pf, e := file.NewParquetReader(io.NewSectionReader(v, 0, r.Size()), file.WithReadProps(props))
	if e != nil {
		return o, safeParquetError(e)
	}
	defer pf.Close()
	zones := map[int]*time.Location{}
	if encoded := pf.MetaData().KeyValueMetadata().FindValue("ARROW:schema"); encoded != nil {
		if len(*encoded) > 1<<20 {
			return o, ErrBudget
		}
		data, e := base64.StdEncoding.DecodeString(*encoded)
		if e != nil {
			return o, ErrUnsupported
		}
		reader, e := ipc.NewReader(bytes.NewReader(data), ipc.WithAllocator(boundedAllocator{b, memory.NewGoAllocator()}))
		if e != nil {
			return o, ErrUnsupported
		}
		defer reader.Release()
		if reader.Schema().NumFields() != pf.MetaData().Schema.NumColumns() {
			return o, ErrUnsupported
		}
		for i, field := range reader.Schema().Fields() {
			if ts, ok := field.Type.(*arrow.TimestampType); ok && ts.TimeZone != "" {
				loc, e := ts.GetZone()
				if e != nil {
					return o, ErrUnsupported
				}
				zones[i] = loc
			}
		}
	}
	sch := pf.MetaData().Schema
	if sch.NumColumns() > p.MaxColumns || sch.NumColumns() == 0 || sch.Root().NumFields() != sch.NumColumns() {
		return o, ErrUnsupported
	}
	names := make([]string, sch.NumColumns())
	acc := make([]*aggregate, len(names))
	for i := range names {
		if _, ok := sch.Root().Field(i).(*schema.PrimitiveNode); !ok {
			return o, ErrUnsupported
		}
		c := sch.Column(i)
		kind, e := parquetKind(c)
		if e != nil {
			return o, e
		}
		names[i] = c.Name()
		acc[i] = newAggregate(kind, i, p)
	}
	if e = nameOK(names, p); e != nil {
		return o, e
	}
	if e = b.reserve(int64(len(acc)) * 2048); e != nil {
		return o, e
	}
	var rows int64
	for rg := 0; rg < pf.NumRowGroups(); rg++ {
		if ctx.Err() != nil {
			return o, ErrTimeout
		}
		group := pf.RowGroup(rg)
		n := group.NumRows()
		if n < 0 || n > math.MaxInt64/1000000-rows {
			return o, ErrBudget
		}
		rows += n
		for i, a := range acc {
			c, e := group.Column(i)
			if e != nil {
				return o, safeParquetError(e)
			}
			if e = parquetColumn(ctx, c, n, a, p, b, zones[i]); e != nil {
				return o, e
			}
		}
	}
	if rows != pf.NumRows() {
		return o, ErrArtifactChanged
	}
	// Random access must finish with a sequential verification of this SAME open.
	if _, e = io.CopyBuffer(io.Discard, io.NewSectionReader(v, 0, r.Size()), make([]byte, blockSize)); e != nil {
		return o, e
	}
	if r.Size() != x.member.Size {
		return o, ErrArtifactChanged
	}
	return finish(names, acc, rows), nil
}
func safeParquetError(e error) error {
	if errors.Is(e, ErrArtifactChanged) {
		return ErrArtifactChanged
	}
	if errors.Is(e, ErrTimeout) {
		return ErrTimeout
	}
	return ErrUnsupported
}
func parquetScalar(value any, c *schema.Column, kind string, zone *time.Location) ([]byte, int, float64, error) {
	raw, e := canonical(value)
	num := 0.0
	length := 0
	if kind == "binary" || kind == "string" {
		var v []byte
		switch z := value.(type) {
		case parquet.ByteArray:
			v = []byte(z)
		case parquet.FixedLenByteArray:
			v = []byte(z)
		default:
			return nil, 0, 0, ErrUnsupported
		}
		length = len(v)
		if kind == "binary" {
			raw = append([]byte("bytes:"), v...)
			e = nil
		} else {
			if !utf8.Valid(v) {
				return nil, 0, 0, ErrUnsupported
			}
			raw, e = canonical(string(v))
		}
		return raw, length, 0, e
	}
	integer := func() (int64, bool) {
		switch z := value.(type) {
		case int32:
			return int64(z), true
		case int64:
			return z, true
		}
		return 0, false
	}
	switch kind {
	case "integer":
		n, ok := integer()
		if !ok {
			return nil, 0, 0, ErrUnsupported
		}
		if t, ok := c.LogicalType().(schema.IntLogicalType); ok && !t.IsSigned() {
			u := uint64(n)
			if t.BitWidth() < 64 {
				u &= (uint64(1) << uint(t.BitWidth())) - 1
			}
			raw = []byte(strconv.FormatUint(u, 10))
			num = float64(u)
		} else {
			raw = []byte(strconv.FormatInt(n, 10))
			num = float64(n)
		}
		e = nil
	case "float":
		switch z := value.(type) {
		case float32:
			num = float64(z)
		case float64:
			num = z
		default:
			return nil, 0, 0, ErrUnsupported
		}
		raw, e = canonical(num)
	case "decimal":
		t := c.LogicalType().(schema.DecimalLogicalType)
		var n big.Int
		switch z := value.(type) {
		case int32:
			n.SetInt64(int64(z))
		case int64:
			n.SetInt64(z)
		case parquet.ByteArray:
			n.SetBytes(z)
			if len(z) > 0 && z[0]&128 != 0 {
				n.Sub(&n, new(big.Int).Lsh(big.NewInt(1), uint(len(z)*8)))
			}
		case parquet.FixedLenByteArray:
			n.SetBytes(z)
			if len(z) > 0 && z[0]&128 != 0 {
				n.Sub(&n, new(big.Int).Lsh(big.NewInt(1), uint(len(z)*8)))
			}
		default:
			return nil, 0, 0, ErrUnsupported
		}
		scale := int(t.Scale())
		if scale < 0 || scale > 76 {
			return nil, 0, 0, ErrUnsupported
		}
		sign := ""
		if n.Sign() < 0 {
			sign = "-"
			n.Abs(&n)
		}
		digits := n.String()
		if scale > 0 {
			if len(digits) <= scale {
				digits = strings.Repeat("0", scale+1-len(digits)) + digits
			}
			digits = digits[:len(digits)-scale] + "." + digits[len(digits)-scale:]
		}
		text := sign + digits
		raw = []byte("decimal:" + text)
		num, e = strconv.ParseFloat(text, 64)
	case "date":
		n, ok := integer()
		if !ok {
			return nil, 0, 0, ErrUnsupported
		}
		t := time.Unix(n*86400, 0).UTC()
		if t.Year() < 1 || t.Year() > 9999 {
			return nil, 0, 0, ErrUnsupported
		}
		raw = []byte("time:" + t.Format("2006-01-02"))
		e = nil
	case "datetime":
		n, ok := integer()
		if !ok {
			return nil, 0, 0, ErrUnsupported
		}
		t := c.LogicalType().(schema.TimestampLogicalType)
		unit := int64(1000000)
		switch t.TimeUnit() {
		case schema.TimeUnitMillis:
			unit = 1000
		case schema.TimeUnitNanos:
			unit = 1000000000
		}
		date := time.Unix(n/unit, (n%unit)*(1000000000/unit)).UTC()
		if zone != nil {
			date = date.In(zone)
		}
		if date.Year() < 1 || date.Year() > 9999 {
			return nil, 0, 0, ErrUnsupported
		}
		raw = []byte("time:" + isoPython(date, t.IsAdjustedToUTC(), date.Nanosecond() != 0))
		e = nil
	}
	return raw, length, num, e
}
func parquetColumn(ctx context.Context, c file.ColumnChunkReader, rows int64, a *aggregate, p Policy, b *budget, zone *time.Location) error {
	defs := make([]int16, 1024)
	reps := make([]int16, 1024)
	remaining := rows
	for remaining > 0 {
		if ctx.Err() != nil {
			return ErrTimeout
		}
		n := min(remaining, 1024)
		var total int64
		var count int
		var e error
		values := make([]any, 0, n)
		switch x := c.(type) {
		case *file.Int32ColumnChunkReader:
			v := make([]int32, n)
			total, count, e = x.ReadBatch(n, v, defs, reps)
			for _, z := range v[:count] {
				values = append(values, z)
			}
		case *file.Int64ColumnChunkReader:
			v := make([]int64, n)
			total, count, e = x.ReadBatch(n, v, defs, reps)
			for _, z := range v[:count] {
				values = append(values, z)
			}
		case *file.Float32ColumnChunkReader:
			v := make([]float32, n)
			total, count, e = x.ReadBatch(n, v, defs, reps)
			for _, z := range v[:count] {
				values = append(values, z)
			}
		case *file.Float64ColumnChunkReader:
			v := make([]float64, n)
			total, count, e = x.ReadBatch(n, v, defs, reps)
			for _, z := range v[:count] {
				values = append(values, z)
			}
		case *file.BooleanColumnChunkReader:
			v := make([]bool, n)
			total, count, e = x.ReadBatch(n, v, defs, reps)
			for _, z := range v[:count] {
				values = append(values, z)
			}
		case *file.ByteArrayColumnChunkReader:
			v := make([]parquet.ByteArray, n)
			total, count, e = x.ReadBatch(n, v, defs, reps)
			for _, z := range v[:count] {
				values = append(values, z)
			}
		case *file.FixedLenByteArrayColumnChunkReader:
			v := make([]parquet.FixedLenByteArray, n)
			total, count, e = x.ReadBatch(n, v, defs, reps)
			for _, z := range v[:count] {
				values = append(values, z)
			}
		default:
			return ErrUnsupported
		}
		if e != nil {
			return safeParquetError(e)
		}
		if total <= 0 || total > n {
			return ErrArtifactChanged
		}
		remaining -= total
		vi := 0
		for j := int64(0); j < total; j++ {
			valid := c.Descriptor().MaxDefinitionLevel() == 0 || defs[j] == c.Descriptor().MaxDefinitionLevel()
			if !valid {
				a.nulls++
				continue
			}
			if vi >= len(values) || a.kind == "unknown" {
				return ErrUnsupported
			}
			raw, l, num, e := parquetScalar(values[vi], c.Descriptor(), a.kind, zone)
			vi++
			if e != nil {
				return e
			}
			if e = a.add(raw, l, num, true, p, b); e != nil {
				return e
			}
		}
		if vi != count {
			return ErrArtifactChanged
		}
	}
	if c.HasNext() {
		return ErrArtifactChanged
	}
	return nil
}
