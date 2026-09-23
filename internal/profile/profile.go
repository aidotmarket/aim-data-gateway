package profile

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
	"sort"
	"strconv"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/config"
	"github.com/aidotmarket/aim-data-gateway/internal/inventory"
	"github.com/apache/arrow-go/v18/parquet"
	"github.com/apache/arrow-go/v18/parquet/file"
	"github.com/apache/arrow-go/v18/parquet/schema"
)

type Column struct {
	Name           string `json:"name"`
	Type           string `json:"type"`
	NullRatePct    *int   `json:"null_rate_pct"`
	DistinctBucket string `json:"distinct_bucket"`
}
type Description struct {
	SHA256   string   `json:"sha256"`
	RowCount int64    `json:"row_count"`
	Columns  []Column `json:"columns"`
}
type accumulator struct {
	name, kind string
	nulls      int64
	seen       int
	hll        [1 << 14]uint8
}

func (a *accumulator) add(v string, valid bool) {
	if !valid {
		a.nulls++
		return
	}
	a.hllAdd(v)
	if a.seen < 10000 {
		a.seen++
		t := infer(v)
		if a.kind == "" {
			a.kind = t
		} else if a.kind != t {
			if (a.kind == "integer" && t == "float") || (a.kind == "float" && t == "integer") {
				a.kind = "float"
			} else {
				a.kind = "string"
			}
		}
	}
}
func infer(v string) string {
	if v == "true" || v == "false" {
		return "boolean"
	}
	if _, e := strconv.ParseInt(v, 10, 64); e == nil {
		return "integer"
	}
	if _, e := strconv.ParseFloat(v, 64); e == nil {
		return "float"
	}
	if _, e := time.Parse("2006-01-02", v); e == nil {
		return "date"
	}
	if _, e := time.Parse(time.RFC3339Nano, v); e == nil {
		return "timestamp"
	}
	return "string"
}
func (a *accumulator) hllAdd(s string) {
	h := sha256.Sum256([]byte(s))
	v := binary.BigEndian.Uint64(h[:8])
	idx := v >> (64 - 14)
	rank := bits.LeadingZeros64(v<<14) + 1
	if rank > 51 {
		rank = 51
	}
	if a.hll[idx] < uint8(rank) {
		a.hll[idx] = uint8(rank)
	}
}
func (a *accumulator) bucket() string {
	const m = 1 << 14
	sum := 0.0
	zeros := 0
	for _, v := range a.hll {
		sum += math.Ldexp(1, -int(v))
		if v == 0 {
			zeros++
		}
	}
	n := 0.7213 / (1 + 1.079/float64(m)) * float64(m*m) / sum
	if n <= 2.5*m && zeros > 0 {
		n = float64(m) * math.Log(float64(m)/float64(zeros))
	}
	switch {
	case n <= 1.5:
		return "1"
	case n <= 10.5:
		return "2-10"
	case n <= 100.5:
		return "11-100"
	case n <= 1000.5:
		return "101-1000"
	default:
		return ">1000"
	}
}
func NullRate(nulls, rows int64) *int {
	if rows == 0 {
		return nil
	}
	v := int(5 * ((40*nulls + rows) / (2 * rows)))
	return &v
}
func describe(acc []*accumulator, rows int64, rule config.Columns, sha string) Description {
	d := Description{SHA256: sha, RowCount: rows, Columns: make([]Column, 0, len(acc))}
	drop := map[string]bool{}
	for _, name := range rule.Drop {
		drop[name] = true
	}
	for _, a := range acc {
		if a == nil {
			continue
		}
		if drop[a.name] {
			continue
		}
		name := a.name
		if x := rule.Rename[name]; x != "" {
			name = x
		}
		kind := a.kind
		if kind == "" {
			kind = "string"
		}
		d.Columns = append(d.Columns, Column{name, kind, NullRate(a.nulls, rows), a.bucket()})
	}
	return d
}
func File(r inventory.Record, rule config.Columns) (Description, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	return FileContext(ctx, r, rule)
}
func FileContext(ctx context.Context, r inventory.Record, rule config.Columns) (Description, error) {
	if e := checkDeadline(ctx); e != nil {
		return Description{}, e
	}
	sha := hex.EncodeToString(r.SHA256[:])
	switch r.Phase1.MediaType {
	case "text/csv", "text/tab-separated-values":
		return delimited(ctx, r, rule, sha)
	case "application/x-ndjson":
		return jsonLines(ctx, r, rule, sha)
	case "application/vnd.apache.parquet":
		return parquetFile(ctx, r, rule, sha)
	default:
		return Description{}, errors.New("unsupported_format")
	}
}
func checkDeadline(ctx context.Context) error {
	if ctx.Err() != nil {
		return errors.New("gateway_timeout")
	}
	return nil
}
func delimited(ctx context.Context, r inventory.Record, rule config.Columns, sha string) (Description, error) {
	f, e := r.Open()
	if e != nil {
		return Description{}, e
	}
	defer f.Close()
	stop := context.AfterFunc(ctx, func() { f.Close() })
	defer stop()
	cr := csv.NewReader(f)
	if r.Phase1.MediaType == "text/tab-separated-values" {
		cr.Comma = '\t'
	}
	cr.FieldsPerRecord = -1
	names, e := cr.Read()
	if e != nil {
		return Description{}, e
	}
	acc := make([]*accumulator, len(names))
	for i, n := range names {
		if !dropped(rule, n) {
			acc[i] = &accumulator{name: n}
		}
	}
	var rows int64
	for {
		if e := checkDeadline(ctx); e != nil {
			return Description{}, e
		}
		values, e := cr.Read()
		if e == io.EOF {
			break
		}
		if e != nil {
			if timeout := checkDeadline(ctx); timeout != nil {
				return Description{}, timeout
			}
			return Description{}, e
		}
		rows++
		for i, a := range acc {
			if a == nil {
				continue
			}
			v := ""
			if i < len(values) {
				v = values[i]
			}
			a.add(v, v != "")
		}
	}
	return describe(acc, rows, rule, sha), nil
}
func jsonLines(ctx context.Context, r inventory.Record, rule config.Columns, sha string) (Description, error) {
	f, e := r.Open()
	if e != nil {
		return Description{}, e
	}
	defer f.Close()
	stop := context.AfterFunc(ctx, func() { f.Close() })
	defer stop()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 16<<20)
	acc := map[string]*accumulator{}
	order := []string{}
	var rows int64
	for sc.Scan() {
		if e := checkDeadline(ctx); e != nil {
			return Description{}, e
		}
		var obj map[string]json.RawMessage
		if e := json.Unmarshal(sc.Bytes(), &obj); e != nil {
			return Description{}, e
		}
		rows++
		for k, v := range obj {
			if dropped(rule, k) {
				continue
			}
			a := acc[k]
			if a == nil {
				if len(acc) >= 1000 {
					return Description{}, errors.New("too many columns")
				}
				a = &accumulator{name: k, nulls: rows - 1}
				acc[k] = a
				order = append(order, k)
			}
			if string(v) == "null" {
				a.add("", false)
			} else {
				var s string
				if e := json.Unmarshal(v, &s); e != nil {
					s = string(v)
				}
				a.add(s, true)
			}
		}
		for k, a := range acc {
			if _, ok := obj[k]; !ok {
				a.add("", false)
			}
		}
	}
	if e := sc.Err(); e != nil {
		if timeout := checkDeadline(ctx); timeout != nil {
			return Description{}, timeout
		}
		return Description{}, e
	}
	cols := make([]*accumulator, 0, len(order))
	sort.Strings(order)
	for _, k := range order {
		cols = append(cols, acc[k])
	}
	return describe(cols, rows, rule, sha), nil
}
func parquetFile(ctx context.Context, r inventory.Record, rule config.Columns, sha string) (Description, error) {
	f, e := r.Open()
	if e != nil {
		return Description{}, e
	}
	defer f.Close()
	stop := context.AfterFunc(ctx, func() { f.Close() })
	defer stop()
	pf, e := file.NewParquetReader(f)
	if e != nil {
		return Description{}, e
	}
	defer pf.Close()
	sch := pf.MetaData().Schema
	rows := pf.NumRows()
	acc := make([]*accumulator, sch.NumColumns())
	for i := range acc {
		if dropped(rule, sch.Column(i).Name()) {
			continue
		}
		kind := parquetType(sch.Column(i).PhysicalType())
		switch sch.Column(i).LogicalType().(type) {
		case schema.DateLogicalType:
			kind = "date"
		case schema.TimestampLogicalType:
			kind = "timestamp"
		}
		acc[i] = &accumulator{name: sch.Column(i).Name(), kind: kind}
	}
	for rg := 0; rg < pf.NumRowGroups(); rg++ {
		if e := checkDeadline(ctx); e != nil {
			return Description{}, e
		}
		group := pf.RowGroup(rg)
		for i, a := range acc {
			if a == nil {
				continue
			}
			col, e := group.Column(i)
			if e != nil {
				return Description{}, e
			}
			if e := readParquetColumn(ctx, col, group.NumRows(), a); e != nil {
				return Description{}, fmt.Errorf("parquet column %d: %w", i, e)
			}
		}
	}
	// ReadBatch supplies definition levels. Footer null counts are preferred when complete.
	for i, a := range acc {
		if a == nil {
			continue
		}
		var count int64
		all := true
		for rg := 0; rg < pf.NumRowGroups(); rg++ {
			m, e := pf.RowGroup(rg).MetaData().ColumnChunk(i)
			if e != nil {
				return Description{}, e
			}
			s, e := m.Statistics()
			if e != nil || s == nil || !s.HasNullCount() {
				all = false
				break
			}
			count += s.NullCount()
		}
		if all {
			a.nulls = count
		}
	}
	return describe(acc, rows, rule, sha), nil
}
func dropped(rule config.Columns, name string) bool {
	for _, n := range rule.Drop {
		if n == name {
			return true
		}
	}
	return false
}
func parquetType(t parquet.Type) string {
	switch t {
	case parquet.Types.Int32, parquet.Types.Int64:
		return "integer"
	case parquet.Types.Float, parquet.Types.Double:
		return "float"
	case parquet.Types.Boolean:
		return "boolean"
	default:
		return "string"
	}
}
func readParquetColumn(ctx context.Context, c file.ColumnChunkReader, rows int64, a *accumulator) error {
	// Flat columns have at most one value per row; nested columns are rejected until a flattening rule is specified.
	if c.Descriptor().MaxRepetitionLevel() > 0 {
		return errors.New("nested parquet column unsupported")
	}
	defs := make([]int16, 1024)
	reps := make([]int16, 1024)
	remaining := rows
	for remaining > 0 {
		if e := checkDeadline(ctx); e != nil {
			return e
		}
		n := min(remaining, 1024)
		var total int64
		var read int
		var e error
		values := make([]string, 0, n)
		switch x := c.(type) {
		case *file.Int32ColumnChunkReader:
			v := make([]int32, n)
			total, read, e = x.ReadBatch(n, v, defs, reps)
			for _, z := range v[:read] {
				values = append(values, strconv.FormatInt(int64(z), 10))
			}
		case *file.Int64ColumnChunkReader:
			v := make([]int64, n)
			total, read, e = x.ReadBatch(n, v, defs, reps)
			for _, z := range v[:read] {
				values = append(values, strconv.FormatInt(z, 10))
			}
		case *file.Float32ColumnChunkReader:
			v := make([]float32, n)
			total, read, e = x.ReadBatch(n, v, defs, reps)
			for _, z := range v[:read] {
				values = append(values, strconv.FormatFloat(float64(z), 'g', -1, 32))
			}
		case *file.Float64ColumnChunkReader:
			v := make([]float64, n)
			total, read, e = x.ReadBatch(n, v, defs, reps)
			for _, z := range v[:read] {
				values = append(values, strconv.FormatFloat(z, 'g', -1, 64))
			}
		case *file.BooleanColumnChunkReader:
			v := make([]bool, n)
			total, read, e = x.ReadBatch(n, v, defs, reps)
			for _, z := range v[:read] {
				values = append(values, strconv.FormatBool(z))
			}
		case *file.ByteArrayColumnChunkReader:
			v := make([]parquet.ByteArray, n)
			total, read, e = x.ReadBatch(n, v, defs, reps)
			for _, z := range v[:read] {
				values = append(values, string(z))
			}
		case *file.FixedLenByteArrayColumnChunkReader:
			v := make([]parquet.FixedLenByteArray, n)
			total, read, e = x.ReadBatch(n, v, defs, reps)
			for _, z := range v[:read] {
				values = append(values, string(z))
			}
		default:
			return errors.New("unsupported parquet physical type")
		}
		if e != nil {
			return e
		}
		if total == 0 {
			return io.ErrUnexpectedEOF
		}
		remaining -= total
		vi := 0
		for j := int64(0); j < total; j++ {
			valid := c.Descriptor().MaxDefinitionLevel() == 0 || defs[j] == c.Descriptor().MaxDefinitionLevel()
			if valid {
				a.hllAdd(values[vi])
				vi++
			} else {
				a.nulls++
			}
		}
	}
	return nil
}
