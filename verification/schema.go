package verification

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"github.com/apache/arrow-go/v18/arrow/memory"
	"github.com/apache/arrow-go/v18/parquet"
	"github.com/apache/arrow-go/v18/parquet/file"
	"github.com/apache/arrow-go/v18/parquet/schema"
)

// DiscoverSchema uses the fact scanner's parsers without inference or aggregation.
// JSONL visits all records so late keys are included, in first-seen order. Memory,
// records, footer decoding and elapsed time have the scanner's hard upper bounds.
// The caller owns and closes r, and applies eligibility before computing facts.
func DiscoverSchema(ctx context.Context, r RandomAccess, format string) (names []string, err error) {
	if ctx.Err() != nil {
		return nil, ErrTimeout
	}
	if !supported(format) {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { r.Close() })
	defer stop()
	defer func() {
		if recover() != nil {
			names, err = nil, ErrBudget
		}
	}()
	p := Policy{MaxColumns: 1000, MaxRecordBytes: 16 << 20, MaxScalarBytes: 16 << 20}
	var magic [4]byte
	if n, _ := r.ReadAt(magic[:], 0); n == 4 && string(magic[:2]) == "PK" {
		return nil, nil
	}
	if format == "parquet" {
		if r.Size() < 12 {
			return nil, ErrUnsupported
		}
		var tail [8]byte
		if _, e := r.ReadAt(tail[:], r.Size()-8); e != nil {
			return nil, e
		}
		footer := int64(binary.LittleEndian.Uint32(tail[:4]))
		if string(tail[4:]) != "PAR1" || footer > 1<<20 || footer > r.Size()-12 {
			return nil, ErrBudget
		}
		b := &budget{limit: 128 << 20}
		props := parquet.NewReaderProperties(boundedAllocator{b, memory.NewGoAllocator()})
		pf, e := file.NewParquetReader(io.NewSectionReader(r, 0, r.Size()), file.WithReadProps(props))
		if e != nil {
			return nil, safeParquetError(e)
		}
		defer pf.Close()
		return parquetNames(pf.MetaData().Schema, p)
	}
	endHeader := errors.New("schema_header_complete")
	seen := map[string]bool{}
	e := walkText(ctx, bufio.NewReaderSize(io.NewSectionReader(r, 0, r.Size()), blockSize), format, p, func(ns []string, _ []cell, _ int64) error {
		for _, n := range ns {
			if !seen[n] {
				if len(names) >= p.MaxColumns {
					return ErrBudget
				}
				seen[n] = true
				names = append(names, n)
			}
		}
		if format != "jsonl" {
			return endHeader
		}
		return nil
	})
	if e != nil && !errors.Is(e, endHeader) {
		return nil, e
	}
	return names, nameOK(names, p)
}

func parquetNames(sch *schema.Schema, p Policy) ([]string, error) {
	if sch.NumColumns() > p.MaxColumns || sch.NumColumns() == 0 || sch.Root().NumFields() != sch.NumColumns() {
		return nil, ErrUnsupported
	}
	names := make([]string, sch.NumColumns())
	for i := range names {
		if _, ok := sch.Root().Field(i).(*schema.PrimitiveNode); !ok {
			return nil, ErrUnsupported
		}
		names[i] = sch.Column(i).Name()
	}
	return names, nameOK(names, p)
}
