// Package generate writes deterministic synthetic data only.
package generate

import (
	"bufio"
	"fmt"
	"github.com/apache/arrow-go/v18/parquet"
	"github.com/apache/arrow-go/v18/parquet/compress"
	"github.com/apache/arrow-go/v18/parquet/file"
	"github.com/apache/arrow-go/v18/parquet/schema"
	"io"
	"math/rand"
	"strings"
	"time"
)

func CSV(w io.Writer, size int64, seed int64) error {
	const header = "id,amount,label,date,active\n"
	if size < 128 {
		return fmt.Errorf("CSV size must be at least 128 bytes")
	}
	bw := bufio.NewWriterSize(w, 64<<10)
	if _, err := bw.WriteString(header); err != nil {
		return err
	}
	remaining := size - int64(len(header))
	r := rand.New(rand.NewSource(seed))
	for i := int64(0); remaining > 0; i++ {
		row := fmt.Sprintf("%d,%.4f,synthetic-%08x,%s,%t\n", i, r.Float64()*2000-1000, r.Uint32(), time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, int(i%1000)).Format("2006-01-02"), i%2 == 0)
		// Leave a valid final row; extend its string column to the exact target size.
		if remaining-int64(len(row)) < 128 {
			base := "0,0.5000,,2020-01-01,true\n"
			pad := remaining - int64(len(base))
			if pad < 0 {
				return fmt.Errorf("internal final row size")
			}
			row = "0,0.5000," + strings.Repeat("x", int(pad)) + ",2020-01-01,true\n"
		}
		if _, err := bw.WriteString(row); err != nil {
			return err
		}
		remaining -= int64(len(row))
	}
	return bw.Flush()
}
func Parquet(w io.Writer, rows int64, seed int64) error {
	if rows < 1 {
		return fmt.Errorf("rows must be positive")
	}
	required := parquet.Repetitions.Required
	n, e := schema.NewPrimitiveNode("id", required, parquet.Types.Int64, -1, -1)
	if e != nil {
		return e
	}
	f, e := schema.NewPrimitiveNode("amount", required, parquet.Types.Double, -1, -1)
	if e != nil {
		return e
	}
	s, e := schema.NewPrimitiveNodeLogical("label", required, schema.StringLogicalType{}, parquet.Types.ByteArray, -1, -1)
	if e != nil {
		return e
	}
	d, e := schema.NewPrimitiveNodeLogical("date", required, schema.DateLogicalType{}, parquet.Types.Int32, -1, -1)
	if e != nil {
		return e
	}
	b, e := schema.NewPrimitiveNode("active", required, parquet.Types.Boolean, -1, -1)
	if e != nil {
		return e
	}
	root, e := schema.NewGroupNode("schema", required, schema.FieldList{n, f, s, d, b}, -1)
	if e != nil {
		return e
	}
	writer := file.NewParquetWriter(writerOnly{w}, root, file.WithWriterProps(parquet.NewWriterProperties(parquet.WithCompression(compress.Codecs.Snappy), parquet.WithDictionaryDefault(false), parquet.WithDataPageSize(64<<10))))
	r := rand.New(rand.NewSource(seed))
	for start := int64(0); start < rows; start += 50000 {
		count := int(min(int64(50000), rows-start))
		ints := make([]int64, count)
		floats := make([]float64, count)
		labels := make([]parquet.ByteArray, count)
		dates := make([]int32, count)
		bools := make([]bool, count)
		for i := range ints {
			ints[i] = start + int64(i)
			floats[i] = r.Float64()*2000 - 1000
			labels[i] = parquet.ByteArray(fmt.Sprintf("synthetic-%08x", r.Uint32()))
			dates[i] = 18262 + int32(ints[i]%1000)
			bools[i] = ints[i]%2 == 0
		}
		group := writer.AppendRowGroup()
		for j := 0; j < 5; j++ {
			c, err := group.NextColumn()
			if err != nil {
				return err
			}
			switch j {
			case 0:
				_, err = c.(*file.Int64ColumnChunkWriter).WriteBatch(ints, nil, nil)
			case 1:
				_, err = c.(*file.Float64ColumnChunkWriter).WriteBatch(floats, nil, nil)
			case 2:
				_, err = c.(*file.ByteArrayColumnChunkWriter).WriteBatch(labels, nil, nil)
			case 3:
				_, err = c.(*file.Int32ColumnChunkWriter).WriteBatch(dates, nil, nil)
			case 4:
				_, err = c.(*file.BooleanColumnChunkWriter).WriteBatch(bools, nil, nil)
			}
			if err != nil {
				return err
			}
			if err = c.Close(); err != nil {
				return err
			}
		}
		if err := group.Close(); err != nil {
			return err
		}
	}
	return writer.Close()
}

// Arrow closes a WriteCloser; leave ownership of the supplied writer with the caller.
type writerOnly struct{ io.Writer }
