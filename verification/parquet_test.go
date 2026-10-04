package verification

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/inventory"

	"github.com/apache/arrow-go/v18/arrow/memory"
	"github.com/apache/arrow-go/v18/parquet"
	"github.com/apache/arrow-go/v18/parquet/compress"
	"github.com/apache/arrow-go/v18/parquet/file"
	"github.com/apache/arrow-go/v18/parquet/schema"
)

func TestLargeParquetMemory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large.parquet")
	f, e := os.Create(path)
	if e != nil {
		t.Fatal(e)
	}
	node, e := schema.NewPrimitiveNode("n", parquet.Repetitions.Required, parquet.Types.Int64, -1, -1)
	if e != nil {
		t.Fatal(e)
	}
	root, e := schema.NewGroupNode("schema", parquet.Repetitions.Required, schema.FieldList{node}, -1)
	if e != nil {
		t.Fatal(e)
	}
	writer := file.NewParquetWriter(f, root, file.WithWriterProps(parquet.NewWriterProperties(parquet.WithDictionaryDefault(false), parquet.WithDataPageSize(64<<10))))
	values := make([]int64, 20000)
	for i := range values {
		values[i] = int64(i)
	}
	for i := 0; i < 100; i++ {
		group := writer.AppendRowGroup()
		c, e := group.NextColumn()
		if e != nil {
			t.Fatal(e)
		}
		_, e = c.(*file.Int64ColumnChunkWriter).WriteBatch(values, nil, nil)
		if e != nil {
			t.Fatal(e)
		}
		if e = c.Close(); e != nil {
			t.Fatal(e)
		}
		if e = group.Close(); e != nil {
			t.Fatal(e)
		}
	}
	if e = writer.Close(); e != nil {
		t.Fatal(e)
	}
	stream, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.New()
	size, e := io.Copy(h, stream)
	stream.Close()
	if e != nil {
		t.Fatal(e)
	}
	m := Member{Identity: strings.Repeat("1", 32), Size: size, SHA256: [32]byte(h.Sum(nil)), Format: "parquet"}
	downloads := make([][]byte, 8)
	for i := range downloads {
		downloads[i] = make([]byte, inventory.BlockSize)
	}
	runtime.GC()
	var baseline runtime.MemStats
	runtime.ReadMemStats(&baseline)
	done := make(chan struct{})
	peak := make(chan uint64, 1)
	go func() {
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		maxHeap := baseline.HeapAlloc
		for {
			select {
			case <-done:
				peak <- maxHeap
				return
			case <-ticker.C:
				var stat runtime.MemStats
				runtime.ReadMemStats(&stat)
				maxHeap = max(maxHeap, stat.HeapAlloc)
			}
		}
	}()
	got, e := Scan(context.Background(), diskSource{m, path, nil}, testPolicy())
	close(done)
	maxHeap := <-peak
	additional := maxHeap - baseline.HeapAlloc
	runtime.KeepAlive(downloads)
	if e != nil {
		t.Fatal(e)
	}
	if got.Objects[0].Rows != 2000000 {
		t.Fatal("footer-only/truncated traversal")
	}
	t.Logf("parquet: file=%d bytes, 100 row groups, 2,000,000 rows, peak additional heap=%d bytes, delivery buffers=%d bytes, combined peak heap=%d bytes", size, additional, 8*inventory.BlockSize, maxHeap)
	if additional > 128<<20 {
		t.Fatalf("memory ceiling %d", additional)
	}
}

// Track actual Arrow buffer ownership independently of the scanner's budget.
type parquetAllocationProbe struct {
	memory.Allocator
	live, peak int
}

func (a *parquetAllocationProbe) Allocate(n int) []byte {
	a.live += n
	a.peak = max(a.peak, a.live)
	return a.Allocator.Allocate(n)
}
func (a *parquetAllocationProbe) Reallocate(n int, old []byte) []byte {
	a.live += n - len(old)
	a.peak = max(a.peak, a.live)
	return a.Allocator.Reallocate(n, old)
}
func (a *parquetAllocationProbe) Free(v []byte) {
	a.live -= len(v)
	a.Allocator.Free(v)
}

func rowGroupFixture(t *testing.T, groups int, dictionary bool) []byte {
	t.Helper()
	fields := schema.FieldList{}
	for _, spec := range []struct {
		name     string
		physical parquet.Type
		logical  schema.LogicalType
	}{
		{"i", parquet.Types.Int64, schema.NoLogicalType{}},
		{"f", parquet.Types.Double, schema.NoLogicalType{}},
		{"s", parquet.Types.ByteArray, schema.StringLogicalType{}},
		{"d", parquet.Types.Int32, schema.DateLogicalType{}},
		{"b", parquet.Types.Boolean, schema.NoLogicalType{}},
	} {
		node, e := schema.NewPrimitiveNodeLogical(spec.name, parquet.Repetitions.Optional, spec.logical, spec.physical, -1, -1)
		if e != nil {
			t.Fatal(e)
		}
		fields = append(fields, node)
	}
	root, e := schema.NewGroupNode("schema", parquet.Repetitions.Required, fields, -1)
	if e != nil {
		t.Fatal(e)
	}
	var buf bytes.Buffer
	w := file.NewParquetWriter(&buf, root, file.WithWriterProps(parquet.NewWriterProperties(
		parquet.WithDictionaryDefault(dictionary), parquet.WithCompression(compress.Codecs.Snappy), parquet.WithDataPageSize(64<<10))))
	for g := 0; g < groups; g++ {
		n := 12800 / groups
		defs := make([]int16, n)
		var ints []int64
		var floats []float64
		var texts []parquet.ByteArray
		var dates []int32
		var bools []bool
		for j := range defs {
			k := g*n + j
			if k%17 == 0 {
				continue
			}
			defs[j] = 1
			ints = append(ints, int64(k%32))
			floats = append(floats, float64(k%32)/2)
			texts = append(texts, parquet.ByteArray(strings.Repeat("x", k%32)))
			dates = append(dates, int32(k%32))
			bools = append(bools, k%2 == 0)
		}
		rg := w.AppendRowGroup()
		for i := range fields {
			c, e := rg.NextColumn()
			if e != nil {
				t.Fatal(e)
			}
			switch i {
			case 0:
				_, e = c.(*file.Int64ColumnChunkWriter).WriteBatch(ints, defs, nil)
			case 1:
				_, e = c.(*file.Float64ColumnChunkWriter).WriteBatch(floats, defs, nil)
			case 2:
				_, e = c.(*file.ByteArrayColumnChunkWriter).WriteBatch(texts, defs, nil)
			case 3:
				_, e = c.(*file.Int32ColumnChunkWriter).WriteBatch(dates, defs, nil)
			case 4:
				_, e = c.(*file.BooleanColumnChunkWriter).WriteBatch(bools, defs, nil)
			}
			if e != nil {
				t.Fatal(e)
			}
			if e = c.Close(); e != nil {
				t.Fatal(e)
			}
		}
		if e = rg.Close(); e != nil {
			t.Fatal(e)
		}
	}
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	return buf.Bytes()
}

func TestParquetRowGroupBudget(t *testing.T) {
	for _, dictionary := range []bool{false, true} {
		t.Run(strconv.FormatBool(dictionary), func(t *testing.T) {
			var want []byte
			for _, groups := range []int{4, 400} {
				data := rowGroupFixture(t, groups, dictionary)
				if _, e := Scan(context.Background(), sourceFor(data, "parquet"), testPolicy()); e != nil {
					t.Fatal(e)
				}
				p, e := testPolicy().checked()
				if e != nil {
					t.Fatal(e)
				}
				b := &budget{limit: p.MaxMemoryBytes}
				s := sourceFor(data, "parquet")
				x, e := prepare(context.Background(), s, p, b)
				if e != nil {
					t.Fatal(e)
				}
				baseline := b.used
				o, e := parquetObject(context.Background(), s, &x[0], p, b)
				if e != nil {
					t.Fatal(e)
				}
				facts, e := canonical(o)
				if e != nil {
					t.Fatal(e)
				}
				if o.Rows != 12800 {
					t.Fatal(o.Rows)
				}
				// Object facts are grouping-independent. Scan's outer commitments
				// include the file hash, which necessarily differs between encodings.
				if want == nil {
					want = facts
				} else if !bytes.Equal(want, facts) {
					t.Fatalf("grouping changed facts: %s != %s", want, facts)
				}
				probe := &parquetAllocationProbe{Allocator: memory.NewGoAllocator()}
				allocatorBudget := &budget{limit: 128 << 20}
				r, e := file.NewParquetReader(bytes.NewReader(data), file.WithReadProps(parquet.NewReaderProperties(boundedAllocator{allocatorBudget, probe})))
				if e != nil {
					t.Fatal(e)
				}
				defer r.Close()
				for g := 0; g < r.NumRowGroups(); g++ {
					group := r.RowGroup(g)
					for i := 0; i < group.NumColumns(); i++ {
						c, e := group.Column(i)
						if e != nil {
							t.Fatal(e)
						}
						kind, e := parquetKind(c.Descriptor())
						if e != nil {
							t.Fatal(e)
						}
						if e = parquetColumn(context.Background(), c, group.NumRows(), newAggregate(kind, i, p), p, &budget{limit: 128 << 20}, nil); e != nil {
							t.Fatal(e)
						}
						if probe.live != 0 || allocatorBudget.used != 0 {
							t.Fatalf("group %d column %d: Arrow live=%d budget=%d peak=%d", g, i, probe.live, allocatorBudget.used, probe.peak)
						}
					}
				}
				// The early-return path must close the just-opened page reader too.
				c, e := r.RowGroup(0).Column(0)
				if e != nil {
					t.Fatal(e)
				}
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				if e = parquetColumn(ctx, c, r.RowGroup(0).NumRows(), newAggregate("integer", 0, p), p, &budget{limit: 128 << 20}, nil); e != ErrTimeout {
					t.Fatal(e)
				}
				if probe.live != 0 || allocatorBudget.used != 0 {
					t.Fatalf("cancelled column: Arrow live=%d budget=%d", probe.live, allocatorBudget.used)
				}
				t.Logf("%d groups: allocator peak=%d, live=%d, scan retained=%d", groups, probe.peak, probe.live, b.used-baseline)
				// Aggregate/scalar reservations remain; decoder workspace must not.
				if delta := b.used - baseline; delta < 0 || delta > 64<<10 {
					t.Fatalf("%d groups: retained budget %d", groups, delta)
				}
			}
		})
	}
}

type changingRandom struct {
	*bytes.Reader
	data  []byte
	reads int
}

func (r *changingRandom) Close() error { return nil }
func (r *changingRandom) ReadAt(p []byte, off int64) (int, error) {
	r.reads++
	n, e := r.Reader.ReadAt(p, off)
	if r.reads == 1 {
		r.data[4] ^= 1
	}
	return n, e
}
func TestParquetMutationAndAllocationBeforeLimit(t *testing.T) {
	payload := read(t, "testdata/oracle/logical_snappy.parquet")
	src := sourceFor(payload, "parquet")
	src.at = func(id string) RandomAccess { return &changingRandom{bytes.NewReader(src.data[id]), src.data[id], 0} }
	f, e := Scan(context.Background(), src, testPolicy())
	if e != ErrArtifactChanged || f.FingerprintHash != "" {
		t.Fatalf("mutation FAILED_VOIDED: %v", e)
	}
	// A malicious footer length must refuse before metadata allocation.
	payload = read(t, "testdata/oracle/logical_snappy.parquet")
	binary.LittleEndian.PutUint32(payload[len(payload)-8:], 0x7fffffff)
	if _, e = Scan(context.Background(), sourceFor(payload, "parquet"), testPolicy()); e != ErrBudget {
		t.Fatal("footer allocation before cap", e)
	}
	b := &budget{limit: 100}
	a := boundedAllocator{b, nil}
	func() {
		defer func() {
			if recover() != ErrBudget {
				t.Fatal("allocator did not refuse before delegation")
			}
		}()
		a.Allocate(101)
	}()
	// Valid file containing an oversized uncompressed page is rejected by the
	// existing Arrow pre-allocation page cap, even with a matching snapshot hash.
	node, _ := schema.NewPrimitiveNode("s", parquet.Repetitions.Required, parquet.Types.ByteArray, -1, -1)
	root, _ := schema.NewGroupNode("schema", parquet.Repetitions.Required, schema.FieldList{node}, -1)
	var buf bytes.Buffer
	w := file.NewParquetWriter(&buf, root, file.WithWriterProps(parquet.NewWriterProperties(parquet.WithDictionaryDefault(false), parquet.WithDataPageSize(8<<20))))
	group := w.AppendRowGroup()
	c, e := group.NextColumn()
	if e != nil {
		t.Fatal(e)
	}
	_, e = c.(*file.ByteArrayColumnChunkWriter).WriteBatch([]parquet.ByteArray{parquet.ByteArray(bytes.Repeat([]byte{'x'}, 5<<20))}, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	group.Close()
	w.Close()
	if _, e = Scan(context.Background(), sourceFor(buf.Bytes(), "parquet"), testPolicy()); e != ErrBudget {
		t.Fatal("over-limit decoded page must refuse with ErrBudget", e)
	}
}
