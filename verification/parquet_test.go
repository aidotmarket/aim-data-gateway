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
	"strings"
	"testing"
	"time"

	"github.com/apache/arrow-go/v18/parquet"
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
	m := Member{strings.Repeat("1", 64), size, [32]byte(h.Sum(nil)), "parquet"}
	downloads := make([][]byte, 8)
	for i := range downloads {
		downloads[i] = make([]byte, 64<<10)
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
	additional := (<-peak) - baseline.HeapAlloc
	runtime.KeepAlive(downloads)
	if e != nil {
		t.Fatal(e)
	}
	if got.Objects[0].Rows != 2000000 {
		t.Fatal("footer-only/truncated traversal")
	}
	t.Logf("parquet: file=%d bytes, 100 row groups, 2,000,000 rows, peak additional heap=%d bytes, eight download buffers live", size, additional)
	if additional > 128<<20 {
		t.Fatalf("memory ceiling %d", additional)
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
	if _, e = Scan(context.Background(), sourceFor(buf.Bytes(), "parquet"), testPolicy()); e == nil {
		t.Fatal("over-limit decoded page accepted")
	}
}
