package cloudflareverification

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aidotmarket/aim-data-gateway/verification"
)

type fakeBridge struct {
	objects                    map[string][]byte
	requests, heads            []Request
	mutate                     func(*fakeBridge, Request)
	fault, headFault, liveETag string
	closed                     int
}

func (f *fakeBridge) Head(_ context.Context, r Request) (*Head, error) {
	f.heads = append(f.heads, r)
	data, exists := f.objects[r.Key]
	if !exists || f.headFault == "missing" {
		return nil, nil
	}
	if r.IfMatch == "" || r.Range != nil || f.headFault == "permission" {
		return nil, errors.New("refused")
	}
	h := &Head{Size: int64(len(data)), ETag: r.IfMatch}
	if f.headFault == "size" {
		h.Size++
	}
	if f.headFault == "etag" {
		h.ETag = "changed"
	}
	return h, nil
}

type trackedBody struct {
	io.Reader
	close func()
}

func (b trackedBody) Close() error { b.close(); return nil }
func (f *fakeBridge) Get(_ context.Context, r Request) (GetResult, error) {
	f.requests = append(f.requests, r)
	if f.mutate != nil {
		f.mutate(f, r)
	}
	data, exists := f.objects[r.Key]
	if !exists || f.fault == "missing" {
		return GetResult{}, nil
	}
	if r.IfMatch == "" || f.fault == "permission" || f.fault == "retry" && len(f.requests) == 1 {
		return GetResult{}, errors.New("refused")
	}
	h := &Head{Size: int64(len(data)), ETag: r.IfMatch}
	if f.liveETag != "" {
		h.ETag = f.liveETag
	}
	result := GetResult{Metadata: h, Range: r.Range}
	if f.fault == "absent_body" || h.ETag != r.IfMatch {
		return result, nil
	}
	if r.Range != nil {
		if r.Range.Offset < 0 || r.Range.Length < 1 || r.Range.Offset+r.Range.Length > int64(len(data)) {
			return GetResult{}, errors.New("range outside pin")
		}
		data = data[r.Range.Offset : r.Range.Offset+r.Range.Length]
	}
	if f.fault == "size" {
		h.Size++
	}
	if f.fault == "etag" {
		h.ETag = "changed"
	}
	if f.fault == "range" {
		result.Range = &Range{1, 1}
	}
	if f.fault == "short" {
		data = data[:len(data)-1]
	}
	if f.fault == "long" {
		data = append(append([]byte(nil), data...), 7)
	}
	result.Body = trackedBody{bytes.NewReader(data), func() { f.closed++ }}
	return result, nil
}

func policy() verification.Policy {
	return verification.Policy{
		CanonicalizationVersion: "python-json-sort-compact-v1", RowCountAlgorithmVersion: "exact-v1",
		DistinctAlgorithmVersion: "hll-sha256-v1", HistogramVersion: "fixed-buckets-v1", NumericBucketVersion: "fixed-buckets-v1",
		MinimumAggregateOccupancy: 10, LengthBounds: []int{0, 1, 4, 8, 16, 32, 64, 128, 256},
		NumericBoundaries: []float64{-1000, -100, -10, 0, 10, 100, 1000},
		Commitments:       Commitments{Bucket: "fixture", ManifestHash: strings.Repeat("a", 64), Key: [32]byte(bytes.Repeat([]byte{99}, 32))},
	}
}
func fixture(t *testing.T, data []byte, format string) (*Source, *fakeBridge) {
	t.Helper()
	f := &fakeBridge{objects: map[string][]byte{"e\u0301." + format: data}}
	s, err := NewSource(f, "fixture", []Object{{Key: "e\u0301." + format, ETag: "etag", Size: int64(len(data)), Format: format}})
	if err != nil {
		t.Fatal(err)
	}
	return s, f
}

func TestPinnedCacheAndRetry(t *testing.T) {
	data := bytes.Repeat([]byte{7}, CF_VERIFY_PARQUET_READ_AHEAD_BYTES+101)
	s, f := fixture(t, data, "parquet")
	at, err := s.OpenAt(context.Background(), s.Members()[0].Identity)
	if err != nil {
		t.Fatal(err)
	}
	defer at.Close()
	for _, off := range []int64{0, 2, int64(len(data) - 5)} {
		buf := make([]byte, 10)
		n, e := at.ReadAt(buf, off)
		if n != min(10, len(data)-int(off)) || e != nil && e != io.EOF || !bytes.Equal(buf[:n], data[off:off+int64(n)]) {
			t.Fatal(n, e)
		}
	}
	if len(f.requests) != 2 || at.(*reader).BufferedBytes() != CF_VERIFY_PARQUET_READ_AHEAD_BYTES {
		t.Fatal("cache")
	}
	for _, r := range append(f.heads, f.requests...) {
		if r.MemberIndex != 0 || r.Key != "e\u0301.parquet" || r.IfMatch != "etag" || r.Bucket != "fixture" || r.Range != nil && r.Range.Offset+r.Range.Length > int64(len(data)) {
			t.Fatal("raw pin/range", r)
		}
	}
	// A failed refill cannot expose previous/partially filled cache bytes. Each
	// retry sends the same pin and range, and never performs an unconditioned GET.
	f.fault = "short"
	if _, e := at.ReadAt(make([]byte, 1), 0); e != verification.ErrArtifactChanged {
		t.Fatal(e)
	}
	f.fault = ""
	if _, e := at.ReadAt(make([]byte, 1), 0); e != nil {
		t.Fatal(e)
	}
	a, b := f.requests[len(f.requests)-2], f.requests[len(f.requests)-1]
	if !reflect.DeepEqual(a, b) || at.(*reader).cache[0] != 7 {
		t.Fatal("retry changed request")
	}
}

func TestDigestParityMutationAndMemory(t *testing.T) {
	data := []byte("n\n" + strings.Repeat("12\n", 20))
	s, f := fixture(t, data, "csv")
	absent, e := verification.Scan(context.Background(), s, policy())
	if e != nil {
		t.Fatal(e)
	}
	if len(f.requests) != 2 {
		t.Fatal("extra hashing traversal")
	}
	s.members[0].DigestPresent, s.members[0].SHA256 = true, sha256.Sum256(data)
	present, e := verification.Scan(context.Background(), s, policy())
	if e != nil || !reflect.DeepEqual(absent, present) {
		t.Fatal("first-pass equality", e)
	}
	s.members[0].SHA256[0] ^= 1
	if facts, e := verification.Scan(context.Background(), s, policy()); e != verification.ErrArtifactChanged || !reflect.DeepEqual(facts, verification.Facts{}) {
		t.Fatal("first-pass digest", e)
	}
	parquetData, e := os.ReadFile("../../verification/testdata/oracle/all_approved_types.parquet")
	if e != nil {
		t.Fatal(e)
	}
	ps, _ := fixture(t, parquetData, "parquet")
	p := policy()
	var peak int64
	p.MemoryPeak = &peak
	if _, e := verification.Scan(context.Background(), ps, p); e != nil || peak > 128<<20 {
		t.Fatal("128 MiB", peak, e)
	}
	p.MaxMemoryBytes = 4*16<<20 + 4*32768 + 4<<20 + int64(len(parquetData)) - 1
	if _, e := verification.Scan(context.Background(), ps, p); e != verification.ErrBudget {
		t.Fatal("buffer reservation", e)
	}
	p = policy()
	p.MaxFactBytes = 1
	s.members[0].SHA256 = sha256.Sum256(data)
	if facts, e := verification.Scan(context.Background(), s, p); e != verification.ErrBudget || len(facts.Objects) != 0 {
		t.Fatal("report budget", e)
	}
}

func TestRangeConcurrencyAndCancellation(t *testing.T) {
	s, _ := fixture(t, bytes.Repeat([]byte{3}, 100), "parquet")
	ctx, cancel := context.WithCancel(context.Background())
	at, e := s.OpenAt(ctx, s.members[0].Identity)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = at.ReadAt(make([]byte, 1), -1); e != verification.ErrArtifactChanged {
		t.Fatal(e)
	}
	if n, e := at.ReadAt(make([]byte, 101), 0); n != 100 || e != io.EOF {
		t.Fatal(n, e)
	}
	cancel()
	if _, e = at.ReadAt(make([]byte, 1), 0); e != context.Canceled {
		t.Fatal("cancel cached read", e)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			for j := 0; j < 20; j++ {
				_, _ = at.ReadAt(make([]byte, 1), 0)
			}
		})
	}
	wg.Go(func() { _ = at.Close() })
	wg.Wait()
	if at.(*reader).cache != nil {
		t.Fatal("cache retained")
	}
	if _, e = at.ReadAt(make([]byte, 1), 0); e != verification.ErrArtifactChanged {
		t.Fatal(e)
	}
}

type blockingBridge struct {
	body    *io.PipeReader
	entered chan struct{}
}

func (b blockingBridge) Head(context.Context, Request) (*Head, error) {
	return &Head{Size: 100, ETag: "etag"}, nil
}
func (b blockingBridge) Get(_ context.Context, r Request) (GetResult, error) {
	close(b.entered)
	return GetResult{Metadata: &Head{Size: 100, ETag: "etag"}, Range: r.Range, Body: b.body}, nil
}
func TestRangeCancellationInterruptsBody(t *testing.T) {
	body, writer := io.Pipe()
	defer writer.Close()
	b := blockingBridge{body: body, entered: make(chan struct{})}
	s, e := NewSource(b, "fixture", []Object{{Key: "a.parquet", ETag: "etag", Size: 100, Format: "parquet"}})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	at, e := s.OpenAt(ctx, s.members[0].Identity)
	if e != nil {
		t.Fatal(e)
	}
	defer at.Close()
	done := make(chan error, 1)
	go func() { _, e := at.ReadAt(make([]byte, 1), 0); done <- e }()
	select {
	case <-b.entered:
	case <-time.After(time.Second):
		t.Fatal("bridge did not start")
	}
	cancel()
	select {
	case e := <-done:
		if e != verification.ErrArtifactChanged {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("body not interrupted")
	}
}
