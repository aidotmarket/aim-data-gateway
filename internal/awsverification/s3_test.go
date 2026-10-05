package awsverification

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aidotmarket/aim-data-gateway/verification"
	"github.com/apache/arrow-go/v18/parquet"
	"github.com/apache/arrow-go/v18/parquet/file"
	"github.com/apache/arrow-go/v18/parquet/schema"
)

type fakeS3 struct {
	objects      map[string][]byte
	requests     []Request
	heads        []Request
	bytes        int64
	mutate       func(*fakeS3, Request)
	fail         bool
	latency      time.Duration
	headOverride *Head
	liveETag     string
	versions     map[string][]byte
}

func (f *fakeS3) Head(_ context.Context, r Request) (Head, error) {
	f.heads = append(f.heads, r)
	if f.headOverride != nil {
		return *f.headOverride, nil
	}
	if r.VersionID == "" && r.IfMatch == "" {
		return Head{}, errors.New("unpinned")
	}
	return Head{int64(len(f.objects[r.Key])), r.VersionID, strings.Trim(r.IfMatch, "\"")}, nil
}
func (f *fakeS3) Get(ctx context.Context, r Request) (io.ReadCloser, error) {
	f.requests = append(f.requests, r)
	if f.mutate != nil {
		f.mutate(f, r)
	}
	if f.fail || r.VersionID == "" && r.IfMatch == "" {
		return nil, errors.New("precondition")
	}
	if f.latency > 0 {
		select {
		case <-time.After(f.latency):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	data := f.objects[r.Key]
	if r.VersionID != "" && f.versions != nil {
		data = f.versions[r.VersionID]
	}
	if r.VersionID == "" && f.liveETag != "" && r.IfMatch != "\""+f.liveETag+"\"" {
		return nil, errors.New("412")
	}
	if r.End >= 0 {
		if r.Start < 0 || r.End >= int64(len(data)) || r.End < r.Start {
			return nil, errors.New("range past length")
		}
		data = data[r.Start : r.End+1]
	}
	f.bytes += int64(len(data))
	return io.NopCloser(bytes.NewReader(data)), nil
}
func policy() verification.Policy {
	return verification.Policy{
		CanonicalizationVersion:   "python-json-sort-compact-v1",
		RowCountAlgorithmVersion:  "exact-v1",
		DistinctAlgorithmVersion:  "hll-sha256-v1",
		HistogramVersion:          "fixed-buckets-v1",
		NumericBucketVersion:      "fixed-buckets-v1",
		MinimumAggregateOccupancy: 10,
		LengthBounds: []int{
			0,
			1,
			4,
			8,
			16,
			32,
			64,
			128,
			256,
		},
		NumericBoundaries: []float64{
			-1000,
			-100,
			-10,
			0,
			10,
			100,
			1000,
		},
		Commitments: Commitments{Bucket: "fixture", ManifestHash: strings.Repeat("a", 64), Key: [32]byte(bytes.Repeat([]byte{99}, 32))},
	}
}
func fixture(t *testing.T, data []byte, format string) (*Source, *fakeS3) {
	t.Helper()
	f := &fakeS3{objects: map[string][]byte{"e\u0301." + format: data}}
	s, err := NewSource(f, "fixture", []Object{{
		Key:    "e\u0301." + format,
		ETag:   "etag",
		Size:   int64(len(data)),
		Format: format,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return s, f
}
func TestIdentityAndAdmission(t *testing.T) {
	a, _ := Identity("e\u0301", "v\u0301")
	b, _ := Identity("é", "v\u0301")
	if a != b {
		t.Fatal("NFC")
	}
	for _, pair := range [][2]string{
		{"", "pin"},
		{"key", ""},
		{"a\x00b", "pin"},
		{"key", "p\x00in"},
		{"\xff", "pin"},
	} {
		if _, err := Identity(pair[0], pair[1]); err == nil {
			t.Fatal(pair)
		}
	}
	for _, objects := range [][]Object{
		{{Key: "é", ETag: "pin"}, {Key: "e\u0301", ETag: "pin"}},
		{{Key: "a", ETag: "pin"}, {Key: "a", ETag: "pin"}},
		{{Key: "z", ETag: "pin"}, {Key: "a", ETag: "pin"}},
		{{Key: "a", Size: 1}},
	} {
		f := &fakeS3{}
		if _, err := NewSource(f, "fixture", objects); err == nil || len(f.heads) != 0 {
			t.Fatal("pre-open refusal", objects)
		}
	}
}
func TestPinnedRangeCache(t *testing.T) {
	for _, version := range []string{"", "v1"} {
		data := bytes.Repeat([]byte{7}, AWS_VERIFY_PARQUET_READ_AHEAD_BYTES+101)
		s, f := fixture(t, data, "parquet")
		o := s.objects[s.members[0].Identity]
		o.VersionID = version
		s.objects[s.members[0].Identity] = o
		at, err := s.OpenAt(context.Background(), s.members[0].Identity)
		if err != nil {
			t.Fatal(err)
		}
		r := at.(*reader)
		for _, off := range []int64{0, 2, int64(len(data) - 5)} {
			buf := make([]byte, 10)
			n, e := r.ReadAt(buf, off)
			want := min(10, len(data)-int(off))
			if n != want || e != nil && e != io.EOF || !bytes.Equal(buf[:n], data[off:off+int64(n)]) {
				t.Fatal(n, e)
			}
		}
		if len(f.requests) != 2 || r.BufferedBytes() != AWS_VERIFY_PARQUET_READ_AHEAD_BYTES {
			t.Fatal("cache", len(f.requests))
		}
		for _, req := range append(f.heads, f.requests...) {
			if req.Key != "e\u0301.parquet" || req.VersionID != version || version == "" && req.IfMatch != "\"etag\"" || version != "" && req.IfMatch != "" {
				t.Fatal(req)
			}
		}
		if err = r.Close(); err != nil || r.cache != nil {
			t.Fatal("release")
		}
		r.Close()
		if _, err = r.ReadAt(make([]byte, 1), 0); err == nil {
			t.Fatal("read after close")
		}
	}
}
func TestDigestParityMutationAndBudget(t *testing.T) {
	data := []byte("n\n" + strings.Repeat("12\n", 20))
	s, f := fixture(t, data, "csv")
	absent, err := verification.Scan(context.Background(), s, policy())
	if err != nil {
		t.Fatal(err)
	}
	if len(f.requests) != 2 {
		t.Fatal("extra hash traversal", len(f.requests))
	}
	s.members[0].DigestPresent = true
	s.members[0].SHA256 = sha256.Sum256(data)
	present, err := verification.Scan(context.Background(), s, policy())
	if err != nil || !reflect.DeepEqual(absent, present) {
		t.Fatal("digest parity", err)
	}
	s.members[0].SHA256[0] ^= 1
	if facts, e := verification.Scan(context.Background(), s, policy()); e != verification.ErrArtifactChanged || len(facts.Objects) != 0 {
		t.Fatal("supplied digest", e)
	}
	s.members[0].DigestPresent = false
	f.requests = nil
	f.mutate = func(f *fakeS3, _ Request) {
		if len(f.requests) == 2 {
			f.objects["e\u0301.csv"] = bytes.ReplaceAll(data, []byte("12"), []byte("13"))
		}
	}
	if facts, e := verification.Scan(context.Background(), s, policy()); e != verification.ErrArtifactChanged || len(facts.Objects) != 0 {
		t.Fatal("second pass", e)
	}
	parquetData, e := os.ReadFile("../../verification/testdata/oracle/all_approved_types.parquet")
	if e != nil {
		t.Fatal(e)
	}
	ps, _ := fixture(t, parquetData, "parquet")
	p := policy()
	var peak int64
	p.MemoryPeak = &peak
	if _, err = verification.Scan(context.Background(), ps, p); err != nil {
		t.Fatal(err)
	}
	p.MaxMemoryBytes = 4*16<<20 + 4*32768 + 4<<20 + int64(len(parquetData)) - 1
	if _, err = verification.Scan(context.Background(), ps, p); err != verification.ErrBudget {
		t.Fatal("buffer+Arrow budget", peak, err)
	}
}
func TestHeadAndGetRefusals(t *testing.T) {
	s, f := fixture(t, []byte("n\n12\n"), "csv")
	id := s.members[0].Identity
	f.objects["e\u0301.csv"] = []byte("x")
	if _, e := s.Open(context.Background(), id); e == nil {
		t.Fatal("HEAD size")
	}
	f.objects["e\u0301.csv"] = []byte("n\n12\n")
	f.fail = true
	if _, e := s.Open(context.Background(), id); e == nil {
		t.Fatal("GET failed")
	}
	at, e := s.OpenAt(context.Background(), id)
	if e != nil {
		t.Fatal(e)
	}
	defer at.Close()
	if _, e = at.ReadAt(make([]byte, 1), 0); e != verification.ErrArtifactChanged {
		t.Fatal("range failure", e)
	}
	f.fail = false
	if _, e = at.ReadAt(make([]byte, 1), 0); e != nil {
		t.Fatal("same pinned retry", e)
	}
}

func TestProviderPinMutation(t *testing.T) {
	data := []byte("n\n" + strings.Repeat("12\n", 20))
	for _, version := range []string{"", "v1", "null"} {
		s, f := fixture(t, data, "csv")
		o := s.objects[s.members[0].Identity]
		o.VersionID = version
		var e error
		s, e = NewSource(f, "fixture", []Object{o})
		if e != nil {
			t.Fatal(e)
		}
		f.liveETag = o.ETag
		f.versions = map[string][]byte{"v1": data}
		f.mutate = func(f *fakeS3, _ Request) {
			if len(f.requests) == 2 {
				f.liveETag = "changed"
				f.objects[o.Key] = bytes.ReplaceAll(data, []byte("12"), []byte("13"))
			}
		}
		facts, e := verification.Scan(context.Background(), s, policy())
		if version == "v1" {
			if e != nil || facts.Objects[0].Rows != 20 {
				t.Fatal("versioned original", e)
			}
		} else if e != verification.ErrArtifactChanged {
			t.Fatal("ETag mutation", e)
		}
	}
	s, f := fixture(t, data, "csv")
	for _, h := range []Head{{Size: int64(len(data)), ETag: "wrong"}, {Size: int64(len(data)), VersionID: "wrong"}} {
		f.headOverride = &h
		if _, e := s.Open(context.Background(), s.members[0].Identity); e != verification.ErrArtifactChanged {
			t.Fatal("HEAD pin mismatch", e)
		}
	}
}

func TestConcurrentRangeCloseAndBoundaries(t *testing.T) {
	data := bytes.Repeat([]byte{3}, AWS_VERIFY_PARQUET_READ_AHEAD_BYTES+100)
	s, _ := fixture(t, data, "parquet")
	at, e := s.OpenAt(context.Background(), s.members[0].Identity)
	if e != nil {
		t.Fatal(e)
	}
	buf := make([]byte, len(data)+1)
	if n, e := at.ReadAt(buf, 0); n != len(data) || e != io.EOF || !bytes.Equal(buf[:n], data) {
		t.Fatal(n, e)
	}
	if _, e := at.ReadAt(buf, -1); e != verification.ErrArtifactChanged {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			for j := 0; j < 20; j++ {
				_, _ = at.ReadAt(make([]byte, 32), int64(j))
			}
		})
	}
	wg.Go(func() {
		_ = at.Close()
	})
	wg.Wait()
	if at.(*reader).cache != nil {
		t.Fatal("cache retained")
	}
	ctx, cancel := context.WithCancel(context.Background())
	other, e := s.OpenAt(ctx, s.members[0].Identity)
	if e != nil {
		t.Fatal(e)
	}
	cancel()
	defer other.Close()
	if _, e = other.ReadAt(buf, 0); e != context.Canceled {
		t.Fatal(e)
	}
}

func TestParquetSecondPassMutation(t *testing.T) {
	data := generatedParquet(t, 20, 2000)
	s, f := fixture(t, data, "parquet")
	f.mutate = func(f *fakeS3, _ Request) {
		if len(f.requests) == 2 {
			changed := append([]byte(nil), data...)
			changed[len(changed)-10] ^= 1
			f.objects["e\u0301.parquet"] = changed
		}
	}
	if facts, e := verification.Scan(context.Background(), s, policy()); e != verification.ErrArtifactChanged || len(facts.Objects) != 0 {
		t.Fatal("Parquet mutation", e)
	}
}
func generatedParquet(t *testing.T, groups, rows int) []byte {
	t.Helper()
	var buf bytes.Buffer
	node, e := schema.NewPrimitiveNode("n", parquet.Repetitions.Required, parquet.Types.Int64, -1, -1)
	if e != nil {
		t.Fatal(e)
	}
	root, e := schema.NewGroupNode("schema", parquet.Repetitions.Required, schema.FieldList{node}, -1)
	if e != nil {
		t.Fatal(e)
	}
	w := file.NewParquetWriter(&buf, root, file.WithWriterProps(parquet.NewWriterProperties(parquet.WithDictionaryDefault(false), parquet.WithDataPageSize(64<<10))))
	values := make([]int64, rows)
	for i := range values {
		values[i] = int64(i % 100)
	}
	for i := 0; i < groups; i++ {
		g := w.AppendRowGroup()
		c, e := g.NextColumn()
		if e != nil {
			t.Fatal(e)
		}
		if _, e = c.(*file.Int64ColumnChunkWriter).WriteBatch(values, nil, nil); e != nil {
			t.Fatal(e)
		}
		if e = c.Close(); e != nil {
			t.Fatal(e)
		}
		if e = g.Close(); e != nil {
			t.Fatal(e)
		}
	}
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	return buf.Bytes()
}

// This generated fake-S3 harness includes a deterministic 1ms GET service delay.
// It does not represent real Lambda latency/RSS or the original 442 MB fixture.
func TestD7ReadAheadMeasurement(t *testing.T) {
	if testing.Short() {
		t.Skip("measurement")
	}
	for _, tc := range []struct{ groups, rows int }{{20, 40000}, {400, 2000}} {
		data := generatedParquet(t, tc.groups, tc.rows)
		var baseline verification.Facts
		var baselineGets int
		for _, ahead := range []int64{256 << 10, AWS_VERIFY_PARQUET_READ_AHEAD_BYTES} {
			s, f := fixture(t, data, "parquet")
			s.readAhead = ahead
			f.latency = time.Millisecond
			p := policy()
			var peak int64
			p.MemoryPeak = &peak
			start := time.Now()
			facts, e := verification.Scan(context.Background(), s, p)
			elapsed := time.Since(start)
			if e != nil {
				t.Fatal(e)
			}
			if ahead == 256<<10 {
				baseline = facts
				baselineGets = len(f.requests)
			} else if !reflect.DeepEqual(baseline, facts) || len(f.requests) >= baselineGets {
				t.Fatal("parity/GET regression")
			}
			if peak > 128<<20 {
				t.Fatal("budget", peak)
			}
			t.Logf("D7 groups=%d rows=%d object_bytes=%d read_ahead=%d GETs=%d fetched_bytes=%d elapsed=%s budget_peak=%d exact_fact_parity=true", tc.groups, tc.groups*tc.rows, len(data), ahead, len(f.requests), f.bytes, elapsed, peak)
		}
	}
}
func ExampleIdentity() {
	id, _ := Identity("e\u0301.csv", "v1")
	fmt.Printf("%q", id) // Output: "é.csv\x00v1"
}
