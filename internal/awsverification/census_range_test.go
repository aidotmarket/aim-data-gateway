package awsverification

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"

	core "github.com/aidotmarket/aim-data-gateway/verification"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)

// Exercise the actual SDK adapter too: Range and If-Match reach the provider.
type censusRangeAPI struct {
	mu     sync.Mutex
	data   []byte
	etag   string
	ranges []string
	change string
}

func (f *censusRangeAPI) HeadObject(_ context.Context, _ *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &s3.HeadObjectOutput{ContentLength: aws.Int64(int64(len(f.data))), ETag: aws.String("\"" + f.etag + "\"")}, nil
}
func (f *censusRangeAPI) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.change != "" {
		f.etag = "changed"
		if f.change == "size" {
			f.data = append(f.data, 0)
		}
	}
	if aws.ToString(in.IfMatch) != "\""+f.etag+"\"" {
		return nil, &smithy.GenericAPIError{Code: "PreconditionFailed"}
	}
	r := aws.ToString(in.Range)
	f.ranges = append(f.ranges, r)
	var start, end int64
	if _, err := fmt.Sscanf(r, "bytes=%d-%d", &start, &end); err != nil || start < 0 || start >= int64(len(f.data)) || end < start {
		return nil, &smithy.GenericAPIError{Code: "InvalidRange"}
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(f.data[start:min(end+1, int64(len(f.data)))]))}, nil
}

func smallThreeEntryTar(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	g, err := gzip.NewWriterLevel(&b, gzip.NoCompression)
	if err != nil {
		t.Fatal(err)
	}
	w := tar.NewWriter(g)
	for i := 0; i < 3; i++ {
		data := bytes.Repeat([]byte("census text\n"), 5500)
		if err := w.WriteHeader(&tar.Header{Name: fmt.Sprintf("entry%d.txt", i), Mode: 0600, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func rangeSource(t *testing.T, data []byte, format string) (*Source, *censusRangeAPI) {
	t.Helper()
	f := &censusRangeAPI{data: data, etag: "pinned"}
	s, err := NewSource(S3Client{Client: f}, "fixture", []Object{{Key: "bundle." + format, Format: format, Size: int64(len(data)), ETag: "pinned"}})
	if err != nil {
		t.Fatal(err)
	}
	return s, f
}

func rangePolicy() core.Policy {
	j := wireCensusJob()
	return scanPolicy(j, &collectedCommitments{Commitments: Commitments{Bucket: "fixture"}, Digests: map[string]string{}})
}

func TestSmallTarGzipThroughAWSSource(t *testing.T) {
	data := smallThreeEntryTar(t)
	if len(data) < 190<<10 || len(data) > 210<<10 {
		t.Fatal("fixture size", len(data))
	}
	s, f := rangeSource(t, data, "tar.gz")
	p := rangePolicy()
	p.RunStats = &core.RunStats{}
	facts, err := core.Scan(ctx, s, p)
	if err != nil {
		t.Fatal(err)
	}
	c := facts.ContentCensus
	if c == nil || c.DepthClass != "content_census_complete_v1" || c.CoverageContent.LimitedCoverage {
		t.Fatalf("not fully read: %+v", c)
	}
	if len(f.ranges) != 1 || f.ranges[0] != fmt.Sprintf("bytes=0-%d", len(data)-1) {
		t.Fatal(f.ranges)
	}
	if p.RunStats.GETs.Load() != 1 || p.RunStats.RequestedBytes.Load() != censusR1ArchiveAllowanceBytes+(1<<20) || p.RunStats.StoredBytes.Load() != int64(len(data)) {
		t.Fatal("planned/actual accounting changed", p.RunStats)
	}
}

func TestCensusRangePinsAndBoundaries(t *testing.T) {
	for _, change := range []string{"etag", "size"} {
		t.Run(change, func(t *testing.T) {
			s, f := rangeSource(t, smallThreeEntryTar(t), "tar.gz")
			f.change = change // HEAD sees the original, GET sees a new object.
			if _, err := s.OpenRange(ctx, s.members[0].Identity, 0, censusR1ArchiveAllowanceBytes+(1<<20)); !errors.Is(err, core.ErrArtifactChanged) {
				t.Fatal(err)
			}
			// The paid scanner must refuse the drift as well.
			s, f = rangeSource(t, smallThreeEntryTar(t), "tar.gz")
			f.change = change
			if _, err := core.Scan(ctx, s, rangePolicy()); !errors.Is(err, core.ErrArtifactChanged) {
				t.Fatal(err)
			}
		})
	}
	s, f := rangeSource(t, []byte("abcdef"), "txt")
	id := s.members[0].Identity
	for _, v := range [][2]int64{{-1, 1}, {0, -1}, {7, 1}} {
		if _, err := s.OpenRange(ctx, id, v[0], v[1]); !errors.Is(err, core.ErrArtifactChanged) {
			t.Fatal(v, err)
		}
	}
	for _, v := range [][2]int64{{6, 0}, {6, 100}, {0, 0}} {
		r, err := s.OpenRange(ctx, id, v[0], v[1])
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(r)
		r.Close()
		if err != nil || len(b) != 0 {
			t.Fatal(b, err)
		}
	}
	if len(f.ranges) != 0 {
		t.Fatal(f.ranges)
	}
	r, err := s.OpenRange(ctx, id, 2, 100)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(r)
	r.Close()
	if err != nil || string(b) != "cdef" || f.ranges[0] != "bytes=2-5" {
		t.Fatal(string(b), f.ranges, err)
	}
}

func TestZipExactRangesThroughAWSSource(t *testing.T) {
	data := zipFixture(t, 200<<10, zip.Store)
	s, f := rangeSource(t, data, "zip")
	facts, err := core.Scan(ctx, s, rangePolicy())
	if err != nil || facts.ContentCensus == nil || facts.ContentCensus.DepthClass != "content_census_complete_v1" {
		t.Fatal(facts, err)
	}
	if len(f.ranges) < 2 {
		t.Fatal(f.ranges)
	}
	for _, r := range f.ranges {
		var start, end int64
		fmt.Sscanf(r, "bytes=%d-%d", &start, &end)
		if start < 0 || end >= int64(len(data)) || end < start {
			t.Fatal(r)
		}
	}
	// An exact interior extent remains exact, rather than expanding to EOF.
	r, err := s.OpenRange(ctx, s.members[0].Identity, 10, 20)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(r)
	r.Close()
	if err != nil || !bytes.Equal(b, data[10:30]) || f.ranges[len(f.ranges)-1] != "bytes=10-29" {
		t.Fatal(f.ranges, err)
	}
}
