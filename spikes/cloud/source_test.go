package cloud

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/aidotmarket/aim-data-gateway/spikes/fixtures/generate"
	h "github.com/aidotmarket/aim-data-gateway/spikes/harness"
	v "github.com/aidotmarket/aim-data-gateway/verification"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This fake serves local files through exactly the SDK API used by the Lambda.
// No network listener, SDK configuration, credentials or cloud calls are involved.
type diskAPI struct {
	path                  string
	rangeCalls, fullCalls int
	failRange             bool
	version               bool
}

func (f *diskAPI) HeadObject(_ context.Context, in *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	st, e := os.Stat(f.path)
	if e != nil {
		return nil, e
	}
	return &s3.HeadObjectOutput{ContentLength: aws.Int64(st.Size()), ETag: aws.String(`"fixture"`), VersionId: aws.String("v1")}, nil
}
func (f *diskAPI) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	if f.version {
		if aws.ToString(in.VersionId) != "v1" || in.IfMatch != nil {
			return nil, fmt.Errorf("version lost")
		}
	} else if aws.ToString(in.IfMatch) != `"fixture"` || in.VersionId != nil {
		return nil, fmt.Errorf("etag lost")
	}
	file, e := os.Open(f.path)
	if e != nil {
		return nil, e
	}
	var body io.ReadCloser = file
	if in.Range != nil {
		f.rangeCalls++
		if f.failRange {
			file.Close()
			return nil, v.ErrArtifactChanged
		}
		var start, end int64
		if _, e = fmt.Sscanf(*in.Range, "bytes=%d-%d", &start, &end); e != nil {
			file.Close()
			return nil, e
		}
		body = sectionCloser{io.NewSectionReader(file, start, end-start+1), file}
	} else {
		f.fullCalls++
	}
	return &s3.GetObjectOutput{Body: body, ETag: aws.String(`"fixture"`), VersionId: aws.String("v1")}, nil
}

type sectionCloser struct {
	*io.SectionReader
	file *os.File
}

func (r sectionCloser) Close() error { return r.file.Close() }
func TestLocalFixtures(t *testing.T) {
	large := os.Getenv("SPIKE_LARGE") == "1"
	for _, format := range []string{"csv", "parquet"} {
		t.Run(format, func(t *testing.T) {
			size, rows := int64(100000), int64(2000)
			if large {
				size = 50000000
				rows = 200000
			}
			dir := t.TempDir()
			if dst := os.Getenv("SPIKE_FIXTURE_DIR"); dst != "" {
				dir = dst
				if e := os.MkdirAll(dir, 0700); e != nil {
					t.Fatal(e)
				}
			}
			path := filepath.Join(dir, "synthetic."+format)
			if os.Getenv("SPIKE_EXISTING") != "1" {
				out, e := os.Create(path)
				if e != nil {
					t.Fatal(e)
				}
				if format == "csv" {
					e = generate.CSV(out, size, 1791)
				} else {
					e = generate.Parquet(out, rows, 1791)
				}
				ce := out.Close()
				if e != nil {
					t.Fatal(e)
				}
				if ce != nil {
					t.Fatal(ce)
				}
			}
			obj := h.Object{Key: "spike/synthetic." + format, ETag: `"fixture"`, Format: format}
			event := h.Event{Mode: "scan", Bucket: "synthetic", Objects: []h.Object{obj}}
			fake := &diskAPI{path: path}
			// Capture the invocation's commitment key and SHA-pinned members for full-byte parity.
			factory := Factory(fake, "s3_listing")
			var source v.Source
			var commits h.Commitments
			result := h.Run(context.Background(), event, func(ctx context.Context, e h.Event, m *h.Meter) (v.Source, h.Commitments, error) {
				s, c, err := factory(ctx, e, m)
				source = s
				commits = c
				return s, c, err
			})
			if result.Error != "" || result.FactsSHA256 == "" {
				t.Fatalf("scan: %+v", result)
			}
			raw, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			member := source.Members()[0]
			member.SHA256 = sha256.Sum256(raw)
			// Run both sources with the SAME fixed policy/key; random keys intentionally differ per invocation.
			commits.Key = sha256.Sum256([]byte("local-parity-only"))
			policy := h.Policy(commits)
			pinned := pinnedTest{source, []v.Member{member}}
			start := time.Now()
			diskFacts, e := v.Scan(context.Background(), pinned, policy)
			if e != nil {
				t.Fatal(e)
			}
			diskWall := time.Since(start).Seconds()
			memoryFacts, e := v.Scan(context.Background(), h.Memory{Member: member, Data: raw}, policy)
			if e != nil {
				t.Fatal(e)
			}
			a, e := v.Canonical(diskFacts)
			if e != nil {
				t.Fatal(e)
			}
			b, e := v.Canonical(memoryFacts)
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(a, b) {
				t.Fatal("facts differ")
			}
			if diskFacts.Coverage.Scanned != 1 {
				t.Fatal("not scanned")
			}
			if format == "parquet" && diskFacts.Objects[0].Rows != rows {
				t.Fatal("wrong row count")
			}
			if format == "csv" && int64(len(raw)) != size {
				t.Fatal("wrong CSV size")
			}
			if format == "parquet" && fake.rangeCalls == 0 {
				t.Fatal("no ranged reads")
			}
			report := struct {
				Fixture        string   `json:"fixture"`
				FileBytes      int      `json:"file_bytes"`
				Rows           int64    `json:"rows"`
				Result         h.Result `json:"harness"`
				Parity         bool     `json:"canonical_facts_equal"`
				DiskRepeatWall float64  `json:"disk_repeat_wall_seconds"`
			}{format, len(raw), diskFacts.Objects[0].Rows, result, true, diskWall}
			encoded, e := json.Marshal(report)
			if e != nil {
				t.Fatal(e)
			}
			t.Log(string(encoded))
			if dst := os.Getenv("SPIKE_RESULTS_DIR"); dst != "" {
				if e = os.MkdirAll(dst, 0700); e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(filepath.Join(dst, format+".json"), append(encoded, '\n'), 0600); e != nil {
					t.Fatal(e)
				}
			}
		})
	}
}

type pinnedTest struct {
	v.Source
	members []v.Member
}

func (s pinnedTest) Members() []v.Member { return s.members }
func TestPinsRangesAndFailures(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bytes")
	raw := bytes.Repeat([]byte("0123456789"), 80000)
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	for _, version := range []bool{false, true} {
		fake := &diskAPI{path: path, version: version}
		obj := h.Object{Key: "spike/bytes", ETag: `"fixture"`}
		if version {
			obj.VersionID = "v1"
		}
		meter := &h.Meter{}
		src, _, e := Factory(fake, "s3_listing")(context.Background(), h.Event{Bucket: "test", Objects: []h.Object{obj}}, meter)
		if e != nil {
			t.Fatal(e)
		}
		id := src.Members()[0].Identity
		r, e := src.OpenAt(context.Background(), id)
		if e != nil {
			t.Fatal(e)
		}
		for _, off := range []int64{0, 40, 300000, 700000, 0} {
			p := make([]byte, 1000)
			n, e := r.ReadAt(p, off)
			if e != nil || n != 1000 || !bytes.Equal(p, raw[off:off+1000]) {
				t.Fatal("range data", e)
			}
		}
		if meter.Ranges != 4 {
			t.Fatalf("cache request count: %d", meter.Ranges)
		}
		fake.failRange = true
		if _, e = r.ReadAt(make([]byte, 50), 500000); e == nil {
			t.Fatal("mutation accepted")
		}
		r.Close()
		// Discovery can pin a HEAD ETag when the event omits both pins.
		if !version {
			obj.ETag = ""
			_, _, e = Factory(fake, "s3_listing")(context.Background(), h.Event{Bucket: "test", Objects: []h.Object{obj}}, meter)
			if e != nil {
				t.Fatal(e)
			}
		}
	}
	if _, _, e := Factory(&diskAPI{path: path}, "s3_listing")(context.Background(), h.Event{Bucket: "test", Objects: []h.Object{{Key: "outside/file"}}}, &h.Meter{}); e == nil {
		t.Fatal("scope accepted")
	}
}
func TestModesAndRefusal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.csv")
	if e := os.WriteFile(path, []byte("x,y\n1,hello\n2,world\n"), 0600); e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"throughput", "probe", "scan", "bad"} {
		fake := &diskAPI{path: path}
		e := h.Event{Mode: mode, Bucket: "fixture", Objects: []h.Object{{Key: "spike/file", ETag: `"fixture"`, Format: "csv"}}}
		r := h.Run(context.Background(), e, Factory(fake, "s3_listing"))
		if mode == "bad" {
			if r.Error == "" {
				t.Fatal("bad mode accepted")
			}
			continue
		}
		if r.Error != "" {
			t.Fatal(r.Error)
		}
		if mode == "throughput" {
			if fake.fullCalls != 1 || r.FactsSHA256 != "" || len(r.StreamSHA256) != 1 {
				t.Fatal("throughput read extra passes")
			}
		} else if r.FactsSHA256 == "" {
			t.Fatal("missing facts hash")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := h.Run(ctx, h.Event{Mode: "scan", Bucket: "fixture", Objects: []h.Object{{Key: "spike/file", ETag: `"fixture"`, Format: "csv"}}}, Factory(&diskAPI{path: path}, "s3_listing"))
	if r.Error == "" || strings.TrimSpace(r.FactsSHA256) != "" {
		t.Fatal("canceled scan returned facts")
	}
}
