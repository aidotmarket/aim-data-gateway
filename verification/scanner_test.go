package verification

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/inventory"
)

func testPolicy() Policy {
	return Policy{CanonicalizationVersion: "python-json-sort-compact-v1", RowCountAlgorithmVersion: "exact-v1", DistinctAlgorithmVersion: "hll-sha256-v1", HistogramVersion: "fixed-buckets-v1", NumericBucketVersion: "fixed-buckets-v1", MinimumAggregateOccupancy: 10, LengthBounds: []int{0, 1, 4, 8, 16, 32, 64, 128, 256}, NumericBoundaries: []float64{-1000, -100, -10, 0, 10, 100, 1000}, GatewayID: "11111111-1111-4111-8111-111111111111", SnapshotHash: strings.Repeat("a", 64), CommitmentKey: [32]byte(bytes.Repeat([]byte{'c'}, 32))}
}

type memorySource struct {
	members []Member
	data    map[string][]byte
	opens   map[string]int
	onOpen  func(string, int)
	at      func(string) RandomAccess
}

func sourceFor(data []byte, format string) *memorySource {
	m := Member{Identity: strings.Repeat("1", 64), Size: int64(len(data)), SHA256: sha256.Sum256(data), Format: format}
	return &memorySource{[]Member{m}, map[string][]byte{m.Identity: data}, map[string]int{}, nil, nil}
}
func (s *memorySource) Members() []Member { return s.members }
func (s *memorySource) Open(_ context.Context, id string) (io.ReadCloser, error) {
	s.opens[id]++
	if s.onOpen != nil {
		s.onOpen(id, s.opens[id])
	}
	v, ok := s.data[id]
	if !ok {
		return nil, os.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader(v)), nil
}
func (s *memorySource) OpenAt(_ context.Context, id string) (RandomAccess, error) {
	s.opens[id]++
	if s.onOpen != nil {
		s.onOpen(id, s.opens[id])
	}
	if s.at != nil {
		return s.at(id), nil
	}
	return &randomBytes{bytes.NewReader(s.data[id])}, nil
}

type randomBytes struct{ *bytes.Reader }

func (r *randomBytes) Close() error { return nil }

func read(t *testing.T, path string) []byte {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestPinnedOraclePairs(t *testing.T) {
	var manifest struct {
		SourcePin string `json:"source_pin"`
		Files     []struct {
			Name, Input, Expected, Format, Seed string
			Refusal                             bool   `json:"refusal"`
			InputSHA                            string `json:"input_sha256"`
			ExpectedSHA                         string `json:"expected_sha256"`
		}
		BoundarySHA string `json:"boundaries_sha256"`
	}
	if e := json.Unmarshal(read(t, "testdata/oracle/manifest.json"), &manifest); e != nil {
		t.Fatal(e)
	}
	if manifest.SourcePin != "1edd9bfdab112517896c8026510b88ca0168c33e" {
		t.Fatal("oracle pin drift")
	}
	for _, v := range manifest.Files {
		t.Run(v.Name, func(t *testing.T) {
			input := read(t, "testdata/oracle/"+v.Input)
			expected := read(t, "testdata/oracle/"+v.Expected)
			for _, pair := range []struct {
				b    []byte
				hash string
			}{{input, v.InputSHA}, {expected, v.ExpectedSHA}} {
				h := sha256.Sum256(pair.b)
				if hex.EncodeToString(h[:]) != pair.hash {
					t.Fatal("oracle digest drift")
				}
			}
			p := testPolicy()
			seed, e := hex.DecodeString(v.Seed)
			if e != nil {
				t.Fatal(e)
			}
			copy(p.Seed[:], seed)
			src := sourceFor(input, v.Format)
			got, e := Scan(context.Background(), src, p)
			if v.Refusal {
				if !errors.Is(e, ErrUnsupported) || !reflect.DeepEqual(got, Facts{}) {
					t.Fatalf("refusal: facts=%+v error=%v", got, e)
				}
				raw, err := canonical(map[string]any{"error": "ValueError", "facts": nil})
				if err != nil || !bytes.Equal(raw, expected) {
					t.Fatalf("refusal differs: %s", raw)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			if len(got.Objects) != 1 {
				t.Fatal(got)
			}
			// Legacy binding exists only in this test. The public package accepts typed gateway binding.
			object := got.Objects[0]
			var expectedObject Object
			if e = json.Unmarshal(expected, &expectedObject); e != nil {
				t.Fatal(e)
			}
			object.ObjectID = expectedObject.ObjectID
			raw, e := canonical(object)
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(raw, expected) {
				t.Fatalf("canonical facts differ\ngot: %s\nwant: %s", raw, expected)
			}
			if src.opens[src.members[0].Identity] != 2 {
				t.Fatal("not exactly two source opens")
			}
		})
	}
	h := sha256.Sum256(read(t, "testdata/oracle/boundaries.json"))
	if hex.EncodeToString(h[:]) != manifest.BoundarySHA {
		t.Fatal("boundary digest")
	}
}
func TestGoldenFactsFingerprintAndReceipt(t *testing.T) {
	raw := read(t, "testdata/s1590/report.json")
	v, e := decodeJSON(raw)
	if e != nil {
		t.Fatal(e)
	}
	report := v.(map[string]any)
	spec, e := decodeJSON(read(t, "testdata/s1590/scan_spec.json"))
	if e != nil {
		t.Fatal(e)
	}
	payload := spec.(map[string]any)["payload"].(map[string]any)
	var data strings.Builder
	data.WriteString("problem_id,difficulty,accepted_count\n")
	for i := 1; i <= 12; i++ {
		fmt.Fprintf(&data, "%d,level_%d,%d\n", i, i, i*10)
	}
	p := testPolicy()
	seed, e := hex.DecodeString(payload["deterministic_seed"].(string))
	if e != nil {
		t.Fatal(e)
	}
	copy(p.Seed[:], seed)
	got, e := Scan(context.Background(), sourceFor([]byte(data.String()), "csv"), p)
	if e != nil {
		t.Fatal(e)
	}
	// Reproduce the legacy object/locator in a test-only binding; no callable legacy adapter.
	got.Objects[0].ObjectID = keyed(p.CommitmentKey, "object\x00dataset-s1590-fixture\x00registered-root")
	expected, _ := canonical(report["objects"])
	actual, _ := canonical(got.Objects)
	if !bytes.Equal(expected, actual) {
		t.Fatalf("golden bytes\n%s\n%s", actual, expected)
	}
	fingerprint, e := fingerprint(got, p)
	if e != nil || fingerprint != report["fingerprint_hash"] {
		t.Fatalf("fingerprint %s %v", fingerprint, e)
	}
	h := sha256.Sum256([]byte(data.String()))
	if hex.EncodeToString(h[:]) != report["content_sha256"] {
		t.Fatal("golden content")
	}
	if keyed(p.CommitmentKey, "local\x00/fixture/registered.csv") != report["artifact_locator_commitment"] {
		t.Fatal("golden locator")
	}
	binding := map[string]any{}
	for _, k := range []string{"spec_hash", "nonce_echo", "install_key_id", "artifact_locator_commitment", "content_sha256", "started_at_utc", "completed_at_utc", "duration_ms", "coverage", "fingerprint_hash"} {
		binding[k] = report[k]
	}
	binding["fingerprint_hash"] = fingerprint
	binding["coverage"] = got.Coverage
	canonicalBinding, e := canonical(binding)
	if e != nil {
		t.Fatal(e)
	}
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	sig := ed25519.Sign(priv, canonicalBinding)
	if base64.StdEncoding.EncodeToString(sig) != report["receipt_signature"] {
		t.Fatal("frozen receipt bytes")
	}
}
func TestSuppressionOracleBoundaries(t *testing.T) {
	var v struct {
		Rates []struct {
			Rows, Nulls, Units int64
			Suppressed         bool
		}
		Distinct []struct {
			Estimate   int64
			Suppressed bool
		}
	}
	if e := json.Unmarshal(read(t, "testdata/oracle/boundaries.json"), &v); e != nil {
		t.Fatal(e)
	}
	for _, r := range v.Rates {
		if rateUnits(r.Nulls, r.Rows) != r.Units {
			t.Fatal(r)
		}
		got := r.Rows < 10 || low([]int64{r.Nulls, r.Rows - r.Nulls}) || ambiguousRate(r.Nulls, r.Rows)
		if got != r.Suppressed {
			t.Fatal(r)
		}
	}
	for _, d := range v.Distinct {
		if ambiguousDistinct(d.Estimate) != d.Suppressed {
			t.Fatal(d)
		}
	}
	// Counts in every emitted histogram are zero or >=10. One/two row and
	// cardinality fixtures above compare each aggregate to the full-set oracle.
}
func TestBoundedDistinctNeverRetainsEleventh(t *testing.T) {
	p := testPolicy()
	p, _ = p.checked()
	b := &budget{limit: 128 << 20}
	a := newAggregate("string", 0, p)
	for i := 0; i < 100000; i++ {
		s := fmt.Sprintf("value-%d", i)
		raw, _ := canonical(s)
		if e := a.add(raw, len(s), 0, true, p, b); e != nil {
			t.Fatal(e)
		}
	}
	if len(a.exact) != 10 || b.used > 10000 {
		t.Fatalf("retained %d values, %d bytes", len(a.exact), b.used)
	}
}

func TestCompleteTraversalAndVoidedMutation(t *testing.T) {
	for _, mode := range []string{"before", "between", "missing", "append", "unsupported_mutation", "late_supported"} {
		t.Run(mode, func(t *testing.T) {
			src := sourceFor([]byte("n\n"+strings.Repeat("123456789\n", 20000)), "csv")
			second := Member{Identity: strings.Repeat("2", 64), Format: "zip", Size: 4, SHA256: sha256.Sum256([]byte("zip!"))}
			src.members = append(src.members, second)
			src.data[second.Identity] = []byte("zip!")
			if mode == "late_supported" {
				src.members[1].Format = "csv"
				src.data[second.Identity] = []byte("n\n12\n")
				src.members[1].Size = 5
				src.members[1].SHA256 = sha256.Sum256(src.data[second.Identity])
			}
			mutate := func(id string) { d := append([]byte(nil), src.data[id]...); d[len(d)-2] ^= 1; src.data[id] = d }
			if mode == "before" {
				mutate(src.members[0].Identity)
			} else {
				src.onOpen = func(id string, n int) {
					if n != 2 {
						return
					}
					switch mode {
					case "missing":
						delete(src.data, id)
					case "append":
						src.data[id] = append(src.data[id], 'x')
					case "unsupported_mutation": // unsupported members have no decoder but are still pre-read verified.
					default:
						mutate(id)
					}
				}
			}
			if mode == "unsupported_mutation" {
				mutate(second.Identity)
			}
			got, e := Scan(context.Background(), src, testPolicy())
			if !errors.Is(e, ErrArtifactChanged) {
				t.Fatalf("FAILED_VOIDED required, got %v", e)
			}
			if len(got.Objects) != 0 || got.FingerprintHash != "" {
				t.Fatal("partial success escaped")
			}
		})
	}
	src := sourceFor([]byte("n\n"+strings.Repeat("12\n", 20)), "csv")
	second := Member{Identity: strings.Repeat("2", 64), Format: "zip", Size: 4, SHA256: sha256.Sum256([]byte("zip!"))}
	src.members = append(src.members, second)
	src.data[second.Identity] = []byte("zip!")
	f, e := Scan(context.Background(), src, testPolicy())
	if e != nil {
		t.Fatal(e)
	}
	if f.Coverage.Discovered != 2 || f.Coverage.Scanned != 1 || f.Coverage.Reasons["unsupported_type"] != 1 || src.opens[second.Identity] != 2 {
		t.Fatal("incomplete traversal", f.Coverage)
	}
}
func TestRejectMalformedAndResourceBounds(t *testing.T) {
	for _, tc := range []struct{ format, data string }{{"jsonl", "{\"a\":1,\"a\":2}\n"}, {"jsonl", "{\"a\":[1]}\n"}, {"jsonl", "[1]\n"}, {"csv", "a,a\n1,2\n"}, {"csv", "a,b\n1\n"}, {"csv", "a\n\xff\n"}} {
		if _, e := Scan(context.Background(), sourceFor([]byte(tc.data), tc.format), testPolicy()); e == nil {
			t.Fatalf("accepted %q", tc.data)
		}
	}
	p := testPolicy()
	p.MaxRecordBytes = 100
	_, e := Scan(context.Background(), sourceFor([]byte("a\n"+strings.Repeat("x", 101)+"\n"), "csv"), p)
	if e == nil {
		t.Fatal("record bound")
	}
	p = testPolicy()
	p.MaxMemoryBytes = 1 << 20
	if _, e = Scan(context.Background(), sourceFor([]byte("a\n1\n"), "csv"), p); e != ErrBudget {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = Scan(ctx, sourceFor([]byte("a\n1\n"), "csv"), testPolicy()); e != ErrTimeout {
		t.Fatal(e)
	}
	p = testPolicy()
	p.MaxFactBytes = 50
	if _, e = Scan(context.Background(), sourceFor([]byte("a\n1\n"), "csv"), p); e != ErrBudget {
		t.Fatal(e)
	}
}

type diskSource struct {
	m      Member
	path   string
	onOpen func()
}

func (s diskSource) Members() []Member { return []Member{s.m} }
func (s diskSource) Open(context.Context, string) (io.ReadCloser, error) {
	if s.onOpen != nil {
		s.onOpen()
	}
	return os.Open(s.path)
}

type randomFile struct {
	*os.File
	size int64
}

func (r randomFile) Size() int64 { return r.size }
func (s diskSource) OpenAt(context.Context, string) (RandomAccess, error) {
	f, e := os.Open(s.path)
	if e != nil {
		return nil, e
	}
	st, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, e
	}
	return randomFile{f, st.Size()}, nil
}
func TestSameSizeSameMtimeMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.csv")
	data := []byte("n\n" + strings.Repeat("12\n", 20))
	os.WriteFile(path, data, 0600)
	st, _ := os.Stat(path)
	m := sourceFor(data, "csv").members[0]
	count := 0
	src := diskSource{m, path, func() {
		count++
		if count == 2 {
			changed := bytes.ReplaceAll(data, []byte("12"), []byte("13"))
			os.WriteFile(path, changed, 0600)
			os.Chtimes(path, st.ModTime(), st.ModTime())
		}
	}}
	f, e := Scan(context.Background(), src, testPolicy())
	if e != ErrArtifactChanged || f.FingerprintHash != "" {
		t.Fatal("same-mtime mutation not voided", e)
	}
}
func TestLargeTextMemoryAndDownloadConcurrency(t *testing.T) {
	for _, format := range []string{"csv", "jsonl"} {
		t.Run(format, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "large")
			f, e := os.Create(path)
			if e != nil {
				t.Fatal(e)
			}
			h := sha256.New()
			w := io.MultiWriter(f, h)
			if format == "csv" {
				io.WriteString(w, "n,text\n")
			}
			line := "123456,abcdefgh\n"
			if format == "jsonl" {
				line = "{\"n\":123456,\"text\":\"abcdefgh\"}\n"
			}
			chunk := []byte(strings.Repeat(line, 2000))
			for i := 0; i < 1000; i++ {
				w.Write(chunk)
			}
			f.Close()
			st, _ := os.Stat(path)
			m := Member{strings.Repeat("1", 64), st.Size(), [32]byte(h.Sum(nil)), format}
			// Existing eight delivery buffers remain live during the measurement.
			downloads := make([][]byte, 8)
			for i := range downloads {
				downloads[i] = make([]byte, inventory.BlockSize)
			}
			runtime.GC()
			var base, peak runtime.MemStats
			runtime.ReadMemStats(&base)
			done := make(chan struct{})
			stopped := make(chan uint64, 1)
			go func() {
				ticker := time.NewTicker(time.Millisecond)
				defer ticker.Stop()
				maxHeap := base.HeapAlloc
				for {
					select {
					case <-done:
						stopped <- maxHeap
						return
					case <-ticker.C:
						runtime.ReadMemStats(&peak)
						maxHeap = max(maxHeap, peak.HeapAlloc)
					}
				}
			}()
			got, e := Scan(context.Background(), diskSource{m, path, nil}, testPolicy())
			close(done)
			maxHeap := <-stopped
			runtime.KeepAlive(downloads)
			if e != nil {
				t.Fatal(e)
			}
			if got.Objects[0].Rows != 2000000 {
				t.Fatal("truncated scan")
			}
			additional := maxHeap - base.HeapAlloc
			t.Logf("%s: file=%d bytes, 2,000,000 rows, peak additional heap=%d bytes, delivery buffers=%d bytes, combined peak heap=%d bytes", format, st.Size(), additional, 8*inventory.BlockSize, maxHeap)
			if additional > 128<<20 {
				t.Fatalf("memory ceiling exceeded: %d", additional)
			}
		})
	}
}
