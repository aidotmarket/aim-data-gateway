// Package harness measures the unchanged public scanner. This is not a production runner.
package harness

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"runtime"
	"time"

	v "github.com/aidotmarket/aim-data-gateway/verification"
)

type Object struct {
	Key       string `json:"key"`
	VersionID string `json:"version_id,omitempty"`
	ETag      string `json:"etag,omitempty"`
	Format    string `json:"format"`
}
type Event struct {
	Mode    string   `json:"mode"`
	Bucket  string   `json:"bucket"`
	Objects []Object `json:"objects"`
}
type Phase struct {
	WallSeconds   float64 `json:"wall_seconds"`
	BytesRead     int64   `json:"bytes_read"`
	RangeRequests int64   `json:"range_requests"`
	MBPerSecond   float64 `json:"mb_per_second"`
}
type Result struct {
	Mode             string   `json:"mode"`
	Prepass          Phase    `json:"prepass"`
	Execution        Phase    `json:"execution"`
	PeakRSSBytes     uint64   `json:"peak_rss_bytes"`
	RSSAvailable     bool     `json:"rss_available"`
	GoSys            uint64   `json:"go_sys_bytes"`
	GoHeapInuse      uint64   `json:"go_heap_inuse_bytes"`
	RemainingSeconds *float64 `json:"remaining_seconds"`
	Error            string   `json:"error"`
	FactsSHA256      string   `json:"facts_sha256"`
	StreamSHA256     []string `json:"stream_sha256,omitempty"`
}

// Meter belongs to one invocation. All sources and range readers share it.
type Meter struct{ Bytes, Ranges int64 }
type counted struct {
	io.ReadCloser
	m *Meter
}

func (r counted) Read(p []byte) (int, error) {
	n, e := r.ReadCloser.Read(p)
	r.m.Bytes += int64(n)
	return n, e
}
func Count(r io.ReadCloser, m *Meter) io.ReadCloser { return counted{r, m} }
func phase(start time.Time, b, r int64, m *Meter) Phase {
	s := time.Since(start).Seconds()
	n := m.Bytes - b
	return Phase{s, n, m.Ranges - r, float64(n) / 1e6 / s}
}

// Policy mirrors internal/verification/runner.go:357 without importing internals.
func Policy(c interface {
	LocatorCommitment() string
	ObjectID(v.Member) string
}) v.Policy {
	return v.Policy{CanonicalizationVersion: "python-json-sort-compact-v1", RowCountAlgorithmVersion: "exact-v1", DistinctAlgorithmVersion: "hll-sha256-v1", HistogramVersion: "fixed-buckets-v1", NumericBucketVersion: "fixed-buckets-v1", MinimumAggregateOccupancy: 10, LengthBounds: []int{0, 1, 4, 8, 16, 32, 64, 128, 256}, NumericBoundaries: []float64{-1000, -100, -10, 0, 10, 100, 1000}, MaxMemoryBytes: 128 << 20, MaxRecordBytes: 16 << 20, MaxScalarBytes: 16 << 20, MaxColumns: 1000, MaxFactBytes: 32768, Deadline: 30 * time.Minute, Commitments: c}
}

type Commitments struct {
	Key                    [32]byte
	Kind, Bucket, Manifest string
	Objects                map[string]Object
}

func (c Commitments) mac(s string) string {
	h := hmac.New(sha256.New, c.Key[:])
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}
func (c Commitments) LocatorCommitment() string {
	return c.mac(c.Kind + "\x00" + c.Bucket + "\x00" + c.Manifest)
}
func (c Commitments) ObjectID(m v.Member) string {
	o := c.Objects[m.Identity]
	pin := o.VersionID
	if pin == "" {
		pin = o.ETag
	}
	return c.mac("object\x00" + c.Kind + "\x00" + c.Bucket + "\x00" + o.Key + "\x00" + pin + "\x00" + hex.EncodeToString(m.SHA256[:]))
}
func Identity(o Object) string {
	pin := o.VersionID
	if pin == "" {
		pin = o.ETag
	}
	h := sha256.Sum256([]byte(o.Key + "\x00" + pin))
	return hex.EncodeToString(h[:16])
}
func Digest(x any) (string, error) {
	b, e := v.Canonical(x)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

// Factory resolves metadata only. Hash preparation is timed separately.
type Factory func(context.Context, Event, *Meter) (v.Source, Commitments, error)

func Run(ctx context.Context, e Event, f Factory) (out Result) {
	out.Mode = e.Mode
	defer func() {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		out.GoSys = m.Sys
		out.GoHeapInuse = m.HeapInuse
		out.PeakRSSBytes, out.RSSAvailable = peakRSS()
		if d, ok := ctx.Deadline(); ok {
			n := time.Until(d).Seconds()
			out.RemainingSeconds = &n
		}
	}()
	if e.Mode != "scan" && e.Mode != "probe" && e.Mode != "throughput" {
		out.Error = "invalid mode"
		return
	}
	meter := &Meter{}
	start := time.Now()
	src, c, err := f(ctx, e, meter)
	if err == nil {
		_, err = rand.Read(c.Key[:])
	}
	var prepared *preparedSource
	if err == nil {
		prepared = &preparedSource{Source: src}
		for _, m := range src.Members() {
			var r io.ReadCloser
			r, err = src.Open(ctx, m.Identity)
			if err != nil {
				break
			}
			h := sha256.New()
			stop := context.AfterFunc(ctx, func() { r.Close() })
			var n int64
			n, err = io.CopyBuffer(h, r, make([]byte, 64<<10))
			stop()
			ce := r.Close()
			if err == nil {
				err = ce
			}
			if err == nil && n != m.Size {
				err = v.ErrArtifactChanged
			}
			if err != nil {
				break
			}
			copy(m.SHA256[:], h.Sum(nil))
			prepared.members = append(prepared.members, m)
			if e.Mode == "throughput" {
				out.StreamSHA256 = append(out.StreamSHA256, hex.EncodeToString(m.SHA256[:]))
			}
		}
	}
	out.Prepass = phase(start, 0, 0, meter)
	if err != nil {
		out.Error = err.Error()
		return
	}
	if e.Mode == "throughput" {
		return
	}
	start = time.Now()
	b, r := meter.Bytes, meter.Ranges
	var facts any
	if e.Mode == "scan" {
		facts, err = v.Scan(ctx, prepared, Policy(c))
	} else {
		facts, err = v.Probe(ctx, prepared, Policy(c))
	}
	out.Execution = phase(start, b, r, meter)
	if err == nil {
		out.FactsSHA256, err = Digest(facts)
	}
	if err != nil {
		out.Error = err.Error()
	}
	return
}

type preparedSource struct {
	v.Source
	members []v.Member
}

func (s *preparedSource) Members() []v.Member { return append([]v.Member(nil), s.members...) }

// Memory is also used by both wasm targets and the independent parity oracle.
type Memory struct {
	Member v.Member
	Data   []byte
}

func (s Memory) Members() []v.Member { return []v.Member{s.Member} }
func (s Memory) Open(ctx context.Context, id string) (io.ReadCloser, error) {
	if id != s.Member.Identity {
		return nil, fmt.Errorf("unknown member")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(s.Data)), nil
}

type memoryAt struct{ *bytes.Reader }

func (memoryAt) Close() error { return nil }
func (s Memory) OpenAt(ctx context.Context, id string) (v.RandomAccess, error) {
	if id != s.Member.Identity {
		return nil, fmt.Errorf("unknown member")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return memoryAt{bytes.NewReader(s.Data)}, nil
}
