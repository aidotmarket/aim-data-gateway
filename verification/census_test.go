package verification

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func censusPolicy() Policy {
	p := testPolicy()
	p.ScanMode = ContentCensusV1
	p.BindingMethod = "planned_read_commitment_v2"
	p.ContentReadBudgetBytes = 4_000_000_000
	p.PlannedProcessedBytes = 4_000_000_000
	p.ArchiveAllowanceBytes = 64 << 20
	p.ArchiveCaps = ArchiveCaps{256 << 20, 10000, 1000}
	p.PatternVersions = append([]string(nil), patternVersions...)
	return p
}

type rangeCall struct {
	id     string
	off, n int64
}
type censusSource struct {
	*memorySource
	mu          sync.Mutex
	calls       []rangeCall
	heads       []string
	head        func(context.Context, string) (Member, error)
	read        func(context.Context, rangeCall, []byte) (io.ReadCloser, error)
	chunk       int
	ignoreRange bool
}

func censusFor(data []byte, format string) *censusSource {
	s := sourceFor(data, format)
	m := s.members[0]
	m.Identity = fmt.Sprintf("%032x", 1)
	s.members[0] = m
	s.data = map[string][]byte{m.Identity: data}
	return &censusSource{memorySource: s}
}

func (s *censusSource) OpenRange(ctx context.Context, id string, off, n int64) (io.ReadCloser, error) {
	call := rangeCall{id, off, n}
	s.mu.Lock()
	s.calls = append(s.calls, call)
	s.mu.Unlock()
	b, ok := s.data[id]
	if !ok {
		return nil, os.ErrNotExist
	}
	if off > int64(len(b)) {
		return nil, io.ErrUnexpectedEOF
	}
	end := min(int64(len(b)), off+n)
	if s.ignoreRange {
		end = int64(len(b))
	}
	b = b[off:end]
	if s.read != nil {
		return s.read(ctx, call, b)
	}
	var r io.Reader = bytes.NewReader(b)
	if s.chunk > 0 {
		r = &shortReader{r, s.chunk}
	}
	return io.NopCloser(r), nil
}
func (s *censusSource) Head(ctx context.Context, id string) (Member, error) {
	s.mu.Lock()
	s.heads = append(s.heads, id)
	s.mu.Unlock()
	if s.head != nil {
		return s.head(ctx, id)
	}
	for _, m := range s.members {
		if m.Identity == id {
			return m, nil
		}
	}
	return Member{}, os.ErrNotExist
}

type shortReader struct {
	r io.Reader
	n int
}

func (r *shortReader) Read(b []byte) (int, error) { return r.r.Read(b[:min(len(b), r.n)]) }
func addCensus(s *censusSource, data []byte, format string) {
	id := fmt.Sprintf("%032x", len(s.members)+1)
	m := Member{Identity: id, Size: int64(len(data)), Format: format, SHA256: sha256.Sum256(data)}
	s.members = append(s.members, m)
	s.data[id] = data
}
func TestCensusPolicyRefusals(t *testing.T) {
	for name, change := range map[string]func(*Policy){"mode": func(p *Policy) { p.ScanMode = "future" }, "method": func(p *Policy) { p.BindingMethod = "future" }, "v1method": func(p *Policy) { p.ScanMode = "table_v1" }, "budget_literal": func(p *Policy) { p.ContentReadBudgetBytes++ }, "planned_over_literal": func(p *Policy) { p.PlannedProcessedBytes++ }, "negative": func(p *Policy) { p.PlannedProcessedBytes = -1 }, "allowance": func(p *Policy) { p.ArchiveAllowanceBytes++ }, "caps": func(p *Policy) { p.ArchiveCaps.Entries++ }, "patterns": func(p *Policy) { p.PatternVersions[0] = "email_v2" }} {
		t.Run(name, func(t *testing.T) {
			p := censusPolicy()
			change(&p)
			if _, e := p.checked(); !errors.Is(e, ErrUnsupported) {
				t.Fatal(e)
			}
		})
	}
	for _, literal := range []int64{3_000_000_000, 4_000_000_000} {
		p := censusPolicy()
		p.ContentReadBudgetBytes = literal
		p.PlannedProcessedBytes = literal
		if _, e := p.checked(); e != nil {
			t.Fatal(e)
		}
	}
}
func TestPlannedReadSetPureAndGreedy(t *testing.T) {
	ms := []Member{{Identity: "a", Size: 100, Format: "txt"}, {Identity: "b", Size: 2, Format: "txt"}, {Identity: "c", Size: 3, Format: "zip"}, {Identity: "d", Size: 1, Format: "csv"}, {Identity: "é", Size: 2, Format: "txt"}}
	orig := append([]Member(nil), ms...)
	p := censusPolicy()
	p.PlannedProcessedBytes = 4
	p.ArchiveAllowanceBytes = 3
	want := PlannedReadSet(p.Seed, ms, p)
	if !reflect.DeepEqual(ms, orig) {
		t.Fatal("input mutated")
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].Identity > ms[j].Identity })
	if !reflect.DeepEqual(want, PlannedReadSet(p.Seed, ms, p)) {
		t.Fatal("snapshot order affected selection")
	}
	var cost int64
	for _, id := range want {
		for _, m := range ms {
			if m.Identity == id {
				if supported(m.Format) {
					t.Fatal("table planned")
				}
				n := m.Size
				if archiveFormat(m) != "" {
					n = p.ArchiveAllowanceBytes
				}
				cost += n
			}
		}
	}
	if cost > 4 || len(want) == 0 {
		t.Fatal(want, cost)
	}
}
func TestPlannedVersusOpenedDeadlineReasons(t *testing.T) {
	for _, mode := range []string{"cancelled_before_open", "deadline_before_open", "cancelled_during_open"} {
		t.Run(mode, func(t *testing.T) {
			s := censusFor([]byte("x"), "txt")
			for i := 1; i < 20; i++ {
				addCensus(s, []byte("x"), "txt")
			}
			p := censusPolicy()
			p.PlannedProcessedBytes = 10
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancelled_before_open" {
				cancel()
			}
			if mode == "deadline_before_open" {
				var end context.CancelFunc
				ctx, end = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer end()
			}
			if mode == "cancelled_during_open" {
				s.read = func(ctx context.Context, c rangeCall, b []byte) (io.ReadCloser, error) {
					cancel()
					return io.NopCloser(bytes.NewReader(b)), nil
				}
			}
			f, e := Scan(ctx, s, p)
			if e != nil {
				t.Fatal(e)
			}
			if len(s.heads) != 20 {
				t.Fatal(s.heads)
			}
			reasons := map[string]int64{}
			for _, cell := range f.ContentCensus.CoverageContent.UnreadByReason.Cells {
				reasons[cell.Class] = cell.Members.(int64)
			}
			if reasons["budget_exhausted"] != 10 || reasons["not_sampled"] != 10 {
				t.Fatal(reasons)
			}
			plan := PlannedReadSet(p.Seed, s.members, p)
			if len(plan) != 10 || f.UnreadBindingSHA256 != UnreadBindingSHA256(s.members, plan) {
				t.Fatal(plan)
			}
		})
	}
}

func TestUnreadDriftHEAD(t *testing.T) {
	for _, field := range []string{"size", "etag", "version", "permission", "deadline"} {
		t.Run(field, func(t *testing.T) {
			s := censusFor([]byte("unread"), "txt")
			p := censusPolicy()
			p.PlannedProcessedBytes = 0
			s.head = func(ctx context.Context, id string) (Member, error) {
				m := s.members[0]
				switch field {
				case "size":
					m.Size++
				case "etag":
					m.ETag = "changed"
				case "version":
					m.VersionID = "changed"
				case "permission":
					return m, os.ErrPermission
				case "deadline":
					return m, context.DeadlineExceeded
				}
				return m, nil
			}
			f, e := Scan(context.Background(), s, p)
			if e == nil || f.ContentCensus != nil {
				t.Fatal("partial facts", e)
			}
			want := "artifact_changed"
			if field == "permission" {
				want = "permission_denied"
			}
			if field == "deadline" {
				want = "timeout"
			}
			if RefusalReason(e) != want {
				t.Fatal(e)
			}
		})
	}
}
func TestHEADConcurrencyAndRequestStats(t *testing.T) {
	s := censusFor([]byte("x"), "txt")
	for i := 1; i < 33; i++ {
		addCensus(s, []byte("x"), "txt")
	}
	var mu sync.Mutex
	active, peak := 0, 0
	s.head = func(ctx context.Context, id string) (Member, error) {
		mu.Lock()
		active++
		peak = max(peak, active)
		mu.Unlock()
		time.Sleep(time.Millisecond)
		mu.Lock()
		active--
		mu.Unlock()
		for _, m := range s.members {
			if m.Identity == id {
				return m, nil
			}
		}
		return Member{}, nil
	}
	p := censusPolicy()
	p.PlannedProcessedBytes = 0
	p.RunStats = &RunStats{}
	f, e := Scan(context.Background(), s, p)
	if e != nil {
		t.Fatal(e)
	}
	if peak > 16 || peak < 2 || p.RunStats.HEADs.Load() != 33 || p.RunStats.GETs.Load() != 0 || f.Coverage.InCensus != 33 {
		t.Fatal(peak, p.RunStats, f.Coverage)
	}
}
func TestProbeCensusAdvisoryAndTableLimits(t *testing.T) {
	for _, tc := range []struct{ census, width int }{{0, 0}, {17029, 0}, {0, 24}, {17029, 24}} {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			s := &censusSource{memorySource: rehearsalSource(t, tc.width)}
			for i := 0; i < tc.census; i++ {
				addCensus(s, nil, "txt")
			}
			p := testPolicy()
			if tc.census > 0 {
				p = censusPolicy()
			}
			result, e := Probe(context.Background(), s, p)
			if e != nil || !result.SourceReachable || result.ObjectsDiscovered != 4+tc.census {
				t.Fatal(result, e)
			}
			if tc.census > 0 && result.EstimatedMaxInputTokens <= 8192 {
				t.Fatal("advisory not included", result)
			}
			f, e := Scan(context.Background(), s, p)
			if e != nil {
				t.Fatal(e)
			}
			if f.Coverage.Scanned+len(f.Coverage.Skipped)+f.Coverage.InCensus != f.Coverage.Discovered {
				t.Fatal(f.Coverage)
			}
		})
	}
	// The spec also asks for 17,033 census members. Exercise those plus four
	// table members at the scanner hard cap (backend admission owns its cap).
	s := &censusSource{memorySource: rehearsalSource(t, 0)}
	for i := 0; i < 17033; i++ {
		addCensus(s, nil, "txt")
	}
	if r, e := Probe(context.Background(), s, censusPolicy()); e != nil || r.ObjectsDiscovered != 17037 {
		t.Fatal(r, e)
	}
	s2 := &censusSource{memorySource: rehearsalSource(t, 0)}
	addCensus(s2, []byte("a,b,c,d,e,f\n1,2,3,4,5,6\n"), "csv")
	r, e := Probe(context.Background(), s2, testPolicy())
	if !errors.Is(e, ErrSummaryBudget) || r.SourceReachable || r.RefusalReason != "summary_budget_exceeded" {
		t.Fatal(r, e)
	}
	p := testPolicy()
	p.MaxRecordBytes = 100
	r, e = Probe(context.Background(), sourceFor([]byte("a\n"+strings.Repeat("w", 101)+"\n"), "csv"), p)
	if !errors.Is(e, ErrResourceLimit) || r.RefusalReason != "resource_limit_exceeded" {
		t.Fatal(r, e)
	}
	raw, _ := json.Marshal(r)
	if !bytes.Contains(raw, []byte(`"refusal_reason":"resource_limit_exceeded"`)) {
		t.Fatal(string(raw))
	}
}

func TestCensusMemoryReservationRefusesWithoutPartialFacts(t *testing.T) {
	s := censusFor([]byte("text"), "txt")
	p := censusPolicy()
	p.MaxMemoryBytes = 1 << 20
	if f, e := Scan(context.Background(), s, p); e != ErrResourceLimit || f.ContentCensus != nil {
		t.Fatal(f, e)
	}
	mem := &censusMemory{limit: 1024}
	a := inspection{memory: mem}
	for i := 0; i < 20; i++ {
		a.addFile(fileFinding{digest: sha256.Sum256([]byte(fmt.Sprint(i))), class: "plain_text", encoding: "utf8", script: "latin"})
	}
	if !mem.failed.Load() || mem.used.Load() > 1024 || len(a.exact) > 4 {
		t.Fatal(mem.used.Load(), len(a.exact))
	}
}
func TestTypedRefusalCodes(t *testing.T) {
	for _, e := range []error{ErrSummaryBudget, ErrResourceLimit, ErrArtifactChanged, ErrPermissionDenied, ErrUnsupported, ErrTimeout, ErrScannerFailure, ErrVerifierUpgradeRequired} {
		if RefusalReason(fmt.Errorf("wrapped: %w", e)) != e.Error() {
			t.Fatal(e)
		}
	}
	if RefusalReason(errors.New("unclassified")) != "scanner_failure" {
		t.Fatal("unknown failure exposed")
	}
}

func TestLegacyBudgetAndExplicitRefusals(t *testing.T) {
	for _, mode := range []string{"", "table_v1", ContentCensusV1} {
		p := testPolicy()
		if mode == ContentCensusV1 {
			p = censusPolicy()
		}
		p.ScanMode = mode
		p.MaxFactBytes = 1
		s := censusFor([]byte("a\n1\n"), "csv")
		_, err := Scan(context.Background(), s, p)
		want := ErrSummaryBudget
		if mode == "" {
			want = ErrBudget
		}
		if err != want {
			t.Fatalf("mode %q: %v want %v", mode, err, want)
		}
		probe, err := Probe(context.Background(), s, p)
		if err != ErrSummaryBudget || probe.RefusalReason != "summary_budget_exceeded" {
			t.Fatal(mode, probe, err)
		}
	}
}
