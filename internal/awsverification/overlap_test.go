package awsverification

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"sync"
	"testing"
	"time"
)

// Hold both invocations at the same boundary before letting either proceed.
func overlap(t *testing.T, handlers [2]Handler, arrived chan struct{}, release chan struct{}) {
	t.Helper()
	results := make(chan error, 2)
	for _, h := range handlers {
		go func(h Handler) { results <- h.Invoke(ctx) }(h)
	}
	defer close(release)
	for range handlers {
		select {
		case <-arrived:
		case err := <-results:
			t.Fatalf("invocation returned before overlap boundary: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("invocations did not overlap")
		}
	}
	// A buffered signal releases each contender; deferred close also unblocks
	// goroutines if an assertion above fails.
	release <- struct{}{}
	release <- struct{}{}
	for range handlers {
		select {
		case err := <-results:
			if err != nil && !errors.Is(err, ErrRefused) {
				t.Fatalf("losing conditional write returned unexpected error: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("invocation did not finish")
		}
	}
}

// Count actual source reads and serialize the underlying fake so a duplicate
// traversal is detected by an assertion as well as remaining race-safe.
type countedS3 struct {
	S3
	mu    sync.Mutex
	reads int
}

func (s *countedS3) Head(ctx context.Context, r Request) (Head, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.S3.Head(ctx, r)
}
func (s *countedS3) Get(ctx context.Context, r Request) (io.ReadCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	return s.S3.Get(ctx, r)
}
func (s *countedS3) ReadCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads
}

func TestOverlappingPollsAdmitAndScanOnce(t *testing.T) {
	f := newFixture(t)
	j := f.job(t, 1, "scan")
	if _, err := Bootstrap(ctx, f.h.Config, f.h.Ledger, f.secrets, f.backend, f.at); err != nil {
		t.Fatal(err)
	}
	arrived, release := make(chan struct{}, 2), make(chan struct{}, 2)
	backends := [2]*memoryBackend{}
	handlers := [2]Handler{f.h, f.h}
	source := &countedS3{S3: f.s3}
	for i := range handlers {
		backends[i] = &memoryBackend{work: f.backend.work, snapshot: f.backend.snapshot,
			onSnapshot: func() error { arrived <- struct{}{}; <-release; return nil }}
		handlers[i].Backend = backends[i]
		handlers[i].Audit = &memoryAudit{}
		handlers[i].S3 = source
	}
	overlap(t, handlers, arrived, release)
	r, ok, err := f.h.Ledger.record(ctx, j.Text("spec_id"))
	if err != nil || !ok || r.State != "reported" || len(backends[0].reports)+len(backends[1].reports) != 1 {
		t.Fatal("overlapping polls did not produce exactly one settled report", err)
	}
	daily := f.db.items["daily#"+j.Text("listing_id")+"#"+f.at.Format("2006-01-02")]
	if !reflect.DeepEqual(daily["accepted_count"], num(1)) {
		t.Fatal("invalid admission count")
	}
	// One CSV scan performs two full reads (prepare and aggregate). A second
	// scanner would add reads even if its eventual ledger commit were refused.
	if reads := source.ReadCount(); reads != 2 {
		t.Fatalf("expected two source reads for one scan, got %d", reads)
	}
}

type gatedReportBackend struct {
	Backend
	arrived chan<- struct{}
	release <-chan struct{}
}

func (b gatedReportBackend) Report(ctx context.Context, s *Secret, body []byte, iid string) error {
	b.arrived <- struct{}{}
	<-b.release
	return b.Backend.Report(ctx, s, body, iid)
}

func TestOverlappingOutboxResendsUseIdenticalBytes(t *testing.T) {
	f := newFixture(t)
	j := f.job(t, 1, "scan")
	f.audit.fail = "committed"
	if f.h.Invoke(ctx) == nil {
		t.Fatal("expected interruption after commit")
	}
	r, _, _ := f.h.Ledger.record(ctx, j.Text("spec_id"))
	saved, err := f.h.Ledger.Body(ctx, r, f.at)
	if err != nil {
		t.Fatal(err)
	}
	reads := len(f.s3.requests)
	arrived, release := make(chan struct{}, 2), make(chan struct{}, 2)
	backends := [2]*memoryBackend{{}, {}}
	handlers := [2]Handler{f.h, f.h}
	for i := range handlers {
		handlers[i].Backend = gatedReportBackend{backends[i], arrived, release}
		handlers[i].Audit = &memoryAudit{}
	}
	overlap(t, handlers, arrived, release)
	for _, b := range backends {
		if len(b.reports) != 1 || !bytes.Equal(saved, b.reports[0]) {
			t.Fatal("concurrent resend changed persisted report bytes")
		}
	}
	if len(f.s3.requests) != reads {
		t.Fatal("concurrent resend rescanned source")
	}
}
