package awsverification

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	core "github.com/aidotmarket/aim-data-gateway/verification"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCompleteScanReceiptPrivacyAndRedelivery(t *testing.T) {
	for _, variant := range []string{"scan", "probe"} {
		t.Run(variant, func(t *testing.T) {
			f := newFixture(t)
			j := f.job(t, 1, variant)
			if e := f.h.Invoke(ctx); e != nil {
				t.Fatal(e)
			}
			if len(f.backend.reports) != 1 {
				t.Fatal("no report")
			}
			body := f.backend.reports[0]
			for _, marker := range []string{"RAW_CELL_MARKER", "RAW_KEY_MARKER", "RAW_ETAG_MARKER", "RAW_PROVIDER_MARKER"} {
				if bytes.Contains(body, []byte(marker)) || strings.Contains(strings.Join(f.audit.events, ""), marker) {
					t.Fatal("marker leaked")
				}
			}
			v, e := core.ParseCanonical(body)
			if e != nil {
				t.Fatal(e)
			}
			m := v.(map[string]any)
			raw, _ := wire.DecodeDocument(m["document_b64"].(string), wire.MaxScanDocument)
			if bytes.Contains(raw, []byte("RAW_")) {
				t.Fatal("encoded raw marker leaked")
			}
			v, _ = core.ParseCanonical(raw)
			d := v.(map[string]any)
			sig, _ := base64.StdEncoding.DecodeString(d["receipt_signature"].(string))
			delete(d, "receipt_signature")
			signed, _ := core.Canonical(receiptBinding(d, variant))
			if !ed25519.Verify(f.secrets.s.Private.Public().(ed25519.PublicKey), signed, sig) {
				t.Fatal("receipt invalid")
			}
			if variant == "scan" {
				if len(m["member_sha256s"].([]any)) != 1 || m["member_sha256s"].([]any)[0] != wire.Digest(f.s3.objects["RAW_KEY_MARKER/data.csv"]) {
					t.Fatal("first-pass digest absent")
				}
			}
			reads := len(f.s3.requests)
			if e = f.h.Invoke(ctx); e != nil {
				t.Fatal(e)
			}
			if len(f.s3.requests) != reads {
				t.Fatal("redelivery rescanned")
			}
			r, _, _ := f.h.Ledger.record(ctx, j.Text("spec_id"))
			if r.State != "reported" {
				t.Fatal(r.State)
			}
		})
	}
}
func TestCommittedOutboxResentFirstAtFifteenMinutePoll(t *testing.T) {
	f := newFixture(t)
	j := f.job(t, 1, "scan")
	f.audit.fail = "committed"
	if f.h.Invoke(ctx) == nil {
		t.Fatal("expected crash after commit")
	}
	if len(f.backend.reports) != 0 {
		t.Fatal("intake happened before crash")
	}
	r, _, _ := f.h.Ledger.record(ctx, j.Text("spec_id"))
	saved, e := f.h.Ledger.Body(ctx, r, f.at)
	if e != nil {
		t.Fatal(e)
	}
	reads := len(f.s3.requests)
	f.at = f.at.Add(15 * time.Minute)
	f.backend.at = f.at
	f.backend.deadline = r.Pickup + 1920
	f.audit.fail = ""
	f.backend.calls = nil
	f.backend.work = ""
	if e = f.h.Invoke(ctx); e != nil {
		t.Fatal(e)
	}
	if len(f.backend.calls) < 2 || f.backend.calls[0] != "report" || f.backend.calls[1] != "work" || !bytes.Equal(saved, f.backend.reports[0]) {
		t.Fatal("report not exact/first", f.backend.calls)
	}
	if len(f.s3.requests) != reads {
		t.Fatal("re-scanned")
	}
}
func TestLostReportReplyResendsIdenticalBytes(t *testing.T) {
	f := newFixture(t)
	f.job(t, 1, "scan")
	f.backend.lostReport = true
	if f.h.Invoke(ctx) == nil {
		t.Fatal("lost response")
	}
	reads := len(f.s3.requests)
	f.at = f.at.Add(15 * time.Minute)
	f.backend.lostReport = false
	f.backend.work = ""
	if e := f.h.Invoke(ctx); e != nil {
		t.Fatal(e)
	}
	if len(f.backend.reports) != 2 || !bytes.Equal(f.backend.reports[0], f.backend.reports[1]) || len(f.s3.requests) != reads {
		t.Fatal("lost reply changed bytes or rescanned")
	}
}
func TestCrashBeforeCommitNeverRescansAndPickupDeadline(t *testing.T) {
	f := newFixture(t)
	j := f.job(t, 1, "scan")
	f.db.failPutAt = 3 // bootstrap lease, first chunk, descriptor
	if f.h.Invoke(ctx) == nil {
		t.Fatal("expected crash")
	}
	r, _, _ := f.h.Ledger.record(ctx, j.Text("spec_id"))
	if r.State != "running" {
		t.Fatal(r.State)
	}
	reads := len(f.s3.requests)
	f.at = f.at.Add(15 * time.Minute)
	if f.h.Invoke(ctx) == nil {
		t.Fatal("running not recoverable at 900s")
	}
	if len(f.s3.requests) != reads {
		t.Fatal("rescanned")
	}
	f.at = f.at.Add(15 * time.Minute)
	f.audit.fail = "interrupted"
	f.db.down = true
	if f.h.Invoke(ctx) == nil {
		t.Fatal("ledger unavailable")
	}
	f.db.down = false
	f.at = f.at.Add(121 * time.Second)
	f.backend.work = ""
	f.audit.fail = ""
	if e := f.h.Invoke(ctx); e != nil {
		t.Fatal(e)
	}
	r, _, _ = f.h.Ledger.record(ctx, j.Text("spec_id"))
	if r.State != "expired" || len(f.backend.reports) != 0 || len(f.s3.requests) != reads {
		t.Fatal("did not void locally at pickup deadline")
	}
}
func TestInterruptedInvocationEmitsTerminalAndLateReportsRefused(t *testing.T) {
	f := newFixture(t)
	j := f.job(t, 1, "scan")
	if _, e := Bootstrap(ctx, f.h.Config, f.h.Ledger, f.secrets, f.backend, f.at); e != nil {
		t.Fatal(e)
	}
	if fresh, e := f.h.Ledger.Admit(ctx, j, f.at); !fresh || e != nil {
		t.Fatal(e)
	}
	f.at = f.at.Add(1021 * time.Second)
	f.backend.work = ""
	if e := f.h.Invoke(ctx); e != nil {
		t.Fatal(e)
	}
	if len(f.backend.reports) != 1 || len(f.s3.heads) != 0 {
		t.Fatal("interrupted work scanned")
	}
	var body struct{ Variant string }
	json.Unmarshal(f.backend.reports[0], &body)
	if body.Variant != "terminal" {
		t.Fatal(body)
	}
	f2 := newFixture(t)
	j = f2.job(t, 2, "scan")
	_, e := f2.h.Ledger.Admit(ctx, j, f2.at)
	if e != nil {
		t.Fatal(e)
	}
	r, _, _ := f2.h.Ledger.record(ctx, j.Text("spec_id"))
	if f2.h.Ledger.Commit(ctx, r, []byte("{}"), f2.at.Add(1921*time.Second)) == nil {
		t.Fatal("late commit accepted")
	}
	f2.backend.deadline = r.Pickup + 1920
	f2.backend.at = f2.at.Add(1921 * time.Second)
	if f2.backend.Report(ctx, nil, []byte("{}"), j.Envelope.IID) == nil {
		t.Fatal("backend fixture accepted late report")
	}
}
func TestRefusalsPerformZeroWork(t *testing.T) {
	for _, mode := range []string{"bad_signature", "expired", "ledger", "logs", "snapshot", "clock", "secret"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			f.job(t, 1, "scan")
			switch mode {
			case "bad_signature":
				f.backend.work = f.backend.work[:len(f.backend.work)-5] + "AAAAA"
			case "expired":
				f.at = f.at.Add(25 * time.Hour)
			case "ledger":
				f.db.down = true
			case "logs":
				f.audit.fail = "accepted"
			case "snapshot":
				f.backend.snapshot += "x"
			case "clock":
				if e := f.h.Ledger.Observe(ctx, f.at.Add(301*time.Second)); e != nil {
					t.Fatal(e)
				}
			case "secret":
				f.secrets.down = true
			}
			if f.h.Invoke(ctx) == nil {
				t.Fatal("refusal accepted")
			}
			if len(f.s3.heads) > 0 || len(f.s3.requests) > 0 || len(f.backend.reports) > 0 {
				t.Fatal("refused spec performed work")
			}
		})
	}
}
func TestNonceAuthorizationRacesQuotaAndClock(t *testing.T) {
	for _, same := range []string{"nonce", "authorization", "spec"} {
		t.Run(same, func(t *testing.T) {
			f := newFixture(t)
			jobs := make([]wire.ScanJob, 20)
			for i := range jobs {
				jobs[i] = f.job(t, i+1, "probe")
			}
			for i := 1; i < len(jobs); i++ {
				if same == "spec" {
					jobs[i] = jobs[0]
				} else {
					field := "nonce"
					if same == "authorization" {
						field = "owner_authorization_id"
					}
					jobs[i].Payload[field] = jobs[0].Payload[field]
				}
			}
			var accepted atomic.Int32
			var wg sync.WaitGroup
			for _, j := range jobs {
				wg.Add(1)
				go func(j wire.ScanJob) {
					defer wg.Done()
					fresh, e := f.h.Ledger.Admit(ctx, j, f.at)
					if fresh && e == nil {
						accepted.Add(1)
					}
				}(j)
			}
			wg.Wait()
			if accepted.Load() != 1 {
				t.Fatal("race admitted", accepted.Load())
			}
		})
	}
	f := newFixture(t)
	f.db.conflicts = 2
	for i := 1; i <= 10; i++ {
		j := f.job(t, i, "probe")
		if fresh, e := f.h.Ledger.Admit(ctx, j, f.at); e != nil || !fresh {
			t.Fatal("quota request", i, e)
		}
		r, _, _ := f.h.Ledger.record(ctx, j.Text("spec_id"))
		if e := f.h.Ledger.Settle(ctx, r, f.at, "reported"); e != nil {
			t.Fatal(e)
		}
	}
	j := f.job(t, 11, "scan")
	if _, e := f.h.Ledger.Admit(ctx, j, f.at); e == nil {
		t.Fatal("11th accepted")
	}
	if ok, _ := f.h.Ledger.get(ctx, "nonce#"+j.Text("nonce"), &map[string]any{}); ok {
		t.Fatal("failed transaction consumed nonce")
	}
	if _, e := f.h.Ledger.Admit(ctx, j, f.at.Add(-301*time.Second)); e == nil {
		t.Fatal("clock rollback accepted")
	}
}
func TestChunkedOutboxIncompleteRecoveryAndCorruption(t *testing.T) {
	f := newFixture(t)
	j := f.job(t, 1, "scan")
	if _, e := f.h.Ledger.Admit(ctx, j, f.at); e != nil {
		t.Fatal(e)
	}
	r, _, _ := f.h.Ledger.record(ctx, j.Text("spec_id"))
	body := bytes.Repeat([]byte("privacy-safe-control"), 100000)
	if len(body) > MaxReport {
		t.Fatal("bad fixture")
	}
	f.db.failPutAt = 2
	if f.h.Ledger.Commit(ctx, r, body, f.at) == nil {
		t.Fatal("chunk interruption")
	}
	saved, _, _ := f.h.Ledger.record(ctx, j.Text("spec_id"))
	if saved.State != "running" {
		t.Fatal("partial chunks committed")
	}
	f.db.failPutAt = 0
	if e := f.h.Ledger.Commit(ctx, r, body, f.at); e != nil {
		t.Fatal(e)
	}
	saved, _, _ = f.h.Ledger.record(ctx, j.Text("spec_id"))
	restored, e := f.h.Ledger.Body(ctx, saved, f.at)
	if e != nil || !bytes.Equal(body, restored) || saved.Chunks < 2 {
		t.Fatal("chunk reconstruction", e)
	}
	f.db.mu.Lock()
	for k, v := range f.db.items {
		if strings.HasPrefix(k, "outbox#") {
			v["data"] = nil
			break
		}
	}
	f.db.mu.Unlock()
	if _, e = f.h.Ledger.Body(ctx, saved, f.at); e == nil {
		t.Fatal("corruption accepted")
	}
}
func TestEmptyWorkDoesNotTouchSource(t *testing.T) {
	f := newFixture(t)
	if e := f.h.Invoke(ctx); e != nil {
		t.Fatal(e)
	}
	if len(f.s3.heads) > 0 || len(f.s3.requests) > 0 || len(f.backend.reports) > 0 {
		t.Fatal("empty work scanned")
	}
}

func TestUnresolvedEvidenceSurvivesTTLUntilAcknowledgment(t *testing.T) {
	f := newFixture(t)
	j := f.job(t, 1, "scan")
	if _, e := f.h.Ledger.Admit(ctx, j, f.at); e != nil {
		t.Fatal(e)
	}
	r, _, _ := f.h.Ledger.record(ctx, j.Text("spec_id"))
	if e := f.h.Ledger.Commit(ctx, r, []byte("durable exact report"), f.at); e != nil {
		t.Fatal(e)
	}
	r, _, _ = f.h.Ledger.record(ctx, j.Text("spec_id"))
	f.db.mu.Lock()
	for k, v := range f.db.items {
		if k == "clock" || strings.HasPrefix(k, "outbox#") || k == "spec#"+j.Text("spec_id") {
			if v["expires_at"] != nil {
				t.Fatal("unresolved evidence eligible for deletion", k)
			}
		}
	}
	f.db.mu.Unlock()
	if _, e := f.h.Ledger.Body(ctx, r, f.at.Add(31*24*time.Hour)); e != nil {
		t.Fatal("unresolved body lost", e)
	}
	if e := f.h.Ledger.Settle(ctx, r, f.at, "reported"); e != nil {
		t.Fatal(e)
	}
	f.db.mu.Lock()
	defer f.db.mu.Unlock()
	for k, v := range f.db.items {
		if strings.HasPrefix(k, "outbox#") || k == "spec#"+j.Text("spec_id") {
			if v["expires_at"] == nil {
				t.Fatal("acknowledged evidence not eligible for cleanup", k)
			}
		}
	}
}
