package ledger

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/config"
	"github.com/aidotmarket/aim-data-gateway/internal/inventory"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
)

const fid = "0123456789abcdef0123456789abcdef"
const oid = "22222222-2222-4222-8222-222222222222"
const lvid = "33333333-3333-4333-8333-333333333333"
const jti = "44444444-4444-4444-8444-444444444444"

func fixture(t *testing.T, size int64) (*Ledger, wire.Permission, string) {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "gateway.db")
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	l, e := Open(path, key, "test")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	hash := sha256.Sum256([]byte("fixture"))
	blocks := [][32]byte{hash}
	if size == 0 {
		blocks = nil
	}
	r := inventory.Record{Phase1: inventory.Phase1{FileID: fid, SizeBytes: size, DisplayName: "file.bin"}, Source: "src", RelativePath: "file.bin", Root: t.TempDir(), SHA256: hash, BlockHashes: blocks, Mtime: time.Now()}
	if e = l.PutFile(ctx, r); e != nil {
		t.Fatal(e)
	}
	if e = l.PutOffer(ctx, Offer{FileID: fid, SHA256: inventory.SHAHex(r), ListingVersionID: lvid, IID: oid, State: "offered", KeyClass: "listing"}); e != nil {
		t.Fatal(e)
	}
	p := wire.Permission{Audience: oid, OrderID: oid, ListingVersionID: lvid, FileID: fid, SHA256: inventory.SHAHex(r), JTI: jti, IssuedAt: time.Now().Unix() - 1, StartDeadline: time.Now().Unix() + 60, TransferDeadline: time.Now().Unix() + 3600}
	_, e = l.DB.ExecContext(ctx, `INSERT INTO permissions(jti,oid,fid,sha256,sd,td,ro,state,bound_at) VALUES(?,?,?,?,?,?,?,'bound',?)`, p.JTI, p.OrderID, p.FileID, p.SHA256, p.StartDeadline, p.TransferDeadline, p.ResumeOffset, now())
	if e != nil {
		t.Fatal(e)
	}
	return l, p, path
}
func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func payload(t *testing.T, s string) wire.Receipt {
	t.Helper()
	parts := []byte(s)
	if len(s) > 0 && s[0] != '{' {
		a := 0
		b := 0
		for i, c := range s {
			if c == '.' {
				if a == 0 {
					a = i + 1
				} else {
					b = i
					break
				}
			}
		}
		var e error
		parts, e = base64.RawURLEncoding.DecodeString(s[a:b])
		must(t, e)
	}
	var r wire.Receipt
	must(t, json.Unmarshal(parts, &r))
	return r
}

func TestReservationProgressSettleAndRestart(t *testing.T) {
	ctx := context.Background()
	l, p, path := fixture(t, 20)
	r, e := l.Reserve(ctx, p, 0, 19)
	must(t, e)
	must(t, l.Progress(ctx, r.ID, 9))
	must(t, l.Settle(ctx, r.ID))
	rec, e := l.Receipt(ctx, oid, fid, "in_progress")
	must(t, e)
	if rec.TransmittedBytes != 10 || len(rec.Transmitted) != 1 || rec.Transmitted[0] != ([2]int64{0, 9}) {
		t.Fatalf("partial receipt: %+v", rec)
	}
	// A re-issued permission resumes coverage from the same order/file ledger.
	_, ackErr := l.Prepare(ctx, wire.Instruction{IID: oid, OrderID: oid, FileID: fid, SHA256: p.SHA256}, config.Config{})
	must(t, ackErr)
	r2, e := l.Reserve(ctx, p, 10, 19)
	must(t, e)
	must(t, l.Progress(ctx, r2.ID, 19))
	must(t, l.Settle(ctx, r2.ID))
	l.Close()
	l, e = Open(path, l.Key, l.KID)
	must(t, e)
	t.Cleanup(func() { l.Close() })
	rec, e = l.Receipt(ctx, oid, fid, "complete")
	must(t, e)
	if rec.TransmittedBytes != 20 || len(rec.Transmitted) != 1 || rec.Transmitted[0] != ([2]int64{0, 19}) {
		t.Fatalf("complete receipt: %+v", rec)
	}
	if _, e = l.Reserve(ctx, p, 0, 0); !errors.Is(e, ErrClosed) {
		t.Fatalf("closed jti: %v", e)
	}
	if _, e = l.Reserve(ctx, p, 10, 10); !errors.Is(e, ErrClosed) {
		t.Fatalf("closed jti for once-served range: %v", e)
	}
	var n int
	must(t, l.DB.QueryRow(`SELECT count(*) FROM receipts_outbox`).Scan(&n))
	if n != 4 {
		t.Fatalf("outbox count %d", n)
	}
	var body string
	must(t, l.DB.QueryRow(`SELECT body FROM receipts_outbox ORDER BY seq DESC LIMIT 1`).Scan(&body))
	if got := payload(t, body); got.Outcome != "complete" || got.TransmittedBytes != 20 {
		t.Fatalf("outbox receipt %+v", got)
	}
	var verified wire.Receipt
	must(t, wire.VerifyGatewayAnswer(body, "receipt", map[string]ed25519.PublicKey{"test": l.Key.Public().(ed25519.PublicKey)}, &verified))
	rows, e := l.DB.Query(`SELECT body FROM receipts_outbox`)
	must(t, e)
	complete := 0
	for rows.Next() {
		var raw string
		must(t, rows.Scan(&raw))
		if payload(t, raw).Outcome == "complete" {
			complete++
		}
	}
	must(t, rows.Err())
	rows.Close()
	if complete != 1 {
		t.Fatalf("complete receipts %d", complete)
	}
}

func TestCrashKeepsOneWindowAndUnusedBytesReturn(t *testing.T) {
	ctx := context.Background()
	l, p, path := fixture(t, 3*window)
	r, e := l.Reserve(ctx, p, 0, 3*window-1)
	must(t, e)
	must(t, l.Progress(ctx, r.ID, window-1))
	l.Close()
	l, e = Open(path, l.Key, l.KID)
	must(t, e)
	t.Cleanup(func() { l.Close() })
	var end int64
	must(t, l.DB.QueryRow(`SELECT max(end) FROM serves`).Scan(&end))
	if end != 2*window-1 {
		t.Fatalf("reserved through %d", end)
	}
	r, e = l.Reserve(ctx, p, 2*window, 3*window-1)
	must(t, e)
	must(t, l.Settle(ctx, r.ID))
	var count int
	must(t, l.DB.QueryRow(`SELECT count(*) FROM serves WHERE start>=?`, 2*window).Scan(&count))
	if count != 0 {
		t.Fatalf("unused reservation remains: %d", count)
	}
}

func TestFragmentationAndPrepare(t *testing.T) {
	ctx := context.Background()
	l, p, _ := fixture(t, 3000)
	for i := int64(0); i < 1024; i++ {
		start := 2*i + 1
		r, e := l.Reserve(ctx, p, start, start)
		must(t, e)
		must(t, l.Progress(ctx, r.ID, start))
		must(t, l.Settle(ctx, r.ID))
	}
	ack, e := l.Prepare(ctx, wire.Instruction{IID: oid, OrderID: oid, FileID: fid, SHA256: p.SHA256}, config.Config{})
	must(t, e)
	if ack.IntervalCount != 1024 || ack.ResumeOffset != 0 {
		t.Fatalf("prepare %+v", ack)
	}
	if _, e = l.Reserve(ctx, p, 2050, 2050); !errors.Is(e, ErrFragmented) {
		t.Fatalf("isolated admission: %v", e)
	}
	r, e := l.Reserve(ctx, p, 0, 0)
	must(t, e)
	must(t, l.Progress(ctx, r.ID, 0))
	must(t, l.Settle(ctx, r.ID))
	rec, e := l.Receipt(ctx, oid, fid, "in_progress")
	must(t, e)
	if len(rec.Transmitted) > 1025 {
		t.Fatalf("intervals %d", len(rec.Transmitted))
	}
}

func TestThirdServeRefusedAndReissueResume(t *testing.T) {
	ctx := context.Background()
	l, p, _ := fixture(t, 20)
	for i := 0; i < 2; i++ {
		r, e := l.Reserve(ctx, p, 0, 4)
		must(t, e)
		must(t, l.Progress(ctx, r.ID, 4))
		must(t, l.Settle(ctx, r.ID))
	}
	if _, e := l.Reserve(ctx, p, 0, 4); !errors.Is(e, ErrExhausted) {
		t.Fatalf("third serve: %v", e)
	}
	r, e := l.Reserve(ctx, p, 5, 9)
	must(t, e)
	must(t, l.Progress(ctx, r.ID, 9))
	must(t, l.Settle(ctx, r.ID))
	ack, e := l.Revoke(ctx, p.JTI)
	must(t, e)
	if ack.StateBefore != "active" {
		t.Fatalf("revoke %+v", ack)
	}
	p.JTI = "55555555-5555-4555-8555-555555555555"
	p.ResumeOffset = 10
	r, e = l.Reserve(ctx, p, 10, 19)
	must(t, e)
	must(t, l.Progress(ctx, r.ID, 19))
	must(t, l.Settle(ctx, r.ID))
	receipt, e := l.Receipt(ctx, oid, fid, "complete")
	must(t, e)
	if receipt.Outcome != "complete" || receipt.TransmittedBytes != 20 || len(receipt.JTIs) != 2 {
		t.Fatalf("reissued receipt %+v", receipt)
	}
}

func TestOpenIsolatedCountsBeforeAdmission(t *testing.T) {
	ctx := context.Background()
	l, p, _ := fixture(t, 3000)
	for i := int64(0); i < 1023; i++ {
		_, e := l.DB.Exec(`INSERT INTO transmitted(oid,fid,start,end) VALUES(?,?,?,?)`, oid, fid, 2*i+1, 2*i+1)
		must(t, e)
	}
	open, e := l.Reserve(ctx, p, 2050, 2050)
	must(t, e)
	if _, e = l.Reserve(ctx, p, 2052, 2052); !errors.Is(e, ErrFragmented) {
		t.Fatalf("open isolated boundary: %v", e)
	}
	r, e := l.Reserve(ctx, p, 0, 0)
	must(t, e)
	must(t, l.Settle(ctx, r.ID))
	must(t, l.Settle(ctx, open.ID))
}

func TestUnknownRevocationBlocksLaterBind(t *testing.T) {
	ctx := context.Background()
	l, p, _ := fixture(t, 20)
	p.JTI = "77777777-7777-4777-8777-777777777777"
	ack, e := l.Revoke(ctx, p.JTI)
	must(t, e)
	if ack.StateBefore != "unknown" {
		t.Fatalf("ack %+v", ack)
	}
	if _, e = l.Reserve(ctx, p, 0, 0); !errors.Is(e, ErrClosed) {
		t.Fatalf("revoked permission admitted: %v", e)
	}
}

func TestPrepareRefusals(t *testing.T) {
	ctx := context.Background()
	l, p, _ := fixture(t, 20)
	i := wire.Instruction{IID: oid, OrderID: oid, FileID: fid, SHA256: p.SHA256}
	check := func(want string, c config.Config) {
		t.Helper()
		a, e := l.Prepare(ctx, i, c)
		must(t, e)
		if a.Refusal == nil || *a.Refusal != want {
			t.Fatalf("want %s, got %+v", want, a)
		}
	}
	check("outside_ceiling", config.Config{OfferCeiling: []string{"other/*"}})
	check("awaiting_local_approval", config.Config{OfferRequiresLocalApproval: true})
	must(t, l.PutOffer(ctx, Offer{FileID: fid, SHA256: p.SHA256, ListingVersionID: lvid, IID: oid, State: "offered", KeyClass: "permission"}))
	check("not_offered", config.Config{})
	must(t, l.PutOffer(ctx, Offer{FileID: fid, SHA256: p.SHA256, ListingVersionID: lvid, IID: oid, State: "offered", KeyClass: "listing"}))
	must(t, l.MarkChanged(ctx, fid))
	check("file_changed", config.Config{})
	i.FileID = "ffffffffffffffffffffffffffffffff"
	check("file_missing", config.Config{})
}

func TestEmptyFileCompletesOnce(t *testing.T) {
	ctx := context.Background()
	l, p, _ := fixture(t, 0)
	must(t, l.FinishEmpty(ctx, p))
	if e := l.FinishEmpty(ctx, p); !errors.Is(e, ErrClosed) {
		t.Fatalf("empty replay: %v", e)
	}
	var n int
	must(t, l.DB.QueryRow(`SELECT count(*) FROM receipts_outbox`).Scan(&n))
	if n != 1 {
		t.Fatalf("complete count %d", n)
	}
}

func TestConcurrentFragmentationBoundary(t *testing.T) {
	ctx := context.Background()
	l, p, _ := fixture(t, 5000)
	for i := int64(0); i < 1023; i++ {
		_, e := l.DB.Exec(`INSERT INTO transmitted(oid,fid,start,end) VALUES(?,?,?,?)`, oid, fid, 2*i+1, 2*i+1)
		must(t, e)
	}
	var wg sync.WaitGroup
	var accepted atomic.Int32
	errs := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			q := p
			q.JTI = fmt.Sprintf("%08d-7777-4777-8777-777777777777", i)
			r, e := l.Reserve(ctx, q, int64(3000+2*i), int64(3000+2*i))
			if e == nil {
				accepted.Add(1)
				return
			}
			if !errors.Is(e, ErrFragmented) {
				errs <- e
			}
			_ = r
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	if accepted.Load() != 1 {
		t.Fatalf("accepted %d isolated requests", accepted.Load())
	}
}

func TestExtendingShortWriteCapsAt1025(t *testing.T) {
	ctx := context.Background()
	l, p, _ := fixture(t, 5000)
	for i := int64(0); i < 1024; i++ {
		_, e := l.DB.Exec(`INSERT INTO transmitted(oid,fid,start,end) VALUES(?,?,?,?)`, oid, fid, 2*i+3, 2*i+3)
		must(t, e)
	}
	r, e := l.Reserve(ctx, p, 0, 2)
	must(t, e)
	must(t, l.Progress(ctx, r.ID, 0))
	must(t, l.Settle(ctx, r.ID))
	var n int
	must(t, l.DB.QueryRow(`SELECT count(*) FROM transmitted`).Scan(&n))
	if n != 1025 {
		t.Fatalf("interval count after short write: %d", n)
	}
	if _, e = l.Reserve(ctx, p, 3000, 3000); !errors.Is(e, ErrFragmented) {
		t.Fatalf("isolated boundary: %v", e)
	}
}

func TestPrepareCoverageExhausted(t *testing.T) {
	ctx := context.Background()
	l, p, _ := fixture(t, 20)
	_, e := l.DB.Exec(`INSERT INTO serves(oid,fid,start,end,count) VALUES(?,?,?,?,2)`, oid, fid, 0, 0)
	must(t, e)
	a, e := l.Prepare(ctx, wire.Instruction{IID: oid, OrderID: oid, FileID: fid, SHA256: p.SHA256}, config.Config{})
	must(t, e)
	if a.Refusal == nil || *a.Refusal != "coverage_exhausted" || a.MaxServeCount != 2 {
		t.Fatalf("prepare %+v", a)
	}
}

func TestGLM2RepeatedCrashesNeverAllowThirdWrite(t *testing.T) {
	ctx := context.Background()
	l, p, path := fixture(t, 20)
	key, kid := l.Key, l.KID
	for attempt := 0; attempt < 2; attempt++ {
		_, e := l.Reserve(ctx, p, 0, 0) // Simulate one written byte without a checkpoint.
		must(t, e)
		must(t, l.Close())
		l, e = Open(path, key, kid)
		must(t, e)
	}
	if _, e := l.Reserve(ctx, p, 0, 0); !errors.Is(e, ErrExhausted) {
		t.Fatalf("third write admitted after two crashes: %v", e)
	}
}

func TestGLM3CrashAfterFullProgressQueuesCompleteOnce(t *testing.T) {
	ctx := context.Background()
	l, p, path := fixture(t, 20)
	key, kid := l.Key, l.KID
	r, e := l.Reserve(ctx, p, 0, 19)
	must(t, e)
	must(t, l.Progress(ctx, r.ID, 19))
	must(t, l.Close())
	l, e = Open(path, key, kid)
	must(t, e)
	must(t, l.Close())
	l, e = Open(path, key, kid)
	must(t, e)
	var n int
	must(t, l.DB.QueryRow(`SELECT count(*) FROM completed WHERE oid=? AND fid=?`, oid, fid).Scan(&n))
	if n != 1 {
		t.Fatalf("complete rows: %d", n)
	}
	var state string
	must(t, l.DB.QueryRow(`SELECT state FROM permissions WHERE jti=?`, p.JTI).Scan(&state))
	if state != "closed" {
		t.Fatalf("permission: %s", state)
	}
	var body string
	must(t, l.DB.QueryRow(`SELECT body FROM receipts_outbox ORDER BY seq DESC LIMIT 1`).Scan(&body))
	if payload(t, body).Outcome != "complete" {
		t.Fatalf("last receipt: %s", body)
	}
}

func TestGemini2PrepareEmptyBeforeAndAfterCompletion(t *testing.T) {
	ctx := context.Background()
	l, p, _ := fixture(t, 0)
	a, e := l.Prepare(ctx, wire.Instruction{IID: oid, OrderID: oid, FileID: fid, SHA256: p.SHA256}, config.Config{})
	must(t, e)
	if !a.Ready || a.Refusal != nil {
		t.Fatalf("untransmitted empty: %+v", a)
	}
	must(t, l.FinishEmpty(ctx, p))
	a, e = l.Prepare(ctx, wire.Instruction{IID: oid, OrderID: oid, FileID: fid, SHA256: p.SHA256}, config.Config{})
	must(t, e)
	if a.Refusal == nil || *a.Refusal != "complete" {
		t.Fatalf("completed empty: %+v", a)
	}
}

func TestGLM5EmptyCompletionClosesEveryJTI(t *testing.T) {
	ctx := context.Background()
	l, p, _ := fixture(t, 0)
	other := p
	other.JTI = "55555555-5555-4555-8555-555555555555"
	_, e := l.DB.Exec(`INSERT INTO permissions(jti,oid,fid,sha256,sd,td,ro,state) VALUES(?,?,?,?,?,?,?,'issued')`, other.JTI, oid, fid, p.SHA256, p.StartDeadline, p.TransferDeadline, 0)
	must(t, e)
	must(t, l.FinishEmpty(ctx, p))
	if e = l.FinishEmpty(ctx, other); !errors.Is(e, ErrClosed) {
		t.Fatalf("second empty response: %v", e)
	}
	var n int
	must(t, l.DB.QueryRow(`SELECT count(*) FROM permissions WHERE oid=? AND fid=? AND state='closed'`, oid, fid).Scan(&n))
	if n != 2 {
		t.Fatalf("closed jtis: %d", n)
	}
}

func TestDeepSeek3NewJTIAfterCompleteRefused(t *testing.T) {
	ctx := context.Background()
	l, p, _ := fixture(t, 20)
	r, e := l.Reserve(ctx, p, 0, 19)
	must(t, e)
	must(t, l.Progress(ctx, r.ID, 19))
	must(t, l.Settle(ctx, r.ID))
	p.JTI = "55555555-5555-4555-8555-555555555555"
	if _, e = l.Reserve(ctx, p, 0, 19); !errors.Is(e, ErrClosed) {
		t.Fatalf("new jti admitted: %v", e)
	}
}

func TestDeepSeek6UnsignedReceiptRefused(t *testing.T) {
	ctx := context.Background()
	l, p, _ := fixture(t, 0)
	l.Key = nil
	if e := l.FinishEmpty(ctx, p); e == nil {
		t.Fatal("unsigned completion committed")
	}
	var n int
	must(t, l.DB.QueryRow(`SELECT count(*) FROM receipts_outbox`).Scan(&n))
	if n != 0 {
		t.Fatalf("unsigned outbox rows: %d", n)
	}
}

func TestDeepSeek7PutOfferClearsApproval(t *testing.T) {
	ctx := context.Background()
	l, p, _ := fixture(t, 20)
	must(t, l.Approve(ctx, fid, p.SHA256, lvid))
	must(t, l.PutOffer(ctx, Offer{FileID: fid, SHA256: p.SHA256, ListingVersionID: lvid, State: "withdrawn", KeyClass: "listing"}))
	must(t, l.PutOffer(ctx, Offer{FileID: fid, SHA256: p.SHA256, ListingVersionID: lvid, State: "offered", KeyClass: "listing"}))
	o, e := l.Offer(ctx, fid, p.SHA256, lvid)
	must(t, e)
	if o.ApprovedAt.Valid {
		t.Fatal("approval carried into new offer")
	}
}

func TestGLM1Gemini1DeepSeek4ConcurrentSameJTIStopsAfterCoverage(t *testing.T) {
	ctx := context.Background()
	l, p, _ := fixture(t, 20)
	a, e := l.Reserve(ctx, p, 0, 19)
	must(t, e)
	b, e := l.Reserve(ctx, p, 0, 19)
	must(t, e)
	start := make(chan struct{})
	var wg sync.WaitGroup
	var wrote atomic.Int32
	errs := make(chan error, 2)
	for _, id := range []int64{a.ID, b.ID} {
		wg.Add(1)
		go func(id int64) {
			defer wg.Done()
			<-start
			n, err := l.WriteChunk(ctx, id, make([]byte, 20), func(b []byte) (int, error) { wrote.Add(1); return len(b), nil })
			if err == nil && n != 20 {
				errs <- fmt.Errorf("short write %d", n)
			}
			if err != nil && !errors.Is(err, ErrClosed) {
				errs <- err
			}
		}(id)
	}
	close(start)
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	if wrote.Load() != 1 {
		t.Fatalf("full writes: %d", wrote.Load())
	}
	must(t, l.Settle(ctx, a.ID))
	must(t, l.Settle(ctx, b.ID))
}

func TestGLM4DeadlineStopsNextWriteAndQueuesAborted(t *testing.T) {
	ctx := context.Background()
	l, p, _ := fixture(t, 20)
	r, e := l.Reserve(ctx, p, 0, 19)
	must(t, e)
	_, e = l.DB.Exec(`UPDATE permissions SET td=? WHERE jti=?`, time.Now().Unix()-1, p.JTI)
	must(t, e)
	called := false
	_, e = l.WriteChunk(ctx, r.ID, []byte{1}, func(b []byte) (int, error) { called = true; return len(b), nil })
	if !errors.Is(e, ErrDeadline) || called {
		t.Fatalf("expired write: %v called=%v", e, called)
	}
	must(t, l.SettleOutcome(ctx, r.ID, "aborted_deadline"))
	var body string
	must(t, l.DB.QueryRow(`SELECT body FROM receipts_outbox ORDER BY seq DESC LIMIT 1`).Scan(&body))
	if payload(t, body).Outcome != "aborted_deadline" {
		t.Fatalf("receipt: %s", body)
	}
}

func TestGLM4SlowWriterDeadlineQueuesAborted(t *testing.T) {
	ctx := context.Background()
	l, p, _ := fixture(t, 20)
	r, e := l.Reserve(ctx, p, 0, 19)
	must(t, e)
	td := time.Now().Unix() + 2
	_, e = l.DB.Exec(`UPDATE permissions SET td=? WHERE jti=?`, td, p.JTI)
	must(t, e)
	_, e = l.WriteChunk(ctx, r.ID, []byte{1}, func([]byte) (int, error) {
		time.Sleep(time.Until(time.Unix(td, 0)) + 10*time.Millisecond)
		return 0, errors.New("network write deadline")
	})
	if !errors.Is(e, ErrDeadline) {
		t.Fatalf("slow writer: %v", e)
	}
	must(t, l.SettleOutcome(ctx, r.ID, "aborted_deadline"))
	var body string
	must(t, l.DB.QueryRow(`SELECT body FROM receipts_outbox ORDER BY seq DESC LIMIT 1`).Scan(&body))
	if payload(t, body).Outcome != "aborted_deadline" {
		t.Fatalf("receipt: %s", body)
	}
}
