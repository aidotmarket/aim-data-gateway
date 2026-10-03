package ledger

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func verificationLedger(t *testing.T, path string) *Ledger {
	t.Helper()
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	l, e := Open(path, k, "gateway")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	return l
}
func admissionFixture(i int) Admission {
	return Admission{SpecID: fmt.Sprint("spec", i), RunnerID: "runner", ListingID: "listing", VersionID: "version", ManifestHash: "manifest", SpecHash: fmt.Sprint("hash", i), Nonce: fmt.Sprint("nonce", i), AuthorizationID: fmt.Sprint("auth", i), Variant: "scan", IID: fmt.Sprint("iid", i), Spec: []byte("signed"), Snapshot: []byte("snapshot"), Accepted: 1, Issued: 2, Expires: 3}
}
func TestVerificationAdmissionAtomic(t *testing.T) {
	ctx := context.Background()
	l := verificationLedger(t, filepath.Join(t.TempDir(), "db"))
	at := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		fresh, e := l.Admit(ctx, admissionFixture(i), at)
		if e != nil || !fresh {
			t.Fatal(i, e)
		}
	}
	if fresh, e := l.Admit(ctx, admissionFixture(0), at); e != nil || fresh {
		t.Fatal("duplicate", e)
	}
	if _, e := l.Admit(ctx, admissionFixture(10), at); e == nil {
		t.Fatal("11th accepted")
	}
	a := admissionFixture(0)
	a.SpecHash = "changed"
	if _, e := l.Admit(ctx, a, at); e == nil {
		t.Fatal("hash conflict")
	}
	a = admissionFixture(11)
	a.AuthorizationID = "auth0"
	if _, e := l.Admit(ctx, a, at.Add(24*time.Hour)); e == nil {
		t.Fatal("authorization reused")
	}
	a = admissionFixture(11)
	a.Nonce = "nonce0"
	if _, e := l.Admit(ctx, a, at.Add(24*time.Hour)); e == nil {
		t.Fatal("nonce reused")
	}
	if _, e := l.Admit(ctx, admissionFixture(12), at.Add(-301*time.Second)); e == nil {
		t.Fatal("clock rollback")
	}
	var n int
	if e := l.DB.QueryRow("SELECT count(*) FROM verification_admissions").Scan(&n); e != nil || n != 10 {
		t.Fatal("transaction leaked", n, e)
	}
}
func TestVerificationCrossConnectionClaim(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "db")
	l1 := verificationLedger(t, path)
	l2 := verificationLedger(t, path)
	var wg sync.WaitGroup
	var mu sync.Mutex
	claims := 0
	fresh := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			l := l1
			if i%2 == 1 {
				l = l2
			}
			a := admissionFixture(1)
			f, e := l.Admit(ctx, a, time.Now())
			if e != nil {
				t.Error(e)
				return
			}
			if f {
				mu.Lock()
				fresh++
				mu.Unlock()
			}
			f, e = l.ClaimVerification(ctx, a.SpecID)
			if e != nil {
				t.Error(e)
			}
			if f {
				mu.Lock()
				claims++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if claims != 1 || fresh != 1 {
		t.Fatal("ran twice", claims, fresh)
	}
	if e := l1.InterruptVerifications(ctx); e != nil {
		t.Fatal(e)
	}
	a, e := l1.Verification(ctx, "spec1")
	if e != nil || a.State != "interrupted" {
		t.Fatal(a, e)
	}
	if f, e := l2.Admit(ctx, admissionFixture(1), time.Now()); e != nil || f {
		t.Fatal("restart admitted twice")
	}
}
func TestVerificationReadOnlyAndRetention(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "db")
	l := verificationLedger(t, path)
	a := admissionFixture(1)
	old := time.Now().Add(-31 * 24 * time.Hour)
	if _, e := l.Admit(ctx, a, old); e != nil {
		t.Fatal(e)
	}
	l.SaveVerification(ctx, a.SpecID, "reported", []byte("result"))
	l.AuditVerification(ctx, a.SpecID, 1)
	if e := l.PruneVerification(ctx, time.Now()); e != nil {
		t.Fatal(e)
	}
	if _, e := l.Verification(ctx, a.SpecID); e != nil {
		t.Fatal("pending outbox pruned")
	}
	l.ReconcileVerification(ctx, 1)
	if e := l.PruneVerification(ctx, time.Now()); e != nil {
		t.Fatal(e)
	}
	if _, e := l.Verification(ctx, a.SpecID); e == nil {
		t.Fatal("terminal retained")
	}
	ro, e := OpenVerificationPreview(path)
	if e != nil {
		t.Fatal(e)
	}
	defer ro.Close()
	if _, e = ro.DB.Exec("DELETE FROM verification_clock"); e == nil {
		t.Fatal("preview writable")
	}
}
