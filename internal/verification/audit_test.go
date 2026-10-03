package verification

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalAuditRecoveryAndTamper(t *testing.T) {
	f := newRunner(t)
	_, j := f.job(t, 1, "scan")
	a := f.r.admission(j, loadVector(t, "snapshot").Token)
	ctx := context.Background()
	if _, e := f.r.Ledger.Admit(ctx, a, f.at); e != nil {
		t.Fatal(e)
	}
	if e := f.r.Audit.Mirror(ctx, f.r.Ledger); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(filepath.Join(f.dir, "verification-audit.jsonl"))
	reopened, e := OpenLocalAudit(f.dir, f.r.Audit.key)
	if e != nil {
		t.Fatal(e)
	}
	if e = reopened.Mirror(ctx, f.r.Ledger); e != nil {
		t.Fatal(e)
	}
	after, _ := os.ReadFile(reopened.path)
	if string(before) != string(after) {
		t.Fatal("duplicate event")
	}
	if strings.Contains(string(after), f.dir) || strings.Contains(string(after), "column_names") {
		t.Fatal("local audit leak")
	}
	after[len(after)/2] ^= 1
	os.WriteFile(reopened.path, after, 0600)
	if _, e = OpenLocalAudit(f.dir, f.r.Audit.key); e == nil {
		t.Fatal("tamper accepted")
	}
}

func TestLocalAuditTornAppendRecoversByEventID(t *testing.T) {
	f := newRunner(t)
	_, j := f.job(t, 1, "scan")
	ctx := context.Background()
	if _, e := f.r.Ledger.Admit(ctx, f.r.admission(j, loadVector(t, "snapshot").Token), f.at); e != nil {
		t.Fatal(e)
	}
	if e := f.r.Audit.Mirror(ctx, f.r.Ledger); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(f.dir, "verification-audit.jsonl")
	full, _ := os.ReadFile(path)
	os.WriteFile(path, full[:len(full)-20], 0600)
	reopened, e := OpenLocalAudit(f.dir, f.r.Audit.key)
	if e != nil {
		t.Fatal(e)
	}
	if e = reopened.Mirror(ctx, f.r.Ledger); e != nil {
		t.Fatal(e)
	}
	actual, _ := os.ReadFile(path)
	if string(actual) != string(full) {
		t.Fatal("torn event not rebuilt exactly")
	}
}
