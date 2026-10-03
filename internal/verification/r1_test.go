package verification

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/audit"
	"github.com/aidotmarket/aim-data-gateway/internal/config"
	"github.com/aidotmarket/aim-data-gateway/internal/inventory"
	"github.com/aidotmarket/aim-data-gateway/internal/ledger"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	core "github.com/aidotmarket/aim-data-gateway/verification"
)

// Replace the pinned source and re-sign both snapshot and spec, using test keys.
func (f *runnerFixture) sourceJob(t *testing.T, kind string, data []byte, variant string) (string, wire.ScanJob, wire.Snapshot, string) {
	t.Helper()
	token, j := f.job(t, 1, variant)
	sv := loadVector(t, "snapshot")
	raw, _ := wire.DecodeDocument(sv.Input["payload_b64"].(string), wire.MaxSnapshot)
	v, _ := core.ParseCanonical(raw)
	p := v.(map[string]any)
	m := p["members"].([]any)[0].(map[string]any)
	id := m["file_id"].(string)
	sum := sha256.Sum256(data)
	m["sha256"], m["size_bytes"] = hex.EncodeToString(sum[:]), int64(len(data))
	p["members"] = []any{m}
	raw, _ = core.Canonical(p)
	hash := wire.Digest(raw)
	sv.Input["payload_b64"], sv.Input["manifest_hash"] = base64.RawURLEncoding.EncodeToString(raw), hash
	snapshotToken, e := wire.Sign("aim-scan-snapshot+jwt", "test-only-scan-key", sv.Input, f.key)
	if e != nil {
		t.Fatal(e)
	}
	j.Payload["manifest_hash"] = hash
	raw, _ = core.Canonical(j.Payload)
	spec := loadVector(t, variant+"_spec")
	spec.Input["payload_b64"], spec.Input["spec_hash"], spec.Input["iid"] = base64.RawURLEncoding.EncodeToString(raw), wire.Digest(raw), j.Envelope.IID
	token, e = wire.Sign("aim-scan-spec+jwt", "test-only-scan-key", spec.Input, f.key)
	if e != nil {
		t.Fatal(e)
	}
	j, e = wire.VerifyScan(token, f.r.Pins(), f.r.GatewayID, f.r.Keys.Snapshot().RunnerID, f.r.Version, f.at)
	if e != nil {
		t.Fatal(e)
	}
	s, e := wire.VerifySnapshot(snapshotToken, f.r.Pins(), j)
	if e != nil {
		t.Fatal(e)
	}
	name := "hidden." + kind
	if e = os.WriteFile(filepath.Join(f.dir, name), data, 0600); e != nil {
		t.Fatal(e)
	}
	rec := inventory.Record{Phase1: inventory.Phase1{FileID: id, SizeBytes: int64(len(data)), Present: true}, Root: f.dir, Source: "data", RelativePath: name, SHA256: sum}
	if e = f.r.Ledger.PutFile(context.Background(), rec); e != nil {
		t.Fatal(e)
	}
	if e = f.r.Ledger.PutOffer(context.Background(), ledger.Offer{FileID: id, SHA256: m["sha256"].(string), ListingVersionID: s.ListingVersionID, IID: "hidden", State: "offered", KeyClass: "listing"}); e != nil {
		t.Fatal(e)
	}
	f.r.HTTP = &http.Client{Transport: transportFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(snapshotToken)), Request: req}, nil
	})}
	return token, j, s, snapshotToken
}

func TestE7SharedSchemaLateJSONAndBOM(t *testing.T) {
	late, e := os.ReadFile("../../verification/testdata/oracle/json_new_field.jsonl")
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		kind, hidden string
		data         []byte
	}{
		{"jsonl", "b", late}, {"csv", "id", []byte("\ufeffid,name\n1,secret\n")}, {"tsv", "id", []byte("\ufeffid\tname\n1\tsecret\n")},
	} {
		for _, rename := range []bool{false, true} {
			for _, mode := range []string{"probe", "scan", "preview"} {
				t.Run(tc.kind+"/"+mode+"/"+map[bool]string{false: "drop", true: "rename"}[rename], func(t *testing.T) {
					ctx := context.Background()
					f := newRunner(t)
					variant := mode
					if mode == "preview" {
						variant = "scan"
					}
					token, j, s, snapshot := f.sourceJob(t, tc.kind, tc.data, variant)
					rule := config.Columns{Drop: []string{tc.hidden}}
					if rename {
						rule = config.Columns{Rename: map[string]string{tc.hidden: "visible"}}
					}
					f.cfg.Columns = map[string]config.Columns{"data/hidden." + tc.kind: rule}
					if mode == "preview" {
						if _, e := f.r.Ledger.Admit(ctx, f.r.admission(j, snapshot), f.at); e != nil {
							t.Fatal(e)
						}
						before, _ := f.r.Ledger.VerificationEvents(ctx, 0)
						raw, e := f.r.Preview(ctx, s.Members[0].FileID, j.Text("spec_id"))
						if e == nil || e.Error() != E7Message || len(raw) != 0 {
							t.Fatal("preview disclosed hidden schema", e, string(raw))
						}
						after, _ := f.r.Ledger.VerificationEvents(ctx, 0)
						if len(before) != len(after) {
							t.Fatal("preview wrote events")
						}
					} else {
						f.start(t)
						if e := f.r.Submit(ctx, token); e != nil {
							t.Fatal(e)
						}
						a := f.wait(t, j.Text("spec_id"))
						var body struct {
							Variant  string
							Document string `json:"document_b64"`
						}
						json.Unmarshal(a.Result, &body)
						raw, _ := wire.DecodeDocument(body.Document, wire.MaxScanDocument)
						if a.State != "refused" || bytes.Contains(raw, []byte("\""+tc.hidden+"\"")) || bytes.Contains(raw, []byte("column_names")) || bytes.Contains(raw, []byte("null_rate")) || bytes.Contains(raw, []byte("secret")) {
							t.Fatal("hidden facts", string(raw))
						}
						if mode == "probe" && !bytes.Contains(raw, []byte(s.Members[0].FileID)) {
							t.Fatal("missing affected ID")
						}
						if mode == "scan" && body.Variant != "terminal" {
							t.Fatal("scan succeeded")
						}
						n := f.opens.Load()
						if e := f.r.Submit(ctx, token); e != nil || f.opens.Load() != n {
							t.Fatal("replay read source", e)
						}
					}
					var count, admissions int
					f.r.Ledger.DB.QueryRow("SELECT accepted_count FROM verification_daily").Scan(&count)
					f.r.Ledger.DB.QueryRow("SELECT count(*) FROM verification_admissions").Scan(&admissions)
					if count != 1 || admissions != 1 {
						t.Fatal("consent consumption", count, admissions)
					}
				})
			}
		}
	}
}

func TestConsentExpiresDuringSnapshotFetch(t *testing.T) {
	f := newRunner(t)
	token, j := f.job(t, 1, "scan")
	f.start(t)
	original := f.r.HTTP.Transport
	f.r.HTTP.Transport = transportFunc(func(req *http.Request) (*http.Response, error) {
		deadline, ok := req.Context().Deadline()
		if !ok || time.Until(deadline) > 31*time.Second {
			t.Error("snapshot deadline absent")
		}
		f.at = j.Expires.Add(301 * time.Second)
		return original.RoundTrip(req)
	})
	if e := f.r.Submit(context.Background(), token); e == nil || e.Error() != "consent_refused" {
		t.Fatal(e)
	}
	var n int
	f.r.Ledger.DB.QueryRow("SELECT count(*) FROM verification_admissions").Scan(&n)
	if n != 0 || f.opens.Load() != 0 {
		t.Fatal("expired consent read/admitted", n, f.opens.Load())
	}
}

func TestQueueRefusalStaysLocal(t *testing.T) {
	f := newRunner(t)
	f.r.queue = make(chan work, 1)
	f.r.queue <- work{}
	token, _ := f.job(t, 1, "scan")
	if e := f.r.Submit(context.Background(), token); e == nil {
		t.Fatal("queue accepted")
	}
	events, _ := f.r.Ledger.VerificationEvents(context.Background(), 0)
	if len(events) != 2 || events[1].RefusalCode != "queue_full" {
		t.Fatal(events)
	}
	if e := f.r.Log.Walk(func(a audit.Entry) error {
		if a.MessageType == "error" {
			t.Error("queue error relayed")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}

func TestTerminalLocalReason(t *testing.T) {
	f := newRunner(t)
	f.start(t)
	token, j := f.job(t, 1, "scan")
	f.r.OpenFile = func(ledger.File) (*os.File, error) { return nil, os.ErrNotExist }
	if e := f.r.Submit(context.Background(), token); e != nil {
		t.Fatal(e)
	}
	f.wait(t, j.Text("spec_id"))
	events, _ := f.r.Ledger.VerificationEvents(context.Background(), 0)
	if events[len(events)-1].RefusalCode != "source_unreachable" {
		t.Fatal(events)
	}
}

func TestFlushDoesNotWalkRetainedHistory(t *testing.T) {
	f := newRunner(t)
	entry, e := f.r.Log.Append("error", wire.GatewayError{Code: "fixed", Message: "fixed"})
	if e != nil {
		t.Fatal(e)
	}
	raw, e := wire.Canonical(entry)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(f.dir, "audit", "000000.jsonl")
	// Retain a large decodable history and poison its tail: any Walk would fail.
	history := bytes.Repeat(append(raw, '\n'), 30000)
	history = append(history, []byte("invalid retained tail\n")...)
	if e := os.WriteFile(path, history, 0600); e != nil {
		t.Fatal(e)
	}
	for range 10 {
		if e := f.r.Flush(context.Background()); e != nil {
			t.Fatal("poll walked history", e)
		}
	}
}

func TestAuditFailureStopsWorkAndRetainsOutbox(t *testing.T) {
	f := newRunner(t)
	open := f.r.OpenFile
	entered, release := make(chan struct{}), make(chan struct{})
	f.r.OpenFile = func(v ledger.File) (*os.File, error) {
		if f.opens.Load() == 0 {
			close(entered)
			<-release
		}
		return open(v)
	}
	f.start(t)
	tokenA, jA := f.job(t, 1, "scan")
	if e := f.r.Submit(context.Background(), tokenA); e != nil {
		t.Fatal(e)
	}
	<-entered
	// Fail only B's accepted event, after its received event has synced.
	f.r.Audit.mu.Lock()
	next := f.r.Audit.last + 2
	f.r.Audit.Sync = func(file *os.File) error {
		if f.r.Audit.last+1 == next {
			return errors.New("injected local sync failure")
		}
		return file.Sync()
	}
	f.r.Audit.mu.Unlock()
	tokenB, jB := f.job(t, 2, "scan")
	if e := f.r.Submit(context.Background(), tokenB); e == nil || f.r.health() == nil {
		t.Fatal("sync did not stop runner", e)
	}
	if e := f.r.Flush(context.Background()); e == nil {
		t.Fatal("flush allowed unsynced audit")
	}
	close(release)
	<-f.r.done
	n := f.opens.Load()
	time.Sleep(20 * time.Millisecond)
	if f.opens.Load() != n || n > 1 {
		t.Fatal("additional open after failure", f.opens.Load())
	}
	a, e := f.r.Ledger.Verification(context.Background(), jA.Text("spec_id"))
	if e != nil || len(a.Result) == 0 || a.AuditSeq.Valid {
		t.Fatal("outbox lost or reported", a, e)
	}
	b, e := f.r.Ledger.Verification(context.Background(), jB.Text("spec_id"))
	if e != nil || b.State != "accepted" {
		t.Fatal("B admission lost", b, e)
	}
	if e := f.r.Log.Walk(func(a audit.Entry) error {
		if a.MessageType == "scan_report" {
			t.Error("unsynced report appended")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	f.r.Close()
	local, e := OpenLocalAudit(f.dir, f.r.Audit.key)
	if e != nil {
		t.Fatal(e)
	}
	r := &Runner{Ledger: f.r.Ledger, Audit: local, Log: f.r.Log, Keys: f.r.Keys, GatewayID: f.r.GatewayID, Version: f.r.Version, Pins: f.r.Pins, Config: f.r.Config, Now: f.r.Now}
	if e := r.Recover(context.Background()); e != nil {
		t.Fatal(e)
	}
	events, _ := r.Ledger.VerificationEvents(context.Background(), 0)
	if local.last != events[len(events)-1].ID {
		t.Fatal("missing event not synced")
	}
	a, _ = r.Ledger.Verification(context.Background(), jA.Text("spec_id"))
	b, _ = r.Ledger.Verification(context.Background(), jB.Text("spec_id"))
	if !a.AuditSeq.Valid || !b.AuditSeq.Valid || b.State != "interrupted" {
		t.Fatal("restart did not reconcile", a, b)
	}
}

func TestStartupPrunesOnlyDeliveredProbes(t *testing.T) {
	f := newRunner(t)
	ctx := context.Background()
	snapshot := loadVector(t, "snapshot").Token
	for i, variant := range []string{"probe", "probe", "scan"} {
		_, j := f.job(t, i+1, variant)
		a := f.r.admission(j, snapshot)
		if _, e := f.r.Ledger.Admit(ctx, a, f.at); e != nil {
			t.Fatal(e)
		}
		if e := f.r.Ledger.SaveVerification(ctx, a.SpecID, "reported", []byte("retained report")); e != nil {
			t.Fatal(e)
		}
		if e := f.r.Ledger.AuditVerification(ctx, a.SpecID, uint64(i+1)); e != nil {
			t.Fatal(e)
		}
		if i != 1 {
			if _, e := f.r.Ledger.DB.Exec("UPDATE verification_admissions SET delivered=1 WHERE spec_id=?", a.SpecID); e != nil {
				t.Fatal(e)
			}
		}
	}
	f.at = f.at.Add(31 * 24 * time.Hour)
	f.start(t)
	if _, e := f.r.Ledger.Verification(ctx, "spec_1"); !errors.Is(e, sql.ErrNoRows) {
		t.Fatal("old delivered probe retained", e)
	}
	for _, id := range []string{"spec_2", "spec_3"} {
		if _, e := f.r.Ledger.Verification(ctx, id); e != nil {
			t.Fatal("pending report/hold pruned", id, e)
		}
	}
}

func TestE7RecheckedAtEveryMemberOpen(t *testing.T) {
	f := newRunner(t)
	data, e := os.ReadFile("../../verification/testdata/oracle/json_new_field.jsonl")
	if e != nil {
		t.Fatal(e)
	}
	_, _, snapshot, _ := f.sourceJob(t, "jsonl", data, "scan")
	src := &source{runner: f.r, snapshot: snapshot}
	if ids, e := src.eligibility(context.Background()); e != nil || len(ids) != 0 {
		t.Fatal(ids, e)
	}
	f.cfg.Columns = map[string]config.Columns{"data/hidden.jsonl": {Drop: []string{"b"}}}
	if handle, e := src.Open(context.Background(), snapshot.Members[0].FileID); !errors.Is(e, ErrE7) || handle != nil {
		t.Fatal("member open bypassed E7", handle, e)
	}
	if handle, e := src.OpenAt(context.Background(), snapshot.Members[0].FileID); !errors.Is(e, ErrE7) || handle != nil {
		t.Fatal("random member open bypassed E7", handle, e)
	}
}
