package verification

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aidotmarket/aim-data-gateway/internal/audit"
	"github.com/aidotmarket/aim-data-gateway/internal/config"
	"github.com/aidotmarket/aim-data-gateway/internal/inventory"
	"github.com/aidotmarket/aim-data-gateway/internal/ledger"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	core "github.com/aidotmarket/aim-data-gateway/verification"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fixtureVector struct {
	Token  string
	Input  map[string]any
	Source map[string]string `json:"source_hex"`
	Seed   string            `json:"test_only_seed_hex"`
	Public string            `json:"test_only_public_hex"`
}

func loadVector(t *testing.T, name string) fixtureVector {
	t.Helper()
	raw, e := os.ReadFile("../../contract/vectors/verification/" + name + ".json")
	if e != nil {
		t.Fatal(e)
	}
	var v fixtureVector
	if e = json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	return v
}

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type runnerFixture struct {
	r     *Runner
	dir   string
	cfg   config.Config
	opens atomic.Int64
	v     fixtureVector
	key   ed25519.PrivateKey
	at    time.Time
}

func newRunner(t *testing.T) *runnerFixture {
	t.Helper()
	ctx := context.Background()
	f := &runnerFixture{dir: t.TempDir(), v: loadVector(t, "scan_spec"), at: time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)}
	f.dir, _ = filepath.EvalSymlinks(f.dir)
	seed, _ := hex.DecodeString(f.v.Seed)
	f.key = ed25519.NewKeyFromSeed(seed)
	pub := f.key.Public().(ed25519.PublicKey)
	pins := map[string]ed25519.PublicKey{"test-only-scan-key": pub}
	gateway := f.v.Input["aud"].(string)
	runner := f.v.Input["runner_id"].(string)
	_, identity, _ := ed25519.GenerateKey(rand.Reader)
	l, e := ledger.Open(filepath.Join(f.dir, "gateway.db"), identity, "gateway")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	log, e := audit.Open(filepath.Join(f.dir, "audit"), identity)
	if e != nil {
		t.Fatal(e)
	}
	a, e := OpenLocalAudit(f.dir, identity)
	if e != nil {
		t.Fatal(e)
	}
	k, e := OpenKeys(f.dir, "1.2.3", "sha256:"+strings.Repeat("a", 64))
	if e != nil {
		t.Fatal(e)
	}
	k.Binding.RunnerID = runner
	k.Binding.ReceiptKeyID = "77777777-7777-4777-8777-777777777777"
	ack := loadVector(t, "runner_ack")
	ack.Input["registration_nonce"] = k.Binding.RegistrationNonce
	ack.Input["scanner_version"] = k.Binding.ScannerVersion
	ack.Input["image_digest"] = k.Binding.ImageDigest
	ackToken, _ := wire.Sign("aim-scan-runner-ack+jwt", "test-only-scan-key", ack.Input, f.key)
	if e = k.Acknowledge(ackToken, gateway, pins, f.at); e != nil {
		t.Fatal(e)
	}
	f.cfg = config.Config{Sources: []config.Source{{Name: "data", Path: f.dir}}, OfferCeiling: []string{"data/*"}, VerificationEnabled: true}
	j, e := wire.VerifyScan(f.v.Token, pins, gateway, runner, "1.2.3", f.at)
	if e != nil {
		t.Fatal(e)
	}
	sv := loadVector(t, "snapshot")
	s, e := wire.VerifySnapshot(sv.Token, pins, j)
	if e != nil {
		t.Fatal(e)
	}
	for i, m := range s.Members {
		raw, _ := hex.DecodeString(sv.Source[m.FileID])
		name := fmt.Sprintf("file%d.csv", i)
		if e = os.WriteFile(filepath.Join(f.dir, name), raw, 0600); e != nil {
			t.Fatal(e)
		}
		sha, _ := hex.DecodeString(m.SHA256)
		record := inventory.Record{Phase1: inventory.Phase1{FileID: m.FileID, SizeBytes: m.Size, Present: true}, Root: f.dir, Source: "data", RelativePath: name}
		copy(record.SHA256[:], sha)
		if e = l.PutFile(ctx, record); e != nil {
			t.Fatal(e)
		}
		if e = l.PutOffer(ctx, ledger.Offer{FileID: m.FileID, SHA256: m.SHA256, ListingVersionID: s.ListingVersionID, IID: "offer", State: "offered", KeyClass: "listing"}); e != nil {
			t.Fatal(e)
		}
	}
	f.r = &Runner{Ledger: l, Audit: a, Log: log, Keys: k, GatewayID: gateway, Version: "1.2.3", Pins: func() map[string]ed25519.PublicKey { return pins }, Config: func() config.Config { return f.cfg }, Now: func() time.Time { return f.at }}
	f.r.OpenFile = func(v ledger.File) (*os.File, error) {
		f.opens.Add(1)
		return (inventory.Record{Root: v.Root, RelativePath: v.RelativePath}).Open()
	}
	f.r.HTTP = &http.Client{Transport: transportFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "api.ai.market" || !strings.HasPrefix(req.URL.Path, "/api/v1/verification-runners/") {
			t.Error("destination")
		}
		var claims struct {
			Runner  string `json:"runner_id"`
			Gateway string `json:"gateway_id"`
			Method  string `json:"method"`
			Path    string `json:"path"`
			Nonce   string `json:"nonce"`
			IAT     int64  `json:"iat"`
		}
		if e := wire.Verify(strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer "), "aim-verification-snapshot-request+jwt", map[string]ed25519.PublicKey{k.Binding.ReceiptKeyID: k.Private.Public().(ed25519.PublicKey)}, &claims); e != nil || claims.Path != req.URL.Path || claims.Method != "GET" {
			t.Error("snapshot auth", e)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(sv.Token)), Request: req}, nil
	})}
	return f
}
func (f *runnerFixture) start(t *testing.T) {
	t.Helper()
	if e := f.r.Start(context.Background(), f.dir); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(f.r.Close)
}
func (f *runnerFixture) wait(t *testing.T, id string) ledger.Admission {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		a, e := f.r.Ledger.Verification(context.Background(), id)
		if e == nil && a.AuditSeq.Valid {
			return a
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("report not durable")
	return ledger.Admission{}
}
func (f *runnerFixture) job(t *testing.T, index int, variant string) (string, wire.ScanJob) {
	t.Helper()
	v := loadVector(t, variant+"_spec")
	raw, _ := wire.DecodeDocument(v.Input["payload_b64"].(string), 40000)
	p, _ := core.ParseCanonical(raw)
	payload := p.(map[string]any)
	payload["spec_id"] = fmt.Sprintf("spec_%d", index)
	payload["owner_authorization_id"] = fmt.Sprintf("auth_%d", index)
	payload["nonce"] = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(index + 1)}, 32))
	b, _ := core.Canonical(payload)
	v.Input["payload_b64"] = base64.RawURLEncoding.EncodeToString(b)
	v.Input["spec_hash"] = wire.Digest(b)
	v.Input["iid"] = fmt.Sprintf("88888888-8888-4888-8888-%012d", index)
	token, e := wire.Sign("aim-scan-spec+jwt", "test-only-scan-key", v.Input, f.key)
	if e != nil {
		t.Fatal(e)
	}
	j, e := wire.VerifyScan(token, f.r.Pins(), f.r.GatewayID, f.r.Keys.Binding.RunnerID, f.r.Version, f.at)
	if e != nil {
		t.Fatal(e)
	}
	return token, j
}
func TestLivePreviewParityReplayAndOutbox(t *testing.T) {
	ctx := context.Background()
	f := newRunner(t)
	token, j := f.job(t, 1, "scan")
	s, e := wire.VerifySnapshot(loadVector(t, "snapshot").Token, f.r.Pins(), j)
	if e != nil {
		t.Fatal(e)
	}
	a := f.r.admission(j, loadVector(t, "snapshot").Token)
	if _, e = f.r.Ledger.Admit(ctx, a, f.at); e != nil {
		t.Fatal(e)
	}
	before, _ := f.r.Ledger.Verifications(ctx)
	preview, e := f.r.Preview(ctx, s.Members[0].FileID, j.Text("spec_id"))
	if e != nil {
		t.Fatal(e)
	}
	after, _ := f.r.Ledger.Verifications(ctx)
	if len(before) != len(after) {
		t.Fatal("preview wrote")
	}
	var pending struct{ Facts core.Facts }
	if e = json.Unmarshal(preview, &pending); e != nil {
		t.Fatal(e)
	}
	if e = f.r.Audit.Mirror(ctx, f.r.Ledger); e != nil {
		t.Fatal(e)
	}
	if e = f.r.run(ctx, j, s); e != nil {
		t.Fatal(e)
	}
	saved, e := f.r.Preview(ctx, s.Members[1].FileID, j.Text("spec_id"))
	if e != nil {
		t.Fatal(e)
	}
	var report map[string]json.RawMessage
	if e = json.Unmarshal(saved, &report); e != nil {
		t.Fatal(e)
	}
	facts, _ := core.Canonical(pending.Facts.Objects)
	if !bytes.Equal(facts, report["objects"]) {
		t.Fatal("preview drift")
	}
	if bytes.Contains(saved, []byte("relative_path")) || bytes.Contains(saved, []byte(f.dir)) {
		t.Fatal("path leak")
	}
	n := f.opens.Load()
	seq := f.r.Log.Sequence()
	f.r.queue = make(chan work, 1)
	if e = f.r.Submit(ctx, token); e != nil {
		t.Fatal(e)
	}
	if f.opens.Load() != n || seq != f.r.Log.Sequence() {
		t.Fatal("duplicate opens/appends")
	}
	// Simulate an append-before-SQL crash: full history reconciliation is recovery-only.
	f.r.Ledger.DB.Exec("UPDATE verification_admissions SET audit_seq=NULL")
	if e = f.r.Recover(ctx); e != nil {
		t.Fatal(e)
	}
	if f.r.Log.Sequence() != seq {
		t.Fatal("duplicate outbox")
	}
}
func TestAdmissionZeroOpens(t *testing.T) {
	for _, kind := range []string{"eleventh", "ledger_failure", "audit_sync_failure", "replay", "outside_ceiling", "withdrawn", "snapshot_tamper", "snapshot_cap", "queue_full", "wrong_version", "disabled"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			f := newRunner(t)
			if kind != "queue_full" {
				f.start(t)
			}
			token, j := f.job(t, 11, "scan")
			switch kind {
			case "eleventh":
				for i := 0; i < 10; i++ {
					_, job := f.job(t, i, "probe")
					if _, e := f.r.Ledger.Admit(ctx, f.r.admission(job, loadVector(t, "snapshot").Token), f.at); e != nil {
						t.Fatal(e)
					}
				}
			case "ledger_failure":
				f.r.Ledger.Close()
			case "audit_sync_failure":
				calls := 0
				f.r.Audit.Sync = func(file *os.File) error {
					calls++
					if calls == 2 {
						return errors.New("injected sync failure")
					}
					return file.Sync()
				}
			case "replay":
				_, job := f.job(t, 1, "scan")
				a := f.r.admission(job, loadVector(t, "snapshot").Token)
				a.Nonce = j.Text("nonce")
				if _, e := f.r.Ledger.Admit(ctx, a, f.at); e != nil {
					t.Fatal(e)
				}
			case "outside_ceiling":
				f.cfg.OfferCeiling = []string{"outside/*"}
			case "withdrawn":
				f.r.Ledger.DB.Exec("UPDATE offers SET state='withdrawn'")
			case "snapshot_cap":
				f.r.HTTP = &http.Client{Transport: transportFunc(func(req *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 200, ContentLength: wire.MaxSnapshot + 1, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
				})}
			case "queue_full":
				f.r.queue = make(chan work, 1)
				f.r.queue <- work{}
			case "wrong_version":
				f.r.Version = "9.9.9"
			case "disabled":
				f.cfg.VerificationEnabled = false
			case "snapshot_tamper":
				f.r.HTTP = &http.Client{Transport: transportFunc(func(req *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("tampered")), Request: req}, nil
				})}
			}
			if e := f.r.Submit(ctx, token); e == nil {
				t.Fatal("accepted refusal")
			}
			if f.opens.Load() != 0 {
				t.Fatal("source opened before refusal", f.opens.Load())
			}
			if kind == "audit_sync_failure" {
				a, e := f.r.Ledger.Verification(ctx, j.Text("spec_id"))
				if e != nil || a.State != "accepted" {
					t.Fatal("failure did not consume admitted consent", e)
				}
			}
		})
	}
}
func TestE7ConsumesConsentAndNoHiddenFacts(t *testing.T) {
	ctx := context.Background()
	for _, rule := range []config.Columns{{Rename: map[string]string{"id": "id"}}, {Drop: []string{"id"}}, {Drop: []string{"nonexistent"}}} {
		f := newRunner(t)
		f.cfg.Columns = map[string]config.Columns{"data/file0.csv": rule}
		f.start(t)
		token, j := f.job(t, 1, "probe")
		if e := f.r.Submit(ctx, token); e != nil {
			t.Fatal(e)
		}
		a := f.wait(t, j.Text("spec_id"))
		var body struct {
			Document string `json:"document_b64"`
		}
		json.Unmarshal(a.Result, &body)
		raw, _ := wire.DecodeDocument(body.Document, wire.MaxScanDocument)
		var d struct {
			Affected []string `json:"affected_file_ids"`
		}
		json.Unmarshal(raw, &d)
		expected := 0
		if rule.Drop == nil || rule.Drop[0] == "id" {
			expected = 1
		}
		if len(d.Affected) != expected {
			t.Fatal("wrong E7 intersection", string(raw))
		}
		if expected == 1 && bytes.Contains(raw, []byte("column_names")) {
			t.Fatal("hidden schema leaked")
		}
		n := f.opens.Load()
		if e := f.r.Submit(ctx, token); e != nil {
			t.Fatal(e)
		}
		if f.opens.Load() != n {
			t.Fatal("E7 replay reran")
		}
		var count int
		f.r.Ledger.DB.QueryRow("SELECT accepted_count FROM verification_daily").Scan(&count)
		if count != 1 {
			t.Fatal("E7 quota rolled back")
		}
	}
}
func TestRestartPaidNeverReruns(t *testing.T) {
	ctx := context.Background()
	f := newRunner(t)
	token, j := f.job(t, 1, "scan")
	a := f.r.admission(j, loadVector(t, "snapshot").Token)
	if _, e := f.r.Ledger.Admit(ctx, a, f.at); e != nil {
		t.Fatal(e)
	}
	f.start(t)
	saved := f.wait(t, j.Text("spec_id"))
	if saved.State != "interrupted" || f.opens.Load() != 0 {
		t.Fatal("restart read source")
	}
	if e := f.r.Submit(ctx, token); e != nil {
		t.Fatal(e)
	}
	var body struct {
		Document string `json:"document_b64"`
	}
	json.Unmarshal(saved.Result, &body)
	raw, _ := wire.DecodeDocument(body.Document, wire.MaxScanDocument)
	if !bytes.Contains(raw, []byte(`"terminal_error_code":"scanner_failure"`)) {
		t.Fatal(string(raw))
	}
}
func TestPinnedMutationTerminal(t *testing.T) {
	f := newRunner(t)
	f.start(t)
	token, j := f.job(t, 1, "scan")
	open := f.r.OpenFile
	f.r.OpenFile = func(v ledger.File) (*os.File, error) {
		if f.opens.Load() >= 3 {
			os.WriteFile(filepath.Join(v.Root, v.RelativePath), []byte("id\nMUTATED\n"), 0600)
		}
		return open(v)
	}
	if e := f.r.Submit(context.Background(), token); e != nil {
		t.Fatal(e)
	}
	a := f.wait(t, j.Text("spec_id"))
	var body struct {
		Document string `json:"document_b64"`
	}
	json.Unmarshal(a.Result, &body)
	raw, _ := wire.DecodeDocument(body.Document, wire.MaxScanDocument)
	if !bytes.Contains(raw, []byte(`"terminal_error_code":"artifact_changed"`)) {
		t.Fatal(string(raw))
	}
}

func TestExclusiveRunnerAndConcurrentRedelivery(t *testing.T) {
	f := newRunner(t)
	f.start(t)
	other := Runner{Ledger: f.r.Ledger, Audit: f.r.Audit, Log: f.r.Log, Keys: f.r.Keys, GatewayID: f.r.GatewayID, Version: f.r.Version, Pins: f.r.Pins, Config: f.r.Config, Now: f.r.Now}
	if e := other.Start(context.Background(), f.dir); e == nil {
		other.Close()
		t.Fatal("second process acquired worker")
	}
	token, j := f.job(t, 1, "scan")
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := f.r.Submit(context.Background(), token); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	a := f.wait(t, j.Text("spec_id"))
	if a.State != "reported" {
		t.Fatal(a.State)
	}
	if f.opens.Load() != 9 {
		t.Fatal("redelivery ran twice", f.opens.Load())
	}
}
func TestSharedConsentBoundaryVectors(t *testing.T) {
	v := loadVector(t, "consent_refusals")
	for _, entry := range v.Input["cases"].([]any) {
		c := entry.(map[string]any)
		t.Run(c["name"].(string), func(t *testing.T) {
			f := newRunner(t)
			f.start(t)
			at := time.Unix(int64(c["now"].(float64)), 0).UTC()
			f.at = at
			for i := 0; i < int(c["daily_count"].(float64)); i++ {
				_, j := f.job(t, i, "probe")
				if _, e := f.r.Ledger.Admit(context.Background(), f.r.admission(j, loadVector(t, "snapshot").Token), at); e != nil {
					t.Fatal(e)
				}
			}
			template := loadVector(t, "probe_spec")
			raw, _ := wire.DecodeDocument(template.Input["payload_b64"].(string), 40000)
			m, _ := core.ParseCanonical(raw)
			p := m.(map[string]any)
			p["spec_id"] = "boundary"
			p["owner_authorization_id"] = "boundary_auth"
			p["nonce"] = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{90}, 32))
			issued := at.Add(time.Duration(c["issued_offset_seconds"].(float64)) * time.Second)
			p["accepted_at_utc"] = timestamp(issued)
			p["issued_at_utc"] = timestamp(issued)
			p["expires_at_utc"] = timestamp(at.Add(time.Duration(c["expires_offset_seconds"].(float64)) * time.Second))
			raw, _ = core.Canonical(p)
			template.Input["payload_b64"] = base64.RawURLEncoding.EncodeToString(raw)
			template.Input["spec_hash"] = wire.Digest(raw)
			template.Input["iat"] = issued.Unix()
			token, _ := wire.Sign("aim-scan-spec+jwt", "test-only-scan-key", template.Input, f.key)
			if expected, ok := c["token"].(string); ok {
				if token != expected {
					t.Fatal("Go/Python signed admission vector drift")
				}
			}
			e := f.r.Submit(context.Background(), token)
			valid := c["expected_verdict"] == "valid"
			if (e == nil) != valid {
				t.Fatal("boundary verdict", e)
			}
			if !valid && f.opens.Load() != 0 {
				t.Fatal("refusal opened bytes")
			}
		})
	}
}

func TestCompletedPreviewIsExactAfterSourceChanges(t *testing.T) {
	ctx := context.Background()
	f := newRunner(t)
	f.start(t)
	token, j := f.job(t, 1, "scan")
	if e := f.r.Submit(ctx, token); e != nil {
		t.Fatal(e)
	}
	a := f.wait(t, j.Text("spec_id"))
	s, e := wire.VerifySnapshot(loadVector(t, "snapshot").Token, f.r.Pins(), j)
	if e != nil {
		t.Fatal(e)
	}
	before, e := f.r.Preview(ctx, s.Members[0].FileID, j.Text("spec_id"))
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 3; i++ {
		os.Remove(filepath.Join(f.dir, fmt.Sprintf("file%d.csv", i)))
	}
	n := f.opens.Load()
	after, e := f.r.Preview(ctx, s.Members[0].FileID, j.Text("spec_id"))
	if e != nil || !bytes.Equal(before, after) || f.opens.Load() != n {
		t.Fatal("historical preview reread source", e)
	}
	f.cfg.Columns = map[string]config.Columns{"data/file0.csv": {Drop: []string{"id"}}}
	if _, e = f.r.Preview(ctx, s.Members[0].FileID, a.SpecID); e == nil {
		t.Fatal("saved hidden names previewed")
	}
}

func TestRuntimeScanReportMatchesPythonContractBytes(t *testing.T) {
	f := newRunner(t)
	j, e := wire.VerifyScan(f.v.Token, f.r.Pins(), f.r.GatewayID, f.r.Keys.Snapshot().RunnerID, f.r.Version, f.at)
	if e != nil {
		t.Fatal(e)
	}
	s, e := wire.VerifySnapshot(loadVector(t, "snapshot").Token, f.r.Pins(), j)
	if e != nil {
		t.Fatal(e)
	}
	copy(f.r.Keys.Commitment[:], bytes.Repeat([]byte{0x63}, 32))
	f.r.Keys.Private = f.key
	j.ScannerVersion = "0.0.0-test"
	j.ReceiptKeyID = f.r.Keys.Snapshot().ReceiptKeyID
	src := &source{runner: f.r, snapshot: s}
	if _, e = src.eligibility(context.Background()); e != nil {
		t.Fatal(e)
	}
	facts, e := core.Scan(context.Background(), src, policy(j, f.r.Keys))
	if e != nil {
		t.Fatal(e)
	}
	golden := loadVector(t, "scan_report")
	start, _ := time.Parse(time.RFC3339, golden.Input["started_at_utc"].(string))
	end, _ := time.Parse(time.RFC3339, golden.Input["completed_at_utc"].(string))
	d := f.r.report(j, facts, start, end)
	if e = signReceipt(d, f.key, "scan"); e != nil {
		t.Fatal(e)
	}
	actual, e := core.Canonical(d)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile("../../contract/vectors/verification/scan_report.json")
	var v struct{ Canonical string }
	json.Unmarshal(raw, &v)
	if string(actual) != v.Canonical {
		t.Fatalf("runtime/contract report differs\n%s\n%s", actual, v.Canonical)
	}
}

func TestPendingRefusalsRetryInsertOnly(t *testing.T) {
	for _, mirrorFailure := range []bool{false, true} {
		t.Run(fmt.Sprint("mirror=", mirrorFailure), func(t *testing.T) {
			f := newRunner(t)
			f.start(t)
			r := f.r
			if mirrorFailure {
				r.Audit.Sync = func(*os.File) error { return errors.New("injected mirror failure") }
			} else if _, e := r.Ledger.DB.Exec(`CREATE TRIGGER fail_refusal BEFORE INSERT ON verification_local_events BEGIN SELECT RAISE(FAIL, 'injected insert failure'); END`); e != nil {
				t.Fatal(e)
			}
			r.outboxMu.Lock()
			for i := 0; i < 100; i++ {
				r.QueueRefusal(context.Background(), wire.Digest([]byte(fmt.Sprint(i))))
			}
			r.outboxMu.Unlock()
			deadline := time.Now().Add(5 * time.Second)
			for r.health() == nil && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if r.health() == nil {
				t.Fatal("failure not injected")
			}
			if !mirrorFailure {
				var n int
				r.Ledger.DB.QueryRow("SELECT count(*) FROM verification_local_events").Scan(&n)
				if n != 0 {
					t.Fatal("insert unexpectedly succeeded", n)
				}
				if _, e := r.Ledger.DB.Exec("DROP TRIGGER fail_refusal"); e != nil {
					t.Fatal(e)
				}
			}
			for time.Now().Before(deadline) {
				events, e := r.Ledger.VerificationEvents(context.Background(), 0)
				if e != nil {
					t.Fatal(e)
				}
				if len(events) == 100 {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			// Wait beyond another retry tick to detect duplicate inserts after mirror failure.
			time.Sleep(1100 * time.Millisecond)
			events, e := r.Ledger.VerificationEvents(context.Background(), 0)
			if e != nil || len(events) != 100 {
				t.Fatal("lost or duplicated evidence", len(events), e)
			}
			hashes := map[string]bool{}
			counted := 0
			for _, event := range events {
				if event.SpecHash == "" {
					counted++
					continue
				}
				if hashes[event.SpecHash] {
					t.Fatal("duplicate hash", event.SpecHash)
				}
				hashes[event.SpecHash] = true
			}
			if counted == 0 || len(hashes) < 64 {
				t.Fatal("bounded backlog missing", len(hashes), counted)
			}
			if f.opens.Load() != 0 {
				t.Fatal("refusal opened source")
			}
		})
	}
}

func TestUnreachableProbeDocument(t *testing.T) {
	for _, stage := range []string{"eligibility", "probe"} {
		t.Run(stage, func(t *testing.T) {
			ctx := context.Background()
			f := newRunner(t)
			f.start(t)
			token, j := f.job(t, 1, "probe")
			open := f.r.OpenFile
			f.r.OpenFile = func(v ledger.File) (*os.File, error) {
				if stage == "eligibility" || f.opens.Load() >= 3 {
					return nil, errors.New("source unreachable")
				}
				return open(v)
			}
			if e := f.r.Submit(ctx, token); e != nil {
				t.Fatal(e)
			}
			a := f.wait(t, j.Text("spec_id"))
			var body struct {
				Variant  string `json:"variant"`
				Document string `json:"document_b64"`
			}
			if e := json.Unmarshal(a.Result, &body); e != nil {
				t.Fatal(e)
			}
			if body.Variant != "probe" {
				t.Fatal("expected probe report", body.Variant)
			}
			raw, e := wire.DecodeDocument(body.Document, wire.MaxScanDocument)
			if e != nil {
				t.Fatal(e)
			}
			var document map[string]json.RawMessage
			if e := json.Unmarshal(raw, &document); e != nil {
				t.Fatal(e)
			}
			expected, e := core.Canonical(map[string]any{
				"listing_id": j.Text("listing_id"), "source_handle_id": j.Text("source_handle_id"),
				"connector_type": "aim_gateway", "connector_version": "aim_gateway-v1",
				"owner_consent": true, "source_reachable": false,
				"objects_discovered": 3, "size_class": "small", "estimated_max_input_tokens": 8192,
				"supported_capabilities": []string{"complete_traversal", "deterministic_object_order", "fixed_bucket_aggregates", "exact_or_declared_estimated_row_counts"},
				"preview_requested":      j.Preview(),
			})
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(document["probe"], expected) {
				t.Fatalf("unreachable probe differs: %s; want %s", document["probe"], expected)
			}
		})
	}
}
