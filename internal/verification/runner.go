// Package verification is the gateway's durable, single-worker verification lane.
package verification

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
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
	"sync"
	"syscall"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/audit"
	"github.com/aidotmarket/aim-data-gateway/internal/config"
	"github.com/aidotmarket/aim-data-gateway/internal/inventory"
	"github.com/aidotmarket/aim-data-gateway/internal/ledger"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	core "github.com/aidotmarket/aim-data-gateway/verification"
)

var ErrE7 = errors.New("columns_hidden")

const E7Message = "Some columns of this data are hidden in your gateway settings, so it can't be verified."
const Guidance = "Request verification on the website before using preview --verify."

type Runner struct {
	failed             error
	failureMu          sync.Mutex
	ActivePins         func() map[string]ed25519.PublicKey
	Ledger             *ledger.Ledger
	Audit              *LocalAudit
	Log                *audit.Log
	Keys               *Keys
	GatewayID, Version string
	Pins               func() map[string]ed25519.PublicKey
	Config             func() config.Config
	HTTP               *http.Client
	// OpenFile is an instrumentable, contained source open; never called at admission.
	OpenFile func(ledger.File) (*os.File, error)
	Now      func() time.Time
	mu       sync.Mutex
	queue    chan work
	lock     *os.File
	cancel   context.CancelFunc
	done     chan struct{}
	outboxMu sync.Mutex
}
type work struct {
	job      wire.ScanJob
	snapshot wire.Snapshot
	ctx      context.Context
}

func (r *Runner) livePins() map[string]ed25519.PublicKey {
	if r.ActivePins != nil {
		return r.ActivePins()
	}
	return r.Pins()
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}
func (r *Runner) Start(ctx context.Context, dir string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.queue != nil {
		return nil
	}
	if r.lock == nil {
		var e error
		r.lock, e = LockRunner(dir)
		if e != nil {
			return e
		}
	}
	lock := r.lock
	var e error
	if e = r.Recover(ctx); e != nil {
		lock.Close()
		r.lock = nil
		return e
	}
	ctx, r.cancel = context.WithCancel(ctx)
	r.queue = make(chan work, 1)
	r.done = make(chan struct{})
	go func() {
		defer close(r.done)
		for {
			select {
			case <-ctx.Done():
				return
			case w := <-r.queue:
				// A connection's cancellation cannot allow its pending job to read bytes.
				jobCtx, cancel := context.WithCancel(w.ctx)
				stop := context.AfterFunc(ctx, cancel)
				e := r.run(jobCtx, w.job, w.snapshot)
				stop()
				cancel()
				if e != nil {
					r.fail(e)
					return
				}
			}
		}
	}()
	return nil
}
func (r *Runner) Close() {
	r.mu.Lock()
	cancel, done, lock := r.cancel, r.done, r.lock
	r.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
	if lock != nil {
		lock.Close()
	}
}
func (r *Runner) admission(j wire.ScanJob, snapshot string) ledger.Admission {
	return ledger.Admission{ReceiptKeyID: r.Keys.Snapshot().ReceiptKeyID, ScannerVersion: r.Version, SpecID: j.Text("spec_id"), RunnerID: j.Envelope.RunnerID, ListingID: j.Text("listing_id"), VersionID: j.Text("listing_version_id"), ManifestHash: j.Text("manifest_hash"), SpecHash: j.Envelope.SpecHash, Nonce: j.Text("nonce"), AuthorizationID: j.Text("owner_authorization_id"), Variant: j.Envelope.Variant, IID: j.Envelope.IID, Accepted: j.Accepted.Unix(), Issued: j.Issued.Unix(), Expires: j.Expires.Unix(), Spec: []byte(j.Token), Snapshot: []byte(snapshot)}
}
func (r *Runner) health() error {
	r.failureMu.Lock()
	defer r.failureMu.Unlock()
	return r.failed
}
func (r *Runner) fail(e error) {
	r.failureMu.Lock()
	defer r.failureMu.Unlock()
	r.failed = e
	if r.cancel != nil {
		r.cancel()
	}
}
func (r *Runner) mirror(ctx context.Context) error {
	if e := r.Audit.Mirror(ctx, r.Ledger); e != nil {
		r.fail(e)
		return e
	}
	return nil
}
func (r *Runner) record(ctx context.Context, a ledger.Admission, result, code string) error {
	r.outboxMu.Lock()
	defer r.outboxMu.Unlock()
	if e := r.Ledger.VerificationEvent(ctx, a, result, code, r.now()); e != nil {
		r.fail(e)
		return e
	}
	return r.mirror(ctx)
}
func (r *Runner) Submit(ctx context.Context, token string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.health(); e != nil {
		return e
	}
	binding := r.Keys.Snapshot()
	if binding.ScannerVersion != r.Version || binding.Ack == "" {
		return wire.ErrVerification
	}
	j, e := wire.VerifyScan(token, r.livePins(), r.GatewayID, binding.RunnerID, r.Version, r.now())
	if e != nil {
		// Expired signed redelivery returns only its durable outbox/status. It
		// cannot re-enter admission or read a source, even after key retirement.
		saved, readErr := r.Ledger.Verifications(ctx)
		if readErr == nil {
			for _, a := range saved {
				if bytes.Equal(a.Spec, []byte(token)) {
					if _, verifyErr := wire.VerifyScan(token, r.Pins(), r.GatewayID, a.RunnerID, r.Version, time.Unix(a.Committed, 0)); verifyErr == nil {
						return r.Flush(ctx)
					}
				}
			}
		}
		a := ledger.Admission{SpecHash: wire.Digest([]byte(token))}
		_ = r.record(ctx, a, "refused", "invalid_spec")
		return wire.ErrVerification
	}
	a := r.admission(j, "")
	if e = r.record(ctx, a, "received", ""); e != nil {
		return r.refusal(ctx, a, "audit_unavailable")
	}
	j.ScannerVersion, j.ReceiptKeyID = r.Version, binding.ReceiptKeyID
	previous, e := r.Ledger.Verification(ctx, a.SpecID)
	if e == nil {
		if previous.SpecHash != a.SpecHash || !bytes.Equal(previous.Spec, []byte(token)) {
			return r.refusal(ctx, a, "replay")
		}
		return r.Flush(ctx)
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return r.refusal(ctx, a, "ledger_unavailable")
	}
	if !r.Config().VerificationEnabled || r.queue == nil {
		return r.refusal(ctx, a, "unsupported")
	}
	if len(r.queue) == cap(r.queue) {
		return r.refusal(ctx, a, "queue_full")
	}
	snapshotToken, e := r.fetchSnapshot(ctx, j)
	if e != nil {
		return r.refusal(ctx, a, "snapshot_invalid")
	}
	s, e := wire.VerifySnapshot(snapshotToken, r.Pins(), j)
	if e != nil {
		return r.refusal(ctx, a, "snapshot_invalid")
	}
	src := &source{runner: r, snapshot: s}
	if e = src.metadata(ctx); e != nil {
		return r.refusal(ctx, a, "source_unavailable")
	}
	a = r.admission(j, snapshotToken)
	fresh, e := r.Ledger.Admit(ctx, a, r.now(), r.now)
	if e != nil {
		return r.refusal(ctx, a, "consent_refused")
	}
	if !fresh {
		return r.Flush(ctx)
	}
	r.outboxMu.Lock()
	e = r.mirror(ctx)
	r.outboxMu.Unlock()
	if e != nil {
		return r.refusal(ctx, a, "audit_unavailable")
	}
	select {
	case r.queue <- work{j, s, ctx}:
		return nil
	default:
		return r.refusal(ctx, a, "queue_full")
	}
}

// RefuseControl records overflow without trusting or echoing inbound claims.
// Channel frames are bounded; hash-only evidence also covers malformed tokens.
func (r *Runner) RefuseControl(ctx context.Context, token string) error {
	return r.record(ctx, ledger.Admission{SpecHash: wire.Digest([]byte(token))}, "refused", "queue_full")
}
func (r *Runner) refusal(ctx context.Context, a ledger.Admission, code string) error {
	// Fixed code only; no parser/path/schema error can escape.
	_ = r.record(ctx, a, "refused", code)
	if a.SpecID != "" && (code == "consent_refused" || code == "ledger_unavailable" || code == "audit_unavailable") {
		_, _ = r.Log.Append("error", wire.GatewayError{Code: code, Message: code})
	}
	return errors.New(code)
}
func (r *Runner) fetchSnapshot(ctx context.Context, j wire.ScanJob) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	b := r.Keys.Snapshot()
	path := "/api/v1/verification-runners/" + b.RunnerID + "/snapshot/" + j.Text("manifest_hash")
	nonce, e := random32()
	if e != nil {
		return "", e
	}
	auth, e := wire.Sign("aim-verification-snapshot-request+jwt", b.ReceiptKeyID, map[string]any{"runner_id": b.RunnerID, "gateway_id": r.GatewayID, "method": "GET", "path": path, "nonce": base64.RawURLEncoding.EncodeToString(nonce), "iat": r.now().Unix()}, r.Keys.Private)
	if e != nil || len(auth) > 4096 {
		return "", wire.ErrVerification
	}
	req, e := http.NewRequestWithContext(ctx, "GET", "https://api.ai.market"+path, nil)
	if e != nil {
		return "", e
	}
	req.Header.Set("Authorization", "Bearer "+auth)
	client := http.DefaultClient
	if r.HTTP != nil {
		client = r.HTTP
	}
	copyClient := *client
	copyClient.Timeout = 30 * time.Second
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, e := copyClient.Do(req)
	if e != nil {
		return "", e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.Request.URL.Host != "api.ai.market" || resp.Request.URL.Scheme != "https" || resp.ContentLength > wire.MaxSnapshot {
		return "", wire.ErrVerification
	}
	raw, e := io.ReadAll(io.LimitReader(resp.Body, wire.MaxSnapshot+1))
	if e != nil || len(raw) > wire.MaxSnapshot {
		return "", wire.ErrVerification
	}
	return string(raw), nil
}
func policy(j wire.ScanJob, k *Keys) core.Policy {
	p := core.Policy{CanonicalizationVersion: "python-json-sort-compact-v1", RowCountAlgorithmVersion: "exact-v1", DistinctAlgorithmVersion: "hll-sha256-v1", HistogramVersion: "fixed-buckets-v1", NumericBucketVersion: "fixed-buckets-v1", MinimumAggregateOccupancy: 10, LengthBounds: []int{0, 1, 4, 8, 16, 32, 64, 128, 256}, NumericBoundaries: []float64{-1000, -100, -10, 0, 10, 100, 1000}, MaxMemoryBytes: 128 << 20, MaxRecordBytes: 16 << 20, MaxScalarBytes: 16 << 20, MaxColumns: 1000, MaxFactBytes: 32768, Deadline: 30 * time.Minute, GatewayID: j.Envelope.Audience, SnapshotHash: j.Text("manifest_hash"), CommitmentKey: k.Commitment}
	seed, _ := hex.DecodeString(j.Text("deterministic_seed"))
	copy(p.Seed[:], seed)
	return p
}
func (r *Runner) run(ctx context.Context, j wire.ScanJob, s wire.Snapshot) error {
	if j.ScannerVersion == "" {
		j.ScannerVersion = r.Version
	}
	if j.ReceiptKeyID == "" {
		j.ReceiptKeyID = r.Keys.Snapshot().ReceiptKeyID
	}
	fresh, e := r.Ledger.ClaimVerification(context.Background(), j.Text("spec_id"))
	if e != nil || !fresh {
		return e
	}
	started := r.now()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	src := &source{runner: r, snapshot: s}
	affected, e := src.eligibility(ctx)
	code := ""
	var document map[string]any
	variant := j.Envelope.Variant
	if j.Envelope.Variant == "probe" {
		reachable := e == nil
		result := core.ProbeResult{ObjectsDiscovered: len(s.Members), SizeClass: sizeClass(s), EstimatedMaxInputTokens: 1, SupportedCapabilities: []string{"complete_traversal", "deterministic_object_order", "fixed_bucket_aggregates", "exact_or_declared_estimated_row_counts"}}
		if reachable && len(affected) == 0 {
			result, e = core.Probe(ctx, src, policy(j, r.Keys))
			reachable = e == nil
		}
		document = map[string]any{"probe_id": j.Text("probe_id"), "spec_id": j.Text("spec_id"), "spec_hash": j.Envelope.SpecHash, "nonce_echo": j.Text("nonce"), "install_key_id": r.Keys.Snapshot().ReceiptKeyID, "affected_file_ids": affected, "signature_algorithm": "Ed25519", "probe": map[string]any{"listing_id": j.Text("listing_id"), "source_handle_id": j.Text("source_handle_id"), "connector_type": "aim_gateway", "connector_version": "aim_gateway-v1", "owner_consent": true, "source_reachable": reachable, "objects_discovered": result.ObjectsDiscovered, "size_class": result.SizeClass, "supported_capabilities": result.SupportedCapabilities, "estimated_max_input_tokens": result.EstimatedMaxInputTokens, "preview_requested": j.Preview()}}
	} else {
		var facts core.Facts
		if e == nil && len(affected) > 0 {
			e = ErrE7
		}
		if e == nil {
			facts, e = core.Scan(ctx, src, policy(j, r.Keys))
		}
		completed := r.now()
		if e == nil && ctx.Err() != nil {
			e = ctx.Err()
		}
		if e != nil {
			code = errorCode(e)
			document = r.terminal(j, code, completed)
			variant = "terminal"
		} else {
			document = r.report(j, facts, started, completed)
		}
	}
	if e = signReceipt(document, r.Keys.Private, variant); e != nil {
		return e
	}
	raw, e := core.Canonical(document)
	if e != nil || len(raw) > wire.MaxScanDocument {
		return wire.ErrVerification
	}
	body := reportBody(j, variant, raw)
	rawBody, e := wire.Canonical(body)
	if e != nil || wire.ValidateScanReportBody(rawBody) != nil {
		return wire.ErrVerification
	}
	state := "reported"
	if variant == "terminal" || len(affected) > 0 {
		state = "refused"
	}
	if e = r.Ledger.SaveVerification(context.Background(), j.Text("spec_id"), state, rawBody); e != nil {
		return e
	}
	if len(affected) > 0 {
		code = "columns_hidden"
	}
	if e = r.record(context.Background(), r.admission(j, ""), state, code); e != nil {
		return e
	}
	return r.Flush(context.Background())
}
func sizeClass(s wire.Snapshot) string {
	var n uint64
	for _, m := range s.Members {
		if uint64(m.Size) >= 100000000 || n >= 100000000 {
			return "large"
		}
		n += uint64(m.Size)
	}
	if n < 10000000 {
		return "small"
	}
	if n < 100000000 {
		return "medium"
	}
	return "large"
}
func errorCode(e error) string {
	switch {
	case errors.Is(e, core.ErrArtifactChanged):
		return "artifact_changed"
	case errors.Is(e, core.ErrTimeout), errors.Is(e, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(e, core.ErrUnsupported):
		return "unsupported_type"
	case errors.Is(e, os.ErrPermission):
		return "permission_denied"
	case errors.Is(e, os.ErrNotExist):
		return "source_unreachable"
	default:
		return "scanner_failure"
	}
}
func (r *Runner) terminal(j wire.ScanJob, code string, at time.Time) map[string]any {
	d := map[string]any{}
	for _, k := range strings.Fields("verification_id listing_id source_handle_id spec_id spec_version connector_type connector_version") {
		d[k] = j.Payload[k]
	}
	d["spec_hash"], d["nonce_echo"], d["install_key_id"] = j.Envelope.SpecHash, j.Text("nonce"), j.ReceiptKeyID
	d["agent_version"], d["terminal_error_code"], d["completed_at_utc"], d["canonicalization_version"], d["signature_algorithm"] = j.ScannerVersion, code, timestamp(at), "python-json-sort-compact-v1", "Ed25519"
	return d
}
func (r *Runner) report(j wire.ScanJob, f core.Facts, start, end time.Time) map[string]any {
	d := map[string]any{}
	for _, k := range strings.Fields("verification_id listing_id owner_authorization_id quote_id idempotency_key wire_manifest_version corpus_disclosure_version payment_disclosure_version accepted_at_utc requested_action source_handle_id spec_id spec_version connector_type connector_version depth_class row_count_algorithm_version histogram_version numeric_bucket_version canonicalization_version preview_requested") {
		d[k] = j.Payload[k]
	}
	d["spec_hash"], d["nonce_echo"], d["install_key_id"] = j.Envelope.SpecHash, j.Text("nonce"), j.ReceiptKeyID
	d["agent_version"], d["distinct_algorithm_version"], d["started_at_utc"], d["completed_at_utc"], d["duration_ms"], d["signature_algorithm"] = j.ScannerVersion, "hll-sha256-v1", timestamp(start), timestamp(end), end.Sub(start).Milliseconds(), "Ed25519"
	d["artifact_locator_commitment"], d["content_sha256"], d["coverage"], d["objects"], d["fingerprint_hash"], d["d6_description"] = f.LocatorCommitment, f.ContentSHA256, f.Coverage, f.Objects, f.FingerprintHash, j.D6
	return d
}
func receiptBinding(d map[string]any, variant string) map[string]any {
	binding := d
	if variant == "scan" {
		binding = map[string]any{}
		for _, k := range strings.Fields("spec_hash nonce_echo install_key_id artifact_locator_commitment content_sha256 started_at_utc completed_at_utc duration_ms coverage fingerprint_hash") {
			binding[k] = d[k]
		}
	}
	return binding
}
func signReceipt(d map[string]any, key ed25519.PrivateKey, variant string) error {
	binding := receiptBinding(d, variant)
	raw, e := core.Canonical(binding)
	if e != nil {
		return e
	}
	d["receipt_signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(key, raw))
	return nil
}
func reportBody(j wire.ScanJob, variant string, raw []byte) map[string]any {
	return map[string]any{"op": "scan_report", "variant": variant, "runner_id": j.Envelope.RunnerID, "iid": j.Envelope.IID, "document_b64": base64.RawURLEncoding.EncodeToString(raw)}
}
func (r *Runner) Flush(ctx context.Context) error { return r.flush(ctx, false) }
func (r *Runner) flush(ctx context.Context, recoverHistory bool) error {
	r.outboxMu.Lock()
	defer r.outboxMu.Unlock()
	if e := r.health(); e != nil {
		return e
	}
	if e := r.mirror(ctx); e != nil {
		return e
	}
	pending, e := r.Ledger.UnlinkedVerifications(ctx)
	if e != nil {
		return e
	}
	if len(pending) == 0 {
		return nil
	}
	byIID := map[string]audit.Entry{}
	if recoverHistory {
		if e = r.Log.Walk(func(a audit.Entry) error {
			if a.MessageType == "scan_report" {
				var body struct {
					IID string `json:"iid"`
				}
				if json.Unmarshal(a.Body, &body) == nil && body.IID != "" {
					byIID[body.IID] = a
				}
			}
			return nil
		}); e != nil {
			return e
		}
	}
	for _, a := range pending {
		entry, exists := byIID[a.IID]
		if exists {
			if !bytes.Equal(entry.Body, a.Result) {
				return errors.New("verification_outbox_conflict")
			}
		} else {
			entry, e = r.Log.Append("scan_report", json.RawMessage(a.Result))
			if e != nil {
				r.fail(e)
				return e
			}
		}
		if e = r.Ledger.AuditVerification(ctx, a.SpecID, entry.Seq); e != nil {
			r.fail(e)
			return e
		}
	}
	return nil
}
func (r *Runner) Recover(ctx context.Context) error {
	if e := r.Audit.Mirror(ctx, r.Ledger); e != nil {
		return e
	}
	if e := r.Ledger.InterruptVerifications(ctx); e != nil {
		return e
	}
	jobs, e := r.Ledger.Verifications(ctx)
	if e != nil {
		return e
	}
	for _, a := range jobs {
		if a.State != "interrupted" || len(a.Result) > 0 {
			continue
		}
		j, e := wire.VerifyScan(string(a.Spec), r.Pins(), r.GatewayID, a.RunnerID, r.Version, time.Unix(a.Committed, 0))
		if e != nil {
			return e
		}
		j.ScannerVersion, j.ReceiptKeyID = a.ScannerVersion, a.ReceiptKeyID
		if a.Variant == "scan" {
			d := r.terminal(j, "scanner_failure", r.now())
			if e = signReceipt(d, r.Keys.Private, "terminal"); e != nil {
				return e
			}
			raw, e := core.Canonical(d)
			if e != nil {
				return e
			}
			body, e := wire.Canonical(reportBody(j, "terminal", raw))
			if e != nil {
				return e
			}
			if e = r.Ledger.SaveVerification(ctx, a.SpecID, "interrupted", body); e != nil {
				return e
			}
		}
		if e = r.record(ctx, a, "interrupted", "scanner_failure"); e != nil {
			return e
		}
	}
	if e = r.flush(ctx, true); e != nil {
		return e
	}
	pruneCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return r.Ledger.PruneVerification(pruneCtx, r.now())
}

// source retains pinned identities. Metadata checks never open bytes.
type source struct {
	index    map[string]wire.SnapshotMember
	runner   *Runner
	snapshot wire.Snapshot
}

func (s *source) metadata(ctx context.Context) error {
	for _, m := range s.snapshot.Members {
		if _, e := s.check(ctx, m.FileID); e != nil {
			return e
		}
	}
	return nil
}
func (s *source) check(ctx context.Context, id string) (ledger.File, error) {
	if s.index == nil {
		s.index = make(map[string]wire.SnapshotMember, len(s.snapshot.Members))
		for _, m := range s.snapshot.Members {
			s.index[m.FileID] = m
		}
	}
	member, exists := s.index[id]
	if !exists {
		return ledger.File{}, core.ErrArtifactChanged
	}
	f, e := s.runner.Ledger.File(ctx, id)
	if e != nil {
		return f, e
	}
	cfg := s.runner.Config()
	if !cfg.VerificationEnabled || !f.Present || f.Changed || f.SHA256 != member.SHA256 || f.Size != member.Size || !ledger.WithinCeiling(cfg, f) {
		return f, core.ErrArtifactChanged
	}
	offer, e := s.runner.Ledger.Offer(ctx, id, member.SHA256, s.snapshot.ListingVersionID)
	if e != nil || offer.State != "offered" || offer.KeyClass != "listing" || cfg.OfferRequiresLocalApproval && !offer.ApprovedAt.Valid {
		return f, core.ErrArtifactChanged
	}
	// A superseding active offer invalidates this version before any open.
	var n int
	e = s.runner.Ledger.DB.QueryRowContext(ctx, "SELECT count(*) FROM offers WHERE fid=? AND state='offered' AND lvid<>?", id, s.snapshot.ListingVersionID).Scan(&n)
	if e != nil {
		return f, e
	}
	if n > 0 {
		return f, core.ErrArtifactChanged
	}
	return f, nil
}
func (s *source) Members() []core.Member {
	out := make([]core.Member, 0, len(s.snapshot.Members))
	for _, m := range s.snapshot.Members {
		sha, _ := hex.DecodeString(m.SHA256)
		v := core.Member{Identity: m.FileID, Size: m.Size}
		copy(v.SHA256[:], sha)
		f, e := s.runner.Ledger.File(context.Background(), m.FileID)
		if e == nil {
			v.Format = format(f.RelativePath)
		}
		out = append(out, v)
	}
	return out
}
func format(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".ndjson" {
		return "jsonl"
	}
	return strings.TrimPrefix(ext, ".")
}
func (s *source) open(ctx context.Context, id string) (*os.File, error) {
	if e := s.runner.health(); e != nil {
		return nil, e
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	f, e := s.check(ctx, id)
	if e != nil {
		return nil, e
	}
	if s.runner.OpenFile != nil {
		return s.runner.OpenFile(f)
	}
	return (inventory.Record{Root: f.Root, RelativePath: f.RelativePath}).Open()
}
func (s *source) checkedOpen(ctx context.Context, id string) (*os.File, error) {
	f, e := s.open(ctx, id)
	if e != nil {
		return nil, e
	}
	names, e := s.schema(ctx, f, id)
	if e == nil {
		v, err := s.runner.Ledger.File(ctx, id)
		e = err
		if e == nil && affected(s.runner.Config().ColumnRule(v.Source, v.RelativePath), names) {
			e = ErrE7
		}
	}
	if e == nil {
		_, e = f.Seek(0, io.SeekStart)
	}
	if e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}
func (s *source) schema(ctx context.Context, f *os.File, id string) ([]string, error) {
	v, e := s.runner.Ledger.File(ctx, id)
	if e != nil {
		return nil, e
	}
	st, e := f.Stat()
	if e != nil {
		return nil, e
	}
	return core.DiscoverSchema(ctx, randomFile{f, st.Size()}, format(v.RelativePath))
}
func (s *source) Open(ctx context.Context, id string) (io.ReadCloser, error) {
	f, e := s.checkedOpen(ctx, id)
	if e != nil {
		return nil, e
	}
	return f, nil
}

type randomFile struct {
	*os.File
	size int64
}

func (f randomFile) Size() int64 { return f.size }
func (s *source) OpenAt(ctx context.Context, id string) (core.RandomAccess, error) {
	f, e := s.checkedOpen(ctx, id)
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
func affected(rule config.Columns, names []string) bool {
	for _, n := range names {
		if _, ok := rule.Rename[n]; ok {
			return true
		}
		for _, drop := range rule.Drop {
			if drop == n {
				return true
			}
		}
	}
	return false
}
func (s *source) eligibility(ctx context.Context) ([]string, error) {
	out := []string{}
	bound := 512
	for _, m := range s.snapshot.Members {
		f, e := s.runner.Ledger.File(ctx, m.FileID)
		if e != nil {
			return out, e
		}
		kind := format(f.RelativePath)
		if kind != "csv" && kind != "tsv" && kind != "jsonl" && kind != "parquet" {
			continue
		}
		handle, e := s.open(ctx, m.FileID)
		if e != nil {
			return out, e
		}
		stop := context.AfterFunc(ctx, func() { handle.Close() })
		names, e := s.schema(ctx, handle, m.FileID)
		stop()
		handle.Close()
		if e != nil {
			return out, e
		}
		bound += 512
		for _, n := range names {
			bound += len(n)*6 + 768
		}
		if bound > 8192*3 {
			return out, core.ErrBudget
		}
		if affected(s.runner.Config().ColumnRule(f.Source, f.RelativePath), names) {
			out = append(out, m.FileID)
		}
	}
	return out, nil
}

// Preview reads retained state only; it never admits, audits, sends or fetches.
func (r *Runner) Preview(ctx context.Context, id, specID string) ([]byte, error) {
	if len(id) != 32 {
		return nil, wire.ErrVerification
	}
	jobs, e := r.Ledger.Verifications(ctx)
	if e != nil {
		return nil, e
	}
	var chosen []ledger.Admission
	for _, a := range jobs {
		if a.Variant != "scan" || specID != "" && a.SpecID != specID {
			continue
		}
		j, e := wire.VerifyScan(string(a.Spec), r.Pins(), r.GatewayID, a.RunnerID, r.Version, time.Unix(a.Committed, 0))
		if e != nil {
			continue
		}
		s, e := wire.VerifySnapshot(string(a.Snapshot), r.Pins(), j)
		if e != nil {
			continue
		}
		for _, m := range s.Members {
			if m.FileID == id {
				chosen = append(chosen, a)
				break
			}
		}
	}
	if len(chosen) == 0 {
		return nil, errors.New(Guidance)
	}
	if len(chosen) > 1 {
		return nil, errors.New("Several retained specs match; use --spec-id.")
	}
	a := chosen[0]
	j, e := wire.VerifyScan(string(a.Spec), r.Pins(), r.GatewayID, a.RunnerID, r.Version, time.Unix(a.Committed, 0))
	if e != nil {
		return nil, e
	}
	s, e := wire.VerifySnapshot(string(a.Snapshot), r.Pins(), j)
	if e != nil {
		return nil, e
	}
	if len(a.Result) > 0 {
		return r.savedPreview(ctx, a, s)
	}
	src := &source{runner: r, snapshot: s}
	ids, e := src.eligibility(ctx)
	if e != nil {
		return nil, errors.New("verification preview refused")
	}
	if len(ids) > 0 {
		return nil, errors.New(E7Message)
	}
	f, e := core.Scan(ctx, src, policy(j, r.Keys))
	if e != nil {
		return nil, errors.New("verification preview refused")
	}
	return core.Canonical(map[string]any{"status": "pending", "policy": j.Payload, "facts": f})
}

// LockRunner precedes audit recovery, preventing a second process from repairing
// a first process's in-flight append. It is not used by read-only preview.
func LockRunner(dir string) (*os.File, error) {
	f, e := os.OpenFile(filepath.Join(dir, "verification-runner.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, errors.New("verification_runner_busy")
	}
	return f, nil
}
func (r *Runner) SetLock(f *os.File) { r.lock = f }

// Completed preview returns historical signed bytes; it does not depend on the
// source still exposing the old content. Current hiding rules still apply.
func (r *Runner) savedPreview(ctx context.Context, a ledger.Admission, s wire.Snapshot) ([]byte, error) {
	var body struct {
		Variant  string `json:"variant"`
		Document string `json:"document_b64"`
	}
	if e := json.Unmarshal(a.Result, &body); e != nil {
		return nil, e
	}
	raw, e := wire.DecodeDocument(body.Document, wire.MaxScanDocument)
	if e != nil {
		return nil, e
	}
	v, e := core.ParseCanonical(raw)
	if e != nil {
		return nil, e
	}
	d, ok := v.(map[string]any)
	if !ok {
		return nil, wire.ErrVerification
	}
	signature, ok := d["receipt_signature"].(string)
	if !ok {
		return nil, wire.ErrVerification
	}
	sig, e := base64.StdEncoding.DecodeString(signature)
	if e != nil {
		return nil, e
	}
	delete(d, "receipt_signature")
	binding := receiptBinding(d, body.Variant)
	signed, e := core.Canonical(binding)
	if e != nil || !ed25519.Verify(r.Keys.Private.Public().(ed25519.PublicKey), signed, sig) {
		return nil, wire.ErrVerification
	}
	if d["spec_hash"] != a.SpecHash || d["install_key_id"] != a.ReceiptKeyID {
		return nil, wire.ErrVerification
	}
	if body.Variant == "scan" {
		fingerprint := map[string]any{}
		for _, k := range strings.Fields("coverage objects depth_class row_count_algorithm_version distinct_algorithm_version histogram_version numeric_bucket_version canonicalization_version") {
			fingerprint[k] = d[k]
		}
		b, e := core.Canonical(fingerprint)
		if e != nil || wire.Digest(b) != d["fingerprint_hash"] {
			return nil, wire.ErrVerification
		}
		objects, ok := d["objects"].([]any)
		if !ok {
			return nil, wire.ErrVerification
		}
		byID := map[string]wire.SnapshotMember{}
		for _, m := range s.Members {
			h := hmac.New(sha256.New, r.Keys.Commitment[:])
			h.Write([]byte("object\x00gateway_listing\x00" + s.GatewayID + "\x00" + m.FileID + "\x00" + m.SHA256))
			byID[hex.EncodeToString(h.Sum(nil))] = m
		}
		for _, v := range objects {
			o, ok := v.(map[string]any)
			if !ok {
				return nil, wire.ErrVerification
			}
			oid, _ := o["object_id"].(string)
			m, exists := byID[oid]
			if !exists {
				return nil, wire.ErrVerification
			}
			f, e := r.Ledger.File(ctx, m.FileID)
			if e != nil {
				return nil, e
			}
			cols, ok := o["column_names"].([]any)
			if !ok {
				return nil, wire.ErrVerification
			}
			names := []string{}
			for _, v := range cols {
				n, ok := v.(string)
				if !ok {
					return nil, wire.ErrVerification
				}
				names = append(names, n)
			}
			if affected(r.Config().ColumnRule(f.Source, f.RelativePath), names) {
				return nil, errors.New(E7Message)
			}
		}
	} else if body.Variant != "terminal" {
		return nil, wire.ErrVerification
	}
	return raw, nil
}
