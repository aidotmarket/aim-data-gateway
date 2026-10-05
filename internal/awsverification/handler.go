package awsverification

import (
	"context"
	"encoding/hex"
	"errors"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	core "github.com/aidotmarket/aim-data-gateway/verification"
	"time"
)

type Audit interface {
	Event(context.Context, string, string) error
}
type Handler struct {
	Config  Config
	Ledger  Ledger
	Store   SecretStore
	Backend Backend
	S3      S3
	Audit   Audit
	Now     func() time.Time
}

func (h Handler) now() time.Time {
	if h.Now != nil {
		return h.Now().UTC()
	}
	return time.Now().UTC()
}
func (h Handler) event(ctx context.Context, event, hash string) error {
	if h.Audit == nil || h.Audit.Event(ctx, event, hash) != nil {
		return ErrRefused
	}
	return nil
}
func (h Handler) Invoke(ctx context.Context) error {
	start := h.now()
	if e := h.Ledger.Observe(ctx, start); e != nil {
		return e
	}
	s, e := Bootstrap(ctx, h.Config, h.Ledger, h.Store, h.Backend, start)
	if e != nil {
		return ErrRefused
	}
	// Recover before every work request, including invocations with no new work.
	if e = h.recover(ctx, s); e != nil {
		return ErrRefused
	}
	pickup := h.now()
	token, e := h.Backend.Work(ctx, s)
	if e != nil {
		return ErrRefused
	}
	if token == "" {
		return nil
	}
	hash := wire.Digest([]byte(token))
	if e = h.event(ctx, "received", hash); e != nil {
		return e
	}
	if e = Rotate(ctx, h.Store, s, token, h.now()); e == nil {
		return h.event(ctx, "key_rotation", hash)
	}
	j, e := VerifyWork(token, s.keys(h.now()), s.Runner, s.Runner, h.Config.Version, h.now())
	if e != nil {
		h.event(ctx, "refused", hash)
		return ErrRefused
	}
	j.ScannerVersion, j.ReceiptKeyID = h.Config.Version, s.Receipt
	// Exact redelivery is answered from state, never opened again, even if expired.
	if r, ok, e := h.Ledger.record(ctx, j.Text("spec_id")); e != nil {
		return e
	} else if ok {
		if r.Job.Token != token {
			return ErrRefused
		}
		return nil
	}
	snapshot, e := h.Backend.Snapshot(ctx, s, j.Text("manifest_hash"))
	if e != nil {
		return ErrRefused
	}
	objects, e := Snapshot(snapshot, s.keys(h.now()), j, h.Config)
	if e != nil {
		h.event(ctx, "refused", hash)
		return ErrRefused
	}
	src, e := NewSource(h.S3, h.Config.Bucket, objects)
	if e != nil {
		return ErrRefused
	}
	// Revalidate freshness after the bounded snapshot fetch; no expiry crossing.
	if _, e = VerifyWork(token, s.keys(h.now()), s.Runner, s.Runner, h.Config.Version, h.now()); e != nil {
		return ErrRefused
	}
	fresh, e := h.Ledger.Admit(ctx, j, h.now(), pickup)
	if e != nil {
		h.event(ctx, "refused", hash)
		return e
	}
	if !fresh {
		return nil
	}
	if e = h.event(ctx, "accepted", hash); e != nil {
		return e
	}
	r, ok, e := h.Ledger.record(ctx, j.Text("spec_id"))
	if e != nil || !ok {
		return ErrRefused
	}
	deadline := start.Add(AWS_VERIFY_DEADLINE_SECONDS * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Add(-30*time.Second).Before(deadline) {
		deadline = d.Add(-30 * time.Second)
	}
	scanCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	body, e := h.scan(scanCtx, s, j, src)
	if e != nil {
		return ErrRefused
	}
	if e = h.Ledger.Commit(ctx, r, body, h.now()); e != nil {
		return e
	}
	if e = h.event(ctx, "committed", hash); e != nil {
		return e
	}
	return h.recover(ctx, s)
}
func (h Handler) recover(ctx context.Context, s *Secret) error {
	c, exists, e := h.Ledger.clock(ctx)
	if e != nil || c.Last > h.now().Unix()+300 {
		return ErrRefused
	}
	if !exists || c.Active == "" {
		return nil
	}
	r, ok, e := h.Ledger.record(ctx, c.Active)
	if e != nil || !ok {
		return ErrRefused
	}
	if h.now().Unix() > r.Pickup+AWS_VERIFY_TERMINAL_DEADLINE_SECONDS {
		if e = h.event(ctx, "expired", r.Job.Envelope.SpecHash); e != nil {
			return e
		}
		return h.Ledger.Settle(ctx, r, h.now(), "expired")
	}
	if r.State != "committed" {
		if h.now().Unix() <= r.Pickup+1020 {
			return ErrRefused
		}
		// No committed outbox: interrupted traversal cannot resume under consent.
		if r.Job.Envelope.Variant == "probe" {
			if e = h.event(ctx, "interrupted", r.Job.Envelope.SpecHash); e != nil {
				return e
			}
			return h.Ledger.Settle(ctx, r, h.now(), "interrupted")
		}
		d := terminal(r.Job, "scanner_failure", h.now())
		body, e := encodeReport(s, r.Job, "terminal", d, nil)
		if e != nil {
			return e
		}
		if e = h.Ledger.Commit(ctx, r, body, h.now()); e != nil {
			return e
		}
		r, _, e = h.Ledger.record(ctx, c.Active)
		if e != nil {
			return e
		}
	}
	body, e := h.Ledger.Body(ctx, r, h.now())
	if e != nil {
		return e
	}
	if e = h.Backend.Report(ctx, s, body, r.Job.Envelope.IID); e != nil {
		return ErrRefused
	}
	if e = h.event(ctx, "reported", r.Job.Envelope.SpecHash); e != nil {
		return e
	}
	return h.Ledger.Settle(ctx, r, h.now(), "reported")
}

type collectedCommitments struct {
	Commitments
	Digests map[string]string
}

func (c *collectedCommitments) ObjectID(m core.Member) string {
	c.Digests[m.Identity] = hex.EncodeToString(m.SHA256[:])
	return c.Commitments.ObjectID(m)
}
func scanPolicy(j wire.ScanJob, c *collectedCommitments) core.Policy {
	p := core.Policy{CanonicalizationVersion: "python-json-sort-compact-v1", RowCountAlgorithmVersion: "exact-v1", DistinctAlgorithmVersion: "hll-sha256-v1", HistogramVersion: "fixed-buckets-v1", NumericBucketVersion: "fixed-buckets-v1", MinimumAggregateOccupancy: 10, LengthBounds: []int{0, 1, 4, 8, 16, 32, 64, 128, 256}, NumericBoundaries: []float64{-1000, -100, -10, 0, 10, 100, 1000}, MaxMemoryBytes: 128 << 20, MaxRecordBytes: 16 << 20, MaxScalarBytes: 16 << 20, MaxColumns: 1000, MaxFactBytes: 32768, Deadline: AWS_VERIFY_DEADLINE_SECONDS * time.Second, Commitments: c}
	b, _ := hex.DecodeString(j.Text("deterministic_seed"))
	copy(p.Seed[:], b)
	return p
}
func (h Handler) scan(ctx context.Context, s *Secret, j wire.ScanJob, src *Source) ([]byte, error) {
	started := h.now()
	c := &collectedCommitments{Commitments: Commitments{Bucket: h.Config.Bucket, ManifestHash: j.Text("manifest_hash"), Key: s.Commitment}, Digests: map[string]string{}}
	// HEAD all members before fact inspection, after consent/audit acknowledgment.
	var e error
	for _, m := range src.Members() {
		_, _, e = src.request(ctx, m.Identity)
		if e != nil {
			break
		}
	}
	variant := j.Envelope.Variant
	var document map[string]any
	var digests []string
	if variant == "probe" {
		var result core.ProbeResult
		if e == nil {
			result, e = core.Probe(ctx, src, scanPolicy(j, c))
		}
		class := "large"
		var total int64
		for _, m := range src.Members() {
			total += m.Size
		}
		if total < 10000000 {
			class = "small"
		} else if total < 100000000 {
			class = "medium"
		}
		if result.EstimatedMaxInputTokens == 0 {
			result.EstimatedMaxInputTokens = 8192
		}
		document = map[string]any{"probe_id": j.Text("probe_id"), "spec_id": j.Text("spec_id"), "spec_hash": j.Envelope.SpecHash, "nonce_echo": j.Text("nonce"), "install_key_id": s.Receipt, "affected_file_ids": []string{}, "signature_algorithm": "Ed25519", "probe": map[string]any{"listing_id": j.Text("listing_id"), "source_handle_id": j.Text("source_handle_id"), "connector_type": "aws_s3_verifier", "connector_version": "aws_s3_verifier-v1", "owner_consent": true, "source_reachable": e == nil, "objects_discovered": len(src.Members()), "size_class": class, "supported_capabilities": []string{"complete_traversal", "deterministic_object_order", "fixed_bucket_aggregates", "exact_or_declared_estimated_row_counts"}, "estimated_max_input_tokens": result.EstimatedMaxInputTokens, "preview_requested": j.Preview()}}
	} else {
		var f core.Facts
		if e == nil {
			f, e = core.Scan(ctx, src, scanPolicy(j, c))
		}
		if e == nil {
			e = ctx.Err()
		}
		if e != nil {
			variant = "terminal"
			document = terminal(j, errorCode(e), h.now())
		} else {
			document = report(j, f, started, h.now())
			digests = make([]string, 0, len(src.Members()))
			for _, m := range src.Members() {
				digest := c.Digests[m.Identity]
				if !hex64.MatchString(digest) {
					return nil, ErrRefused
				}
				digests = append(digests, digest)
			}
		}
	}
	return encodeReport(s, j, variant, document, digests)
}
func errorCode(e error) string {
	switch {
	case errors.Is(e, core.ErrArtifactChanged):
		return "artifact_changed"
	case errors.Is(e, core.ErrTimeout), errors.Is(e, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(e, core.ErrUnsupported):
		return "unsupported_type"
	default:
		return "scanner_failure"
	}
}
func encodeReport(s *Secret, j wire.ScanJob, variant string, d map[string]any, digests []string) ([]byte, error) {
	if e := signReceipt(d, s.Private, variant); e != nil {
		return nil, e
	}
	raw, e := core.Canonical(d)
	if e != nil || len(raw) > wire.MaxScanDocument {
		return nil, ErrRefused
	}
	b := reportBody(j, variant, raw)
	if variant == "scan" {
		if len(digests) == 0 || len(digests) > MaxMembers {
			return nil, ErrRefused
		}
		b["member_sha256s"] = digests
	}
	raw, e = core.Canonical(b)
	if e != nil || len(raw) > MaxReport {
		return nil, ErrRefused
	}
	return raw, nil
}
