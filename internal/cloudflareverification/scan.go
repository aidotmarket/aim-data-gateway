package cloudflareverification

import (
	"context"
	"encoding/hex"
	"errors"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	core "github.com/aidotmarket/aim-data-gateway/verification"
	"time"
)

type Handler struct {
	Config Config
	Now    func() time.Time
}

func (h Handler) now() time.Time {
	if h.Now != nil {
		return h.Now().UTC()
	}
	return time.Now().UTC()
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
	p := core.Policy{
		CanonicalizationVersion:   "python-json-sort-compact-v1",
		RowCountAlgorithmVersion:  "exact-v1",
		DistinctAlgorithmVersion:  "hll-sha256-v1",
		HistogramVersion:          "fixed-buckets-v1",
		NumericBucketVersion:      "fixed-buckets-v1",
		MinimumAggregateOccupancy: 10,
		LengthBounds: []int{
			0,
			1,
			4,
			8,
			16,
			32,
			64,
			128,
			256,
		},
		NumericBoundaries: []float64{
			-1000,
			-100,
			-10,
			0,
			10,
			100,
			1000,
		},
		MaxMemoryBytes: 128 << 20,
		MaxRecordBytes: 16 << 20,
		MaxScalarBytes: 16 << 20,
		MaxColumns:     1000,
		MaxFactBytes:   32768,
		Deadline:       CF_VERIFY_DEADLINE_SECONDS * time.Second,
		Commitments:    c,
	}
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
		document = map[string]any{
			"probe_id":            j.Text("probe_id"),
			"spec_id":             j.Text("spec_id"),
			"spec_hash":           j.Envelope.SpecHash,
			"nonce_echo":          j.Text("nonce"),
			"install_key_id":      s.Receipt,
			"affected_file_ids":   []string{},
			"signature_algorithm": "Ed25519",
			"probe": map[string]any{
				"listing_id":         j.Text("listing_id"),
				"source_handle_id":   j.Text("source_handle_id"),
				"connector_type":     "r2_verifier",
				"connector_version":  "r2_verifier-v1",
				"owner_consent":      true,
				"source_reachable":   e == nil,
				"objects_discovered": len(src.Members()),
				"size_class":         class,
				"supported_capabilities": []string{
					"complete_traversal",
					"deterministic_object_order",
					"fixed_bucket_aggregates",
					"exact_or_declared_estimated_row_counts",
				},
				"estimated_max_input_tokens": result.EstimatedMaxInputTokens,
				"preview_requested":          j.Preview(),
			},
		}
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
