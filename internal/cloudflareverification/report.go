package cloudflareverification

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	core "github.com/aidotmarket/aim-data-gateway/verification"
)

func terminal(j wire.ScanJob, code string, at time.Time) map[string]any {
	d := map[string]any{}
	for _, k := range strings.Fields("verification_id listing_id source_handle_id spec_id spec_version connector_type connector_version") {
		d[k] = j.Payload[k]
	}
	d["spec_hash"], d["nonce_echo"], d["install_key_id"] = j.Envelope.SpecHash, j.Text("nonce"), j.ReceiptKeyID
	d["agent_version"], d["terminal_error_code"], d["completed_at_utc"], d["canonicalization_version"], d["signature_algorithm"] = j.ScannerVersion, code, timestamp(at), "python-json-sort-compact-v1", "Ed25519"
	return d
}
func report(j wire.ScanJob, f core.Facts, start, end time.Time) map[string]any {
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
	return map[string]any{
		"op":           "scan_report",
		"variant":      variant,
		"runner_id":    j.Envelope.RunnerID,
		"iid":          j.Envelope.IID,
		"document_b64": base64.RawURLEncoding.EncodeToString(raw),
	}
}
