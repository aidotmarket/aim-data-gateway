package awsverification

import (
	"crypto/ed25519"
	"encoding/json"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	core "github.com/aidotmarket/aim-data-gateway/verification"
	"regexp"
	"strings"
	"time"
)

var identifier = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func closed(raw []byte, names string) (map[string]any, error) {
	v, e := core.ParseCanonical(raw)
	if e != nil {
		return nil, wire.ErrVerification
	}
	m, ok := v.(map[string]any)
	if !ok || len(m) != len(strings.Fields(names)) {
		return nil, wire.ErrVerification
	}
	for _, n := range strings.Fields(names) {
		if m[n] == nil {
			return nil, wire.ErrVerification
		}
	}
	return m, nil
}

const probeFields = "spec_id spec_version probe_id listing_id source_handle_id listing_version_id runner_id source_kind manifest_hash owner_authorization_id accepted_at_utc issued_at_utc expires_at_utc nonce platform_key_id connector_type connector_version preview_requested"
const scanFields = "spec_id spec_version verification_id listing_id source_handle_id listing_version_id runner_id source_kind manifest_hash owner_authorization_id accepted_at_utc issued_at_utc expires_at_utc nonce platform_key_id connector_type connector_version preview_requested quote_id idempotency_key deterministic_seed requested_action wire_manifest_version corpus_disclosure_version payment_disclosure_version traversal_root traversal_order fingerprint_algorithm canonicalization_version approximate_distinct_algorithm output_contract depth_class field_contract bucket_definitions minimum_aggregate_occupancy low_occupancy_behavior row_count_algorithm_version histogram_version numeric_bucket_version d6_schema_version d6_sanitizer_policy_version hard_inference_budget cancellation_signal"

func VerifyWork(token string, keys map[string]ed25519.PublicKey, gateway, runner, version string, now time.Time) (wire.ScanJob, error) {
	j := wire.ScanJob{Token: token}
	if len(token) > 64<<10 {
		return j, wire.ErrVerification
	}
	// Untrusted discriminant is used only to choose an exact signed schema.
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return j, wire.ErrVerification
	}
	raw, e := wire.DecodeDocument(parts[1], 64<<10)
	if e != nil {
		return j, e
	}
	var v struct {
		Variant string `json:"variant"`
	}
	if json.Unmarshal(raw, &v) != nil {
		return j, wire.ErrVerification
	}
	fields := "op aud iid iat runner_id variant spec_hash payload_b64"
	payloadFields := probeFields
	if v.Variant == "scan" {
		fields += " d6_b64 d6_hash"
		payloadFields = scanFields
	} else if v.Variant != "probe" {
		return j, wire.ErrVerification
	}
	j.KID, e = wire.VerifyControl(token, "aim-scan-spec+jwt", fields, keys, &j.Envelope, 64<<10)
	if e != nil {
		return j, e
	}
	a := j.Envelope
	if a.Op != "scan_spec" || a.Audience != gateway || !uuid.MatchString(a.IID) || a.RunnerID != runner || !uuid.MatchString(runner) || !hex64.MatchString(a.SpecHash) {
		return j, wire.ErrVerification
	}
	j.Raw, e = wire.DecodeDocument(a.Payload, 40<<10)
	if e != nil || wire.Digest(j.Raw) != a.SpecHash {
		return j, wire.ErrVerification
	}
	j.Payload, e = closed(j.Raw, payloadFields)
	if e != nil {
		return j, e
	}
	for _, k := range strings.Fields("listing_id source_handle_id listing_version_id runner_id") {
		if !uuid.MatchString(j.Text(k)) {
			return j, wire.ErrVerification
		}
	}
	for _, k := range strings.Fields("spec_id owner_authorization_id platform_key_id nonce") {
		if !identifier.MatchString(j.Text(k)) {
			return j, wire.ErrVerification
		}
	}
	if j.Text("runner_id") != runner || j.Text("platform_key_id") != j.KID || j.Text("spec_version") != "1" || j.Text("source_kind") != "s3_listing" || j.Text("connector_type") != "aws_s3_verifier" || j.Text("connector_version") != "aws_s3_verifier-v1" || !hex64.MatchString(j.Text("manifest_hash")) {
		return j, wire.ErrVerification
	}
	if _, ok := j.Payload["preview_requested"].(bool); !ok {
		return j, wire.ErrVerification
	}
	if b, e := wire.DecodeDocument(j.Text("nonce"), 32); e != nil || len(b) != 32 {
		return j, wire.ErrVerification
	}
	j.Accepted, e = utc(j.Text("accepted_at_utc"))
	if e != nil {
		return j, e
	}
	j.Issued, e = utc(j.Text("issued_at_utc"))
	if e != nil {
		return j, e
	}
	j.Expires, e = utc(j.Text("expires_at_utc"))
	if e != nil {
		return j, e
	}
	if j.Issued.Unix() != a.IssuedAt || j.Accepted.After(j.Issued) || !j.Issued.Before(j.Expires) || j.Expires.Sub(j.Issued) > 24*time.Hour || j.Issued.After(now.Add(300*time.Second)) || j.Issued.Before(now.Add(-24*time.Hour-300*time.Second)) || j.Accepted.Before(now.Add(-24*time.Hour-300*time.Second)) || j.Expires.Before(now.Add(-300*time.Second)) {
		return j, wire.ErrVerification
	}
	if a.Variant == "probe" {
		if !uuid.MatchString(j.Text("probe_id")) {
			return j, wire.ErrVerification
		}
		return j, nil
	}
	if !uuid.MatchString(j.Text("verification_id")) || !identifier.MatchString(j.Text("quote_id")) || !identifier.MatchString(j.Text("idempotency_key")) || !hex64.MatchString(j.Text("deterministic_seed")) || !identifier.MatchString(version) {
		return j, wire.ErrVerification
	}
	fixed := map[string]string{"requested_action": "start", "wire_manifest_version": "data-verification-wire-v1", "corpus_disclosure_version": "s1396-disclosure-v1", "payment_disclosure_version": "payment-disclosure-v1", "traversal_root": "registered_source_artifact", "traversal_order": "canonical_object_identity_ascending", "fingerprint_algorithm": "sha256", "canonicalization_version": "python-json-sort-compact-v1", "approximate_distinct_algorithm": "hll-sha256-v1", "output_contract": "data-verification-report-v1", "depth_class": "complete_standard_v1", "low_occupancy_behavior": "suppressed_low_occupancy", "row_count_algorithm_version": "exact-v1", "histogram_version": "fixed-buckets-v1", "numeric_bucket_version": "fixed-buckets-v1", "d6_schema_version": "d6-v1", "d6_sanitizer_policy_version": "nfkc-fixed-enum-v1"}
	for k, v := range fixed {
		if j.Text(k) != v {
			return j, wire.ErrVerification
		}
	}
	constants := map[string]string{"minimum_aggregate_occupancy": `10`, "field_contract": `["coverage","objects.object_id","objects.column_names","objects.column_types","objects.null_rate","objects.approx_distinct_count","objects.length_histograms","objects.numeric_range_buckets","objects.row_count","objects.row_count_method","fingerprint_hash"]`, "bucket_definitions": `{"numeric_boundaries":[-1000.0,-100.0,-10.0,0.0,10.0,100.0,1000.0],"string_length_upper_bounds":[0,1,4,8,16,32,64,128,256]}`, "hard_inference_budget": `{"max_input_tokens":8192,"max_output_tokens":1024,"model_request_count":1}`, "cancellation_signal": `{"cancelled":false,"kind":"signed_spec_flag"}`}
	for k, want := range constants {
		b, e := core.Canonical(j.Payload[k])
		if e != nil || string(b) != want {
			return j, wire.ErrVerification
		}
	}
	d6, e := wire.DecodeDocument(a.D6, 2048)
	if e != nil || wire.Digest(d6) != a.D6Hash {
		return j, wire.ErrVerification
	}
	j.D6, e = wire.ValidateD6(d6)
	return j, e
}
func utc(s string) (time.Time, error) {
	t, e := time.Parse(time.RFC3339Nano, s)
	if e != nil || !strings.HasSuffix(s, "Z") || t.Nanosecond()%1000 != 0 {
		return t, wire.ErrVerification
	}
	return t, nil
}
