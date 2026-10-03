package wire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	core "github.com/aidotmarket/aim-data-gateway/verification"
)

var ErrVerification = errors.New("invalid_verification")
var identifier = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

const MaxScanDocument = 700 << 10
const MaxSnapshot = 16 << 20

type ScanEnvelope struct {
	Op       string `json:"op"`
	Audience string `json:"aud"`
	IID      string `json:"iid"`
	IssuedAt int64  `json:"iat"`
	RunnerID string `json:"runner_id"`
	Variant  string `json:"variant"`
	SpecHash string `json:"spec_hash"`
	Payload  string `json:"payload_b64"`
	D6       string `json:"d6_b64,omitempty"`
	D6Hash   string `json:"d6_hash,omitempty"`
}
type ScanJob struct {
	Envelope                  ScanEnvelope
	Payload                   map[string]any
	Raw                       []byte
	D6                        map[string]any
	Token                     string
	KID                       string
	Accepted, Issued, Expires time.Time
}

func (j ScanJob) Text(k string) string { v, _ := j.Payload[k].(string); return v }
func (j ScanJob) Preview() bool        { v, _ := j.Payload["preview_requested"].(bool); return v }
func Digest(b []byte) string           { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func DecodeDocument(s string, limit int) ([]byte, error) {
	if len(s) > base64.RawURLEncoding.EncodedLen(limit) {
		return nil, ErrVerification
	}
	b, e := b64.DecodeString(s)
	if e != nil || len(b) > limit || b64.EncodeToString(b) != s {
		return nil, ErrVerification
	}
	return b, nil
}

// closed applies exact keys and canonical bytes before decoding a signed envelope.
func closed(raw []byte, names string) (map[string]any, error) {
	v, e := core.ParseCanonical(raw)
	if e != nil {
		return nil, ErrVerification
	}
	m, ok := v.(map[string]any)
	if !ok || len(m) != len(strings.Fields(names)) {
		return nil, ErrVerification
	}
	for _, n := range strings.Fields(names) {
		if m[n] == nil {
			return nil, ErrVerification
		}
	}
	return m, nil
}
func VerifyControl(token, typ, names string, keys map[string]ed25519.PublicKey, out any, limit int) (string, error) {
	if len(token) > limit {
		return "", ErrVerification
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", ErrVerification
	}
	h, e := DecodeDocument(parts[0], 512)
	if e != nil {
		return "", e
	}
	m, e := closed(h, "alg typ kid")
	if e != nil {
		return "", e
	}
	kid, _ := m["kid"].(string)
	if !identifier.MatchString(kid) {
		return "", ErrVerification
	}
	raw, e := DecodeDocument(parts[1], limit)
	if e != nil {
		return "", e
	}
	if _, e = closed(raw, names); e != nil {
		return "", e
	}
	// Gateway envelopes use the gateway escaping/integer rules, not fact encoding.
	var v any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if e = d.Decode(&v); e != nil {
		return "", e
	}
	canon, e := Canonical(v)
	if e != nil || !bytes.Equal(canon, raw) {
		return "", ErrVerification
	}
	if e = Verify(token, typ, keys, out); e != nil {
		return "", ErrVerification
	}
	return kid, nil
}

const probeFields = "spec_id spec_version probe_id listing_id source_handle_id listing_version_id runner_id source_kind manifest_hash owner_authorization_id accepted_at_utc issued_at_utc expires_at_utc nonce platform_key_id connector_type connector_version preview_requested"
const scanFields = "spec_id spec_version verification_id listing_id source_handle_id listing_version_id runner_id source_kind manifest_hash owner_authorization_id accepted_at_utc issued_at_utc expires_at_utc nonce platform_key_id connector_type connector_version preview_requested quote_id idempotency_key deterministic_seed requested_action wire_manifest_version corpus_disclosure_version payment_disclosure_version traversal_root traversal_order fingerprint_algorithm canonicalization_version approximate_distinct_algorithm output_contract depth_class field_contract bucket_definitions minimum_aggregate_occupancy low_occupancy_behavior row_count_algorithm_version histogram_version numeric_bucket_version d6_schema_version d6_sanitizer_policy_version hard_inference_budget cancellation_signal"

func VerifyScan(token string, keys map[string]ed25519.PublicKey, gateway, runner, version string, now time.Time) (ScanJob, error) {
	j := ScanJob{Token: token}
	if len(token) > 64<<10 {
		return j, ErrVerification
	}
	// Untrusted discriminant is used only to choose an exact signed schema.
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return j, ErrVerification
	}
	raw, e := DecodeDocument(parts[1], 64<<10)
	if e != nil {
		return j, e
	}
	var v struct {
		Variant string `json:"variant"`
	}
	if json.Unmarshal(raw, &v) != nil {
		return j, ErrVerification
	}
	fields := "op aud iid iat runner_id variant spec_hash payload_b64"
	payloadFields := probeFields
	if v.Variant == "scan" {
		fields += " d6_b64 d6_hash"
		payloadFields = scanFields
	} else if v.Variant != "probe" {
		return j, ErrVerification
	}
	j.KID, e = VerifyControl(token, "aim-scan-spec+jwt", fields, keys, &j.Envelope, 64<<10)
	if e != nil {
		return j, e
	}
	a := j.Envelope
	if a.Op != "scan_spec" || a.Audience != gateway || !uuid.MatchString(a.IID) || a.RunnerID != runner || !uuid.MatchString(runner) || !hex64.MatchString(a.SpecHash) {
		return j, ErrVerification
	}
	j.Raw, e = DecodeDocument(a.Payload, 40<<10)
	if e != nil || Digest(j.Raw) != a.SpecHash {
		return j, ErrVerification
	}
	j.Payload, e = closed(j.Raw, payloadFields)
	if e != nil {
		return j, e
	}
	for _, k := range strings.Fields("listing_id source_handle_id listing_version_id runner_id") {
		if !uuid.MatchString(j.Text(k)) {
			return j, ErrVerification
		}
	}
	for _, k := range strings.Fields("spec_id owner_authorization_id platform_key_id nonce") {
		if !identifier.MatchString(j.Text(k)) {
			return j, ErrVerification
		}
	}
	if j.Text("runner_id") != runner || j.Text("platform_key_id") != j.KID || j.Text("spec_version") != "1" || j.Text("source_kind") != "gateway_listing" || j.Text("connector_type") != "aim_gateway" || j.Text("connector_version") != "aim_gateway-v1" || !hex64.MatchString(j.Text("manifest_hash")) {
		return j, ErrVerification
	}
	if _, ok := j.Payload["preview_requested"].(bool); !ok {
		return j, ErrVerification
	}
	if b, e := DecodeDocument(j.Text("nonce"), 32); e != nil || len(b) != 32 {
		return j, ErrVerification
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
		return j, ErrVerification
	}
	if a.Variant == "probe" {
		if !uuid.MatchString(j.Text("probe_id")) {
			return j, ErrVerification
		}
		return j, nil
	}
	if !uuid.MatchString(j.Text("verification_id")) || !identifier.MatchString(j.Text("quote_id")) || !identifier.MatchString(j.Text("idempotency_key")) || !hex64.MatchString(j.Text("deterministic_seed")) || !identifier.MatchString(version) {
		return j, ErrVerification
	}
	fixed := map[string]string{"requested_action": "start", "wire_manifest_version": "data-verification-wire-v1", "corpus_disclosure_version": "s1396-disclosure-v1", "payment_disclosure_version": "payment-disclosure-v1", "traversal_root": "registered_source_artifact", "traversal_order": "canonical_object_identity_ascending", "fingerprint_algorithm": "sha256", "canonicalization_version": "python-json-sort-compact-v1", "approximate_distinct_algorithm": "hll-sha256-v1", "output_contract": "data-verification-report-v1", "depth_class": "complete_standard_v1", "low_occupancy_behavior": "suppressed_low_occupancy", "row_count_algorithm_version": "exact-v1", "histogram_version": "fixed-buckets-v1", "numeric_bucket_version": "fixed-buckets-v1", "d6_schema_version": "d6-v1", "d6_sanitizer_policy_version": "nfkc-fixed-enum-v1"}
	for k, v := range fixed {
		if j.Text(k) != v {
			return j, ErrVerification
		}
	}
	constants := map[string]string{"minimum_aggregate_occupancy": `10`, "field_contract": `["coverage","objects.object_id","objects.column_names","objects.column_types","objects.null_rate","objects.approx_distinct_count","objects.length_histograms","objects.numeric_range_buckets","objects.row_count","objects.row_count_method","fingerprint_hash"]`, "bucket_definitions": `{"numeric_boundaries":[-1000.0,-100.0,-10.0,0.0,10.0,100.0,1000.0],"string_length_upper_bounds":[0,1,4,8,16,32,64,128,256]}`, "hard_inference_budget": `{"max_input_tokens":8192,"max_output_tokens":1024,"model_request_count":1}`, "cancellation_signal": `{"cancelled":false,"kind":"signed_spec_flag"}`}
	for k, want := range constants {
		b, e := core.Canonical(j.Payload[k])
		if e != nil || string(b) != want {
			return j, ErrVerification
		}
	}
	d6, e := DecodeDocument(a.D6, 2048)
	if e != nil || Digest(d6) != a.D6Hash {
		return j, ErrVerification
	}
	j.D6, e = ValidateD6(d6)
	return j, e
}
func utc(s string) (time.Time, error) {
	t, e := time.Parse(time.RFC3339Nano, s)
	if e != nil || !strings.HasSuffix(s, "Z") || t.Nanosecond()%1000 != 0 {
		return t, ErrVerification
	}
	return t, nil
}
func ValidateD6(raw []byte) (map[string]any, error) {
	m, e := closed(raw, "domain_class record_granularity temporal_scope update_cadence intended_use_tags known_limitation_tags")
	if e != nil || len(raw) > 2048 {
		return nil, ErrVerification
	}
	enums := map[string]string{"domain_class": "education_learning software_technology business_finance health_life_sciences public_social physical_environment", "record_granularity": "entity event measurement document relationship aggregate", "temporal_scope": "current_snapshot historical_period time_series mixed_periods not_time_based", "update_cadence": "one_time irregular continuous daily weekly monthly quarterly yearly", "intended_use_tags": "analysis_reporting research_education machine_learning benchmarking reference_lookup operations_planning", "known_limitation_tags": "incomplete_coverage missing_values estimated_fields historical_cutoff sampled_source known_duplicates source_defined_categories"}
	for k, allowed := range enums {
		valid := func(s string) bool { return strings.Contains(" "+allowed+" ", " "+s+" ") && s != "" }
		if strings.HasSuffix(k, "_tags") {
			a, ok := m[k].([]any)
			if !ok || len(a) > 5 {
				return nil, ErrVerification
			}
			last := ""
			for _, v := range a {
				s, ok := v.(string)
				if !ok || !valid(s) || s <= last {
					return nil, ErrVerification
				}
				last = s
			}
		} else {
			s, ok := m[k].(string)
			if !ok || !valid(s) {
				return nil, ErrVerification
			}
		}
	}
	// All accepted enum strings are ASCII, making NFKC the identity.
	return m, nil
}

type SnapshotMember struct {
	FileID string `json:"file_id"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size_bytes"`
}
type Snapshot struct {
	Version          string           `json:"snapshot_version"`
	Kind             string           `json:"source_kind"`
	GatewayID        string           `json:"gateway_id"`
	ListingID        string           `json:"listing_id"`
	ListingVersionID string           `json:"listing_version_id"`
	SourceID         string           `json:"source_handle_id"`
	Members          []SnapshotMember `json:"members"`
}

func VerifySnapshot(token string, keys map[string]ed25519.PublicKey, j ScanJob) (Snapshot, error) {
	var s Snapshot
	var wrapper struct {
		Audience string `json:"aud"`
		Runner   string `json:"runner_id"`
		Hash     string `json:"manifest_hash"`
		Payload  string `json:"payload_b64"`
	}
	_, e := VerifyControl(token, "aim-scan-snapshot+jwt", "aud runner_id manifest_hash payload_b64", keys, &wrapper, MaxSnapshot)
	if e != nil {
		return s, e
	}
	if wrapper.Audience != j.Envelope.Audience || wrapper.Runner != j.Envelope.RunnerID || wrapper.Hash != j.Text("manifest_hash") {
		return s, ErrVerification
	}
	raw, e := DecodeDocument(wrapper.Payload, MaxSnapshot)
	if e != nil || Digest(raw) != wrapper.Hash {
		return s, ErrVerification
	}
	m, e := closed(raw, "snapshot_version source_kind gateway_id listing_id listing_version_id source_handle_id members")
	if e != nil {
		return s, e
	}
	members, ok := m["members"].([]any)
	if !ok || len(members) == 0 || len(members) > 100000 {
		return s, ErrVerification
	}
	for _, v := range members {
		b, e := core.Canonical(v)
		if e != nil {
			return s, e
		}
		if _, e = closed(b, "file_id sha256 size_bytes"); e != nil {
			return s, e
		}
	}
	if e = json.Unmarshal(raw, &s); e != nil {
		return s, ErrVerification
	}
	if s.Version != "verification-source-snapshot-v1" || s.Kind != "gateway_listing" || s.GatewayID != j.Envelope.Audience || s.ListingID != j.Text("listing_id") || s.ListingVersionID != j.Text("listing_version_id") || s.SourceID != j.Text("source_handle_id") {
		return s, ErrVerification
	}
	last := ""
	for _, m := range s.Members {
		if !hex32.MatchString(m.FileID) || !hex64.MatchString(m.SHA256) || m.Size < 0 || m.FileID <= last {
			return s, ErrVerification
		}
		last = m.FileID
	}
	return s, nil
}

// ValidateScanReportBody enforces the control envelope and the decoded channel cap.
func ValidateScanReportBody(raw []byte) error {
	var head struct {
		Variant string `json:"variant"`
	}
	if json.Unmarshal(raw, &head) != nil {
		return ErrVerification
	}
	fields := "op variant runner_id iid document_b64"
	if head.Variant == "register" {
		fields = "op variant gateway_id scanner_version image_digest receipt_public_key registration_nonce registered_at_utc key_proof"
	}
	m, e := closed(raw, fields)
	if e != nil || m["op"] != "scan_report" {
		return ErrVerification
	}
	str := func(k string) string { s, _ := m[k].(string); return s }
	if head.Variant == "register" {
		if !uuid.MatchString(str("gateway_id")) || !identifier.MatchString(str("scanner_version")) || !strings.HasPrefix(str("image_digest"), "sha256:") || !hex64.MatchString(strings.TrimPrefix(str("image_digest"), "sha256:")) {
			return ErrVerification
		}
		for k, n := range map[string]int{"receipt_public_key": 32, "registration_nonce": 32, "key_proof": 64} {
			b, e := DecodeDocument(str(k), n)
			if e != nil || len(b) != n {
				return ErrVerification
			}
		}
		_, e = utc(str("registered_at_utc"))
		return e
	}
	if head.Variant != "scan" && head.Variant != "probe" && head.Variant != "terminal" {
		return ErrVerification
	}
	if !uuid.MatchString(str("runner_id")) || !uuid.MatchString(str("iid")) {
		return ErrVerification
	}
	b, e := DecodeDocument(str("document_b64"), MaxScanDocument)
	if e != nil {
		return e
	}
	_, e = core.ParseCanonical(b)
	return e
}
