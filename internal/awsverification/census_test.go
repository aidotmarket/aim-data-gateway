package awsverification

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	core "github.com/aidotmarket/aim-data-gateway/verification"
	"github.com/aws/smithy-go"
)

func censusWork(t *testing.T, f *handlerFixture, budget int64) wire.ScanJob {
	t.Helper()
	f.backend.work = resignWork(t, f.backend.work, func(m map[string]any) {
		editPayload(m, func(p map[string]any) {
			p["spec_version"], p["scan_mode"], p["binding_method"] = "2", core.ContentCensusV1, "planned_read_commitment_v2"
			p["planned_processed_bytes"] = budget
			if m["variant"] == "scan" {
				p["depth_class"] = "content_census_sampled_v1"
			}
		})
	})
	j, e := VerifyWork(f.backend.work, map[string]ed25519.PublicKey{platformKey.KID: platformPrivate.Public().(ed25519.PublicKey)}, runnerID, runnerID, f.h.Config.Version, f.at)
	if e != nil {
		t.Fatal(e)
	}
	j.ScannerVersion, j.ReceiptKeyID = f.h.Config.Version, receiptID
	return j
}
func reportDocument(t *testing.T, body []byte) (map[string]any, map[string]any) {
	t.Helper()
	v, e := core.ParseCanonical(body)
	if e != nil {
		t.Fatal(e)
	}
	envelope := v.(map[string]any)
	raw, e := wire.DecodeDocument(envelope["document_b64"].(string), wire.MaxScanDocument)
	if e != nil {
		t.Fatal(e)
	}
	v, e = core.ParseCanonical(raw)
	if e != nil {
		t.Fatal(e)
	}
	return envelope, v.(map[string]any)
}
func member(key, format string, n int) any {
	return map[string]any{"provider": "aws", "key": key, "etag": "RAW_ETAG_MARKER", "size_bytes": n, "format": format}
}
func TestCensusSignedC1VectorCrossParserAndReceipt(t *testing.T) {
	raw, err := os.ReadFile("../../contract/census_plan_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Contract        string
		CommitmentForms []struct {
			Tag      string
			BytesHex string `json:"bytes_hex"`
		} `json:"commitment_forms"`
		Plans []struct {
			Seed string `json:"seed_hex"`
		}
	}
	if err = json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	// C1 supplies deterministic content/plan vectors, not provider JWS envelopes.
	// Frame those same vector bytes in signed AWS work and snapshot documents.
	plain, _ := hex.DecodeString(vectors.CommitmentForms[0].BytesHex)
	archive, _ := hex.DecodeString(vectors.CommitmentForms[1].BytesHex)
	for _, variant := range []string{"probe", "scan"} {
		t.Run(variant, func(t *testing.T) {
			f := newFixture(t)
			f.s3.objects = map[string][]byte{"RAW_KEY_MARKER/a.txt": plain, "RAW_KEY_MARKER/b.zip": archive}
			f.jobWithMembers(t, 1, variant, []any{member("RAW_KEY_MARKER/a.txt", "txt", len(plain)), member("RAW_KEY_MARKER/b.zip", "zip", len(archive))})
			if variant == "scan" {
				f.backend.work = resignWork(t, f.backend.work, func(m map[string]any) {
					editPayload(m, func(p map[string]any) { p["deterministic_seed"] = vectors.Plans[0].Seed })
				})
			}
			j := censusWork(t, f, censusR1ArchiveAllowanceBytes+int64(len(plain)))
			objects, e := Snapshot(f.backend.snapshot, map[string]ed25519.PublicKey{platformKey.KID: platformPrivate.Public().(ed25519.PublicKey)}, j, f.h.Config)
			if e != nil || len(objects) != 2 || objects[1].Format != "zip" {
				t.Fatal(objects, e)
			}
			if e = f.h.Invoke(ctx); e != nil {
				t.Fatal(e)
			}
			envelope, d := reportDocument(t, f.backend.reports[0])
			if _, ok := envelope["member_sha256s"]; ok {
				t.Fatal("v2 leaked member digests")
			}
			signature, _ := base64.StdEncoding.DecodeString(d["receipt_signature"].(string))
			delete(d, "receipt_signature")
			signed, _ := core.Canonical(receiptBinding(d, variant))
			if !ed25519.Verify(f.secrets.s.Private.Public().(ed25519.PublicKey), signed, signature) {
				t.Fatal("receipt signature")
			}
			if variant == "probe" {
				p := d["probe"].(map[string]any)
				if p["source_reachable"] != true || len(f.s3.requests) != 1 {
					t.Fatal(p, f.s3.requests)
				}
				if p["census_preflight"].(map[string]any)["known_processed_bytes"] != json.Number(fmt.Sprint(len(plain)+33)) {
					t.Fatal(p)
				}
			} else {
				census := d["content_census"].(map[string]any)
				if d["binding_method"] != "planned_read_commitment_v2" || !hex64.MatchString(d["unread_binding_sha256"].(string)) || census["depth_class"] != "content_census_complete_v1" {
					t.Fatal(d)
				}
				coverage := d["coverage"].(map[string]any)
				if coverage["objects_in_census"] != json.Number("2") || coverage["objects_scanned"] != json.Number("0") {
					t.Fatal(coverage)
				}
				d["unread_binding_sha256"] = strings.Repeat("0", 64)
				tampered, _ := core.Canonical(receiptBinding(d, variant))
				if ed25519.Verify(f.secrets.s.Private.Public().(ed25519.PublicKey), tampered, signature) {
					t.Fatal("unread binding not signed")
				}
			}
		})
	}
}
func TestCensusWorkVersionsAndClosedEnums(t *testing.T) {
	for _, version := range []string{"0.2.2", ScannerVersion, "0.3.1", "1.0.0"} {
		f := newFixture(t)
		f.h.Config.Version = version
		f.job(t, 1, "scan")
		keys := map[string]ed25519.PublicKey{platformKey.KID: platformPrivate.Public().(ed25519.PublicKey)}
		if _, e := VerifyWork(f.backend.work, keys, runnerID, runnerID, version, f.at); e != nil {
			t.Fatal("v1", version, e)
		}
		token := resignWork(t, f.backend.work, func(m map[string]any) {
			editPayload(m, func(p map[string]any) {
				p["spec_version"] = "2"
				p["scan_mode"] = core.ContentCensusV1
				p["binding_method"] = "planned_read_commitment_v2"
				p["planned_processed_bytes"] = 8
				p["depth_class"] = "content_census_complete_v1"
			})
		})
		_, e := VerifyWork(token, keys, runnerID, runnerID, version, f.at)
		if version == "0.2.2" {
			if !errors.Is(e, core.ErrVerifierUpgradeRequired) {
				t.Fatal(version, e)
			}
		} else if e != nil {
			t.Fatal(version, e)
		}
	}
	for _, variant := range []string{"probe", "scan"} {
		f := newFixture(t)
		f.job(t, 1, variant)
		censusWork(t, f, 0)
		for field, values := range map[string][]any{"scan_mode": {"unknown", "table_v1"}, "binding_method": {"unknown", "full_sha256_v1"}, "planned_processed_bytes": {-1, censusR1BudgetBytes + 1, "1", 1.5}, "spec_version": {"3"}} {
			for _, value := range values {
				token := resignWork(t, f.backend.work, func(m map[string]any) { editPayload(m, func(p map[string]any) { p[field] = value }) })
				if _, e := VerifyWork(token, map[string]ed25519.PublicKey{platformKey.KID: platformPrivate.Public().(ed25519.PublicKey)}, runnerID, runnerID, ScannerVersion, f.at); e == nil {
					t.Fatal(variant, field, value)
				}
			}
		}
	}
}
func TestCensusScopeAndAdmissionEnvelope(t *testing.T) {
	for _, mode := range []string{"", "prefix", "whole_bucket", "unknown"} {
		for _, prefix := range []string{"", "data/", "*"} {
			env := configEnv()
			env[EnvReadScope] = mode
			env[EnvScope] = fmt.Sprintf(`{"keys":[],"prefixes":[%q]}`, prefix)
			c, e := ParseConfig(func(k string) string { return env[k] })
			want := mode == "whole_bucket" && prefix == "" || (mode == "" || mode == "prefix") && prefix == "data/"
			if (e == nil) != want {
				t.Fatal(mode, prefix, e)
			}
			if e == nil && (!c.permits("data/file") || c.permits("database/file") != (mode == "whole_bucket")) {
				t.Fatal("scope", mode)
			}
		}
	}
	for _, objects := range [][]Object{{{Format: "txt", Size: 100_000_000_000}}, {{Format: "zip", Size: 100_000_000_000}}, {{Format: "csv", Size: 1}, {Format: "txt", Size: 9_000_000_000}}} {
		if e := AdmitSize(objects, censusR1BudgetBytes); e != nil {
			t.Fatal(e)
		}
	}
	if !errors.Is(AdmitSize(nil), core.ErrEmptyVersion) || !errors.Is(AdmitSize(make([]Object, MaxMembers+1)), core.ErrMemberCountExceeded) {
		t.Fatal("typed admission")
	}
	if AdmitSize([]Object{{Format: "txt", Size: 1}}, censusR1BudgetBytes+1) == nil || AdmitSize([]Object{{Format: "csv", Size: 6_000_000_001}, {Format: "txt", Size: 1}}, censusR1BudgetBytes) == nil {
		t.Fatal("signed allowance or table limit not enforced")
	}
	if AdmitSize([]Object{{Format: "txt", Size: 1 << 62}, {Format: "txt", Size: 1 << 62}}) == nil {
		t.Fatal("overflow")
	}
}
func zipFixture(t *testing.T, n int, method uint16) []byte {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	w, e := z.CreateHeader(&zip.FileHeader{Name: "inside.txt", Method: method})
	if e != nil {
		t.Fatal(e)
	}
	w.Write(bytes.Repeat([]byte("a"), n))
	if e = z.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}
func tarFixture(t *testing.T, n int) []byte {
	t.Helper()
	var b bytes.Buffer
	g, err := gzip.NewWriterLevel(&b, gzip.NoCompression)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(g)
	tw.WriteHeader(&tar.Header{Name: "inside.txt", Mode: 0600, Size: int64(n)})
	tw.Write(bytes.Repeat([]byte("a"), n))
	tw.Close()
	g.Close()
	return b.Bytes()
}
func TestCensusFreeCheckBoundsAndArchiveFloor(t *testing.T) {
	for _, tc := range []struct {
		name, format string
		data         []byte
		want         int64
		refusal      string
	}{
		{"plain", "txt", bytes.Repeat([]byte("a"), 2<<20), 0, ""},
		{"zip", "zip", zipFixture(t, 2<<20, zip.Store), 1 << 20, ""},
		{"tar", "tar.gz", tarFixture(t, 2<<20), 64 << 10, ""},
		{"ratio", "zip", zipFixture(t, 16<<20, zip.Deflate), -1, "insufficient_readable_content"},
		{"bad_tar", "tar.gz", []byte("broken gzip"), -1, "insufficient_readable_content"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			key := "RAW_KEY_MARKER/a." + tc.format
			f.s3.objects = map[string][]byte{key: tc.data}
			f.jobWithMembers(t, 1, "probe", []any{member(key, tc.format, len(tc.data))})
			censusWork(t, f, censusR1ArchiveAllowanceBytes)
			if e := f.h.Invoke(ctx); e != nil {
				t.Fatal(e)
			}
			_, d := reportDocument(t, f.backend.reports[0])
			probe := d["probe"].(map[string]any)
			if tc.refusal == "" {
				if probe["source_reachable"] != true {
					t.Fatal(probe)
				}
			} else if probe["refusal_reason"] != tc.refusal || probe["source_reachable"] != false {
				t.Fatal(probe)
			}
			if tc.want == 0 {
				if len(f.s3.requests) != 0 {
					t.Fatal("plain content read")
				}
				return
			}
			if len(f.s3.requests) != 1 {
				t.Fatal("unbounded reads", f.s3.requests)
			}
			r := f.s3.requests[0]
			limit := int64(64 << 10)
			if tc.format == "zip" {
				limit = 1 << 20
			}
			if r.End < 0 || r.End-r.Start+1 > limit || tc.want > 0 && r.End-r.Start+1 != tc.want || tc.format != "zip" && r.Start != 0 {
				t.Fatal(r)
			}
		})
	}
	// LOW-H is shared: a directory larger than the tail gets the paid cap verdict.
	b := zipFixture(t, 1, zip.Store)
	binary.LittleEndian.PutUint32(b[len(b)-10:], 2<<20)
	p := scanPolicy(wire.ScanJob{Payload: map[string]any{"scan_mode": core.ContentCensusV1}}, nil)
	if got := core.PreflightZip(b, int64(len(b)), p); got.Reason != "archive_over_cap" {
		t.Fatal(got.Reason)
	}
}
func TestEveryTypedRefusalSurvivesAdapter(t *testing.T) {
	for _, code := range []string{"summary_budget_exceeded", "resource_limit_exceeded", "empty_version", "member_count_exceeded", "insufficient_readable_content", "verifier_upgrade_required", "scanner_failure", "permission_denied", "artifact_changed", "unsupported_type", "timeout"} {
		if got := errorCode(fmt.Errorf("wrapped: %w", core.RefusalError(code))); got != code {
			t.Fatal(code, got)
		}
	}
	if errorCode(context.Canceled) != "timeout" || errorCode(io.ErrUnexpectedEOF) != "scanner_failure" {
		t.Fatal("fallback")
	}
	for code, want := range map[string]string{"AccessDenied": "permission_denied", "PreconditionFailed": "artifact_changed", "NoSuchVersion": "artifact_changed", "InternalError": "scanner_failure"} {
		if errorCode(storageRefusal(&smithy.GenericAPIError{Code: code})) != want {
			t.Fatal(code)
		}
	}
}
func TestCensusUnreadHEADDriftAndNoGET(t *testing.T) {
	f := newFixture(t)
	data := []byte("plain census text")
	key := "RAW_KEY_MARKER/a.txt"
	f.s3.objects = map[string][]byte{key: data}
	j := f.jobWithMembers(t, 1, "scan", []any{member(key, "txt", len(data))})
	_ = j
	j = censusWork(t, f, 0)
	s, e := Bootstrap(ctx, f.h.Config, f.h.Ledger, f.secrets, f.backend, f.at)
	if e != nil {
		t.Fatal(e)
	}
	src, e := NewSource(f.s3, f.h.Config.Bucket, []Object{{Key: key, Format: "txt", Size: int64(len(data)), ETag: f.s3.liveETag}})
	if e != nil {
		t.Fatal(e)
	}
	body, e := f.h.scan(ctx, s, j, src)
	if e != nil {
		t.Fatal(e)
	}
	_, d := reportDocument(t, body)
	if len(f.s3.requests) != 0 || d["depth_class"] != "content_census_sampled_v1" {
		t.Fatal(d, f.s3.requests)
	}
	f.s3.heads = nil
	f.s3.onHead = func(Request) {
		if len(f.s3.heads) == 2 {
			f.s3.headOverride = &Head{Size: int64(len(data)), ETag: "changed"}
		}
	}
	body, e = f.h.scan(ctx, s, j, src)
	if e != nil {
		t.Fatal(e)
	}
	envelope, d := reportDocument(t, body)
	if len(f.s3.heads) != 2 || envelope["variant"] != "terminal" || d["terminal_error_code"] != "artifact_changed" {
		t.Fatal(d)
	}
}
func TestCensusMixedTableProbeTypedSummaryBudget(t *testing.T) {
	f := newFixture(t)
	members := []any{}
	f.s3.objects = map[string][]byte{}
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("RAW_KEY_MARKER/%d.csv", i)
		data := []byte("a,b,c,d,e,f\n" + strings.Repeat("1,2,3,4,5,6\n", 20))
		f.s3.objects[key] = data
		members = append(members, member(key, "csv", len(data)))
	}
	f.s3.objects["RAW_KEY_MARKER/z.txt"] = []byte("census")
	members = append(members, member("RAW_KEY_MARKER/z.txt", "txt", 6))
	f.jobWithMembers(t, 1, "probe", members)
	censusWork(t, f, 6)
	if e := f.h.Invoke(ctx); e != nil {
		t.Fatal(e)
	}
	_, d := reportDocument(t, f.backend.reports[0])
	p := d["probe"].(map[string]any)
	if p["refusal_reason"] != "summary_budget_exceeded" || p["source_reachable"] != false {
		t.Fatal(p)
	}
}

func TestCensusMixedTableProbeTypedResourceLimit(t *testing.T) {
	f := newFixture(t)
	data := []byte("column\n" + strings.Repeat("x", (16<<20)+1) + "\n")
	f.s3.objects = map[string][]byte{"RAW_KEY_MARKER/a.csv": data}
	f.jobWithMembers(t, 1, "probe", []any{member("RAW_KEY_MARKER/a.csv", "csv", len(data))})
	censusWork(t, f, 0)
	if err := f.h.Invoke(ctx); err != nil {
		t.Fatal(err)
	}
	_, d := reportDocument(t, f.backend.reports[0])
	p := d["probe"].(map[string]any)
	if p["refusal_reason"] != "resource_limit_exceeded" || p["source_reachable"] != false {
		t.Fatal(p)
	}
}

type concurrentS3 struct {
	data                           []byte
	heads, gets, maxHeads, maxGets atomic.Int32
}

func activePeak(current, peak *atomic.Int32) {
	n := current.Add(1)
	for {
		old := peak.Load()
		if old >= n || peak.CompareAndSwap(old, n) {
			return
		}
	}
}
func (s *concurrentS3) Head(ctx context.Context, r Request) (Head, error) {
	activePeak(&s.heads, &s.maxHeads)
	defer s.heads.Add(-1)
	select {
	case <-time.After(time.Millisecond):
	case <-ctx.Done():
		return Head{}, ctx.Err()
	}
	return Head{Size: int64(len(s.data)), ETag: "RAW_ETAG_MARKER"}, nil
}
func (s *concurrentS3) Get(ctx context.Context, r Request) (io.ReadCloser, error) {
	activePeak(&s.gets, &s.maxGets)
	select {
	case <-time.After(2 * time.Millisecond):
	case <-ctx.Done():
		s.gets.Add(-1)
		return nil, ctx.Err()
	}
	return &countedBody{Reader: bytes.NewReader(s.data[r.Start : r.End+1]), active: &s.gets}, nil
}

type countedBody struct {
	*bytes.Reader
	active *atomic.Int32
}

func (b *countedBody) Close() error {
	if b.active != nil {
		b.active.Add(-1)
		b.active = nil
	}
	return nil
}
func TestCensusPreflightAndHEADConcurrencyBound(t *testing.T) {
	f := newFixture(t)
	client := &concurrentS3{data: zipFixture(t, 1024, zip.Store)}
	f.h.S3 = client
	members := []any{}
	for i := 0; i < 40; i++ {
		members = append(members, member(fmt.Sprintf("RAW_KEY_MARKER/%02d.zip", i), "zip", len(client.data)))
	}
	f.jobWithMembers(t, 1, "probe", members)
	censusWork(t, f, censusR1BudgetBytes)
	if err := f.h.Invoke(ctx); err != nil {
		t.Fatal(err)
	}
	_, d := reportDocument(t, f.backend.reports[0])
	if d["probe"].(map[string]any)["source_reachable"] != true {
		t.Fatal(d)
	}
	for _, peak := range []int32{client.maxHeads.Load(), client.maxGets.Load()} {
		if peak < 2 || peak > 16 {
			t.Fatal("concurrency", peak)
		}
	}
	if client.heads.Load() != 0 || client.gets.Load() != 0 {
		t.Fatal("unclosed requests")
	}
}

func TestCensusSnapshotFormatsAndLegacyUpgrade(t *testing.T) {
	for _, tc := range []struct {
		key, format string
		valid       bool
	}{
		{"notes.TXT", "txt", true}, {"source.go", "go", true}, {"extensionless", "other", true}, {"bundle.tar.gz", "tar.gz", true}, {"bundle.tgz", "tgz", true}, {"plain.gz", "gz", true}, {"data.ndjson", "jsonl", true}, {"notes.txt", "TXT", false}, {"notes.txt", "csv", false}, {"extensionless", "", false},
	} {
		f := newFixture(t)
		key := "RAW_KEY_MARKER/" + tc.key
		j := f.jobWithMembers(t, 1, "probe", []any{member(key, tc.format, 1)})
		keys := map[string]ed25519.PublicKey{platformKey.KID: platformPrivate.Public().(ed25519.PublicKey)}
		if tc.valid && !tableFormat(tc.format) {
			if _, err := Snapshot(f.backend.snapshot, keys, j, f.h.Config); !errors.Is(err, core.ErrVerifierUpgradeRequired) {
				t.Fatal("old runner", tc, err)
			}
		}
		j = censusWork(t, f, 1)
		objects, err := Snapshot(f.backend.snapshot, keys, j, f.h.Config)
		if (err == nil) != tc.valid {
			t.Fatal(tc, objects, err)
		}
	}
}

func TestCensusModeTableOnlyReceipt(t *testing.T) {
	f := newFixture(t)
	f.job(t, 1, "scan")
	censusWork(t, f, 0)
	if err := f.h.Invoke(ctx); err != nil {
		t.Fatal(err)
	}
	envelope, d := reportDocument(t, f.backend.reports[0])
	if envelope["variant"] != "scan" {
		t.Fatal(d)
	}
	if _, ok := envelope["member_sha256s"]; ok {
		t.Fatal("v2 member digests")
	}
	if d["content_census"] != nil || !hex64.MatchString(d["unread_binding_sha256"].(string)) {
		t.Fatal(d)
	}
}

func TestCensusEmptyMemberDoesNotIssueInvalidRange(t *testing.T) {
	f := newFixture(t)
	key := "RAW_KEY_MARKER/empty.txt"
	f.s3.objects = map[string][]byte{key: {}}
	f.jobWithMembers(t, 1, "scan", []any{member(key, "txt", 0)})
	censusWork(t, f, 0)
	if err := f.h.Invoke(ctx); err != nil {
		t.Fatal(err)
	}
	envelope, d := reportDocument(t, f.backend.reports[0])
	if envelope["variant"] != "scan" || d["depth_class"] != "content_census_complete_v1" || len(f.s3.requests) != 0 {
		t.Fatal(d, f.s3.requests)
	}
}
