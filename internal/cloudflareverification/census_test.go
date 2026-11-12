package cloudflareverification

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	core "github.com/aidotmarket/aim-data-gateway/verification"
)

// Serialize test bookkeeping for parallel preflight and paid admission HEADs.
type lockedBridge struct {
	*fakeBridge
	mu sync.Mutex
}

func (b *lockedBridge) Head(ctx context.Context, r Request) (*Head, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.fakeBridge.Head(ctx, r)
}
func (b *lockedBridge) Get(ctx context.Context, r Request) (GetResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	result, err := b.fakeBridge.Get(ctx, r)
	if result.Body != nil {
		result.Body = lockedBody{result.Body, &b.mu}
	}
	return result, err
}

type lockedBody struct {
	io.ReadCloser
	mu *sync.Mutex
}

func (b lockedBody) Close() error { b.mu.Lock(); defer b.mu.Unlock(); return b.ReadCloser.Close() }

func censusPolicy() core.Policy {
	return scanPolicy(wireCensusJob(), &collectedCommitments{Commitments: Commitments{Bucket: "fixture"}, Digests: map[string]string{}})
}
func censusSource(t *testing.T, objects []Object, data map[string][]byte) (*Source, *lockedBridge) {
	t.Helper()
	b := &lockedBridge{fakeBridge: &fakeBridge{objects: data}}
	s, err := NewSource(b, "fixture", objects)
	if err != nil {
		t.Fatal(err)
	}
	return s, b
}

func snapshotRaw(t *testing.T, j wire.ScanJob, bucket string, objects []Object) []byte {
	t.Helper()
	members := make([]any, 0, len(objects))
	for _, o := range objects {
		members = append(members, map[string]any{"provider": "r2", "key": o.Key, "etag": o.ETag, "size_bytes": o.Size, "format": o.Format})
	}
	return canonicalTest(t, map[string]any{"snapshot_version": "verification-source-snapshot-v1", "source_kind": "r2_listing", "connection_id": testConfig().Connection, "bucket": bucket, "listing_id": j.Text("listing_id"), "listing_version_id": j.Text("listing_version_id"), "source_handle_id": j.Text("source_handle_id"), "members": members})
}

func signedSnapshot(t *testing.T, j wire.ScanJob, c Config, objects []Object) (string, wire.ScanJob) {
	t.Helper()
	raw := snapshotRaw(t, j, c.Bucket, objects)
	j.Payload["manifest_hash"] = wire.Digest(raw)
	token, err := signJWS(censusTestKey(0x24), censusPlatformKID, "aim-scan-snapshot+jwt", map[string]any{"aud": j.Envelope.Audience, "runner_id": j.Envelope.RunnerID, "manifest_hash": wire.Digest(raw), "payload_b64": base64.RawURLEncoding.EncodeToString(raw)})
	if err != nil {
		t.Fatal(err)
	}
	return token, j
}
func smallTar(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	g, _ := gzip.NewWriterLevel(&b, gzip.NoCompression)
	w := tar.NewWriter(g)
	for i := 0; i < 3; i++ {
		data := bytes.Repeat([]byte("census text\n"), 5500)
		if err := w.WriteHeader(&tar.Header{Name: fmt.Sprintf("entry%d.txt", i), Mode: 0600, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func TestSmallTarGzipThroughCloudflareSource(t *testing.T) {
	data := smallTar(t)
	if len(data) < 190<<10 || len(data) > 210<<10 {
		t.Fatal(len(data))
	}
	s, b := censusSource(t, []Object{{Key: "a.tar.gz", ETag: "pin", Format: "tar.gz", Size: int64(len(data))}}, map[string][]byte{"a.tar.gz": data})
	p := censusPolicy()
	p.RunStats = &core.RunStats{}
	facts, err := core.Scan(context.Background(), s, p)
	if err != nil || facts.ContentCensus == nil || facts.ContentCensus.DepthClass != "content_census_complete_v1" || facts.ContentCensus.CoverageContent.LimitedCoverage {
		t.Fatal(facts, err)
	}
	if len(b.requests) != 1 || b.requests[0].Range == nil || *b.requests[0].Range != (Range{0, int64(len(data))}) {
		t.Fatal(b.requests)
	}
	if p.RunStats.GETs.Load() != 1 || p.RunStats.RequestedBytes.Load() != censusR1ArchiveAllowanceBytes+(1<<20) || p.RunStats.StoredBytes.Load() != int64(len(data)) {
		t.Fatal(p.RunStats)
	}
}
func TestCensusRangeBoundariesAndPins(t *testing.T) {
	s, b := censusSource(t, []Object{{Key: "a.txt", ETag: "pin", Format: "txt", Size: 6}}, map[string][]byte{"a.txt": []byte("abcdef")})
	id := s.members[0].Identity
	for _, v := range [][2]int64{{-1, 1}, {0, -1}, {7, 1}} {
		if _, err := s.OpenRange(context.Background(), id, v[0], v[1]); !errors.Is(err, core.ErrArtifactChanged) {
			t.Fatal(v, err)
		}
	}
	for _, v := range [][2]int64{{6, 0}, {6, 100}, {0, 0}, {2, 100}, {2, 2}} {
		r, err := s.OpenRange(context.Background(), id, v[0], v[1])
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(r)
		r.Close()
		if err != nil || string(got) != "abcdef"[v[0]:min(6, v[0]+v[1])] {
			t.Fatal(v, string(got), err)
		}
	}
	if len(b.requests) != 2 || *b.requests[0].Range != (Range{2, 4}) || *b.requests[1].Range != (Range{2, 2}) {
		t.Fatal(b.requests)
	}
	for _, fault := range []string{"etag", "size", "short", "long", "range"} {
		b.fault = fault
		r, err := s.OpenRange(context.Background(), id, 0, 6)
		if err == nil {
			_, err = io.ReadAll(r)
			r.Close()
		}
		if !errors.Is(err, core.ErrArtifactChanged) {
			t.Fatal(fault, err)
		}
	}
}
func TestCensusScopeModesAndScale(t *testing.T) {
	for _, mode := range []string{"", "keys", "prefix", "whole_bucket", "unknown"} {
		for _, prefix := range []string{"data", "", "*", "data/*"} {
			c := testConfig()
			c.ReadScope = mode
			c.Prefix = prefix
			if mode == "prefix" || mode == "whole_bucket" {
				c.Keys = []string{}
			} else {
				c.Keys = []string{"data/a.txt"}
			}
			want := mode != "unknown" && !strings.Contains(prefix, "*") && !(mode == "prefix" && prefix == "") && !(mode == "whole_bucket" && prefix != "")
			if (c.Validate() == nil) != want {
				t.Fatalf("mode=%q prefix=%q: %v", mode, prefix, c.Validate())
			}
		}
	}
	c := testConfig()
	c.ReadScope = "prefix"
	c.Prefix = "data"
	c.Keys = []string{}
	if !c.permits("data/file") || c.permits("database/file") || c.permits("data") {
		t.Fatal("prefix boundary")
	}
	c.ReadScope = "whole_bucket"
	c.Prefix = ""
	if !c.permits("any/file") || c.permits("") {
		t.Fatal("bucket scope")
	}
	for _, mode := range []string{"", "keys", "prefix", "whole_bucket"} {
		c := testConfig()
		c.ReadScope = mode
		c.Prefix = "p/"
		c.Keys = []string{"p/a?b.csv", "p/x*y.csv", "p/${literal}.csv"}
		if (c.Validate() == nil) != (mode == "" || mode == "keys") {
			t.Fatal("literal keys", mode)
		}
		c.Keys = []string{"p/a\x00b.csv"}
		if c.Validate() == nil {
			t.Fatal("NUL key", mode)
		}
	}
	objects := make([]Object, MaxMembers)
	keys := make([]string, MaxMembers)
	for i := range objects {
		keys[i] = fmt.Sprintf("data/%05d/%s.txt", i, strings.Repeat("x", 50))
		objects[i] = Object{Key: keys[i], ETag: "pin", Format: "txt", Size: 1}
	}
	c = testConfig()
	c.Prefix = "data"
	c.ReadScope = "prefix"
	c.Keys = []string{}
	if c.Validate() != nil {
		t.Fatal("prefix config")
	}
	if len(canonicalTest(t, c)) > 1<<20 {
		t.Fatal("scope size")
	}
	for _, o := range objects {
		if !c.permits(o.Key) {
			t.Fatal(o.Key)
		}
	}
	if _, err := NewSource(&fakeBridge{}, "fixture", objects); err != nil {
		t.Fatal(err)
	}
	v := generateCensusReceipts(t)["cf_receipt_success_complete.json"].(censusReceiptVector)
	j := verifyCensusSpec(t, v.Spec)
	token, j := signedSnapshot(t, j, c, objects)
	admitted, err := Snapshot(token, map[string]ed25519.PublicKey{censusPlatformKID: censusTestKey(0x24).Public().(ed25519.PublicKey)}, j, c)
	if err != nil || len(admitted) != MaxMembers {
		t.Fatal(len(admitted), err)
	}
	c.ReadScope = "keys"
	c.Keys = keys
	if c.Validate() == nil {
		t.Fatal("fixture must exceed canonical keys-list limit")
	}
}

func TestCensusLiteralKeysAndPrefixPatterns(t *testing.T) {
	for _, mode := range []string{"", "keys", "prefix"} {
		for _, prefix := range []string{"p/*", "p/?", "p/${", "p/\x00"} {
			c := testConfig()
			c.ReadScope, c.Prefix = mode, prefix
			c.Keys = []string{prefix + "/file.csv"}
			if mode == "prefix" {
				c.Keys = []string{}
			}
			want := mode != "prefix" && !strings.ContainsRune(prefix, 0)
			if (c.Validate() == nil) != want {
				t.Fatalf("mode=%q prefix=%q: %v", mode, prefix, c.Validate())
			}
		}
	}
}

func TestCensusSnapshotV1AndScopeBinding(t *testing.T) {
	v := generateCensusReceipts(t)["cf_receipt_success_complete.json"].(censusReceiptVector)
	j := verifyCensusSpec(t, v.Spec)
	c := testConfig()
	c.ReadScope = "prefix"
	c.Keys = []string{}
	objects := []Object{{Key: "p/a.csv", ETag: "pin", Format: "csv", Size: 1}, {Key: "p/b.txt", ETag: "pin", Format: "txt", Size: 2}}
	keys := map[string]ed25519.PublicKey{censusPlatformKID: censusTestKey(0x24).Public().(ed25519.PublicKey)}
	token, j := signedSnapshot(t, j, c, objects)
	if _, err := Snapshot(token, keys, j, c); err != nil {
		t.Fatal(err)
	}
	delete(j.Payload, "scan_mode")
	j.Payload["spec_version"] = "1"
	if _, err := Snapshot(token, keys, j, c); !errors.Is(err, core.ErrVerifierUpgradeRequired) {
		t.Fatal("v1 census", err)
	}
	token, j = signedSnapshot(t, j, c, objects[:1])
	if _, err := Snapshot(token, keys, j, c); err != nil {
		t.Fatal("v1 table", err)
	}
	j.Payload["scan_mode"] = core.ContentCensusV1
	j.Payload["spec_version"] = "2"
	for _, prefix := range []string{"outside/", "p-other/"} {
		c.Prefix = prefix
		if _, err := Snapshot(token, keys, j, c); err == nil {
			t.Fatal("scope escape", prefix)
		}
	}
	c.ReadScope = "whole_bucket"
	c.Prefix = ""
	if _, err := Snapshot(token, keys, j, c); err != nil {
		t.Fatal(err)
	}
	objects[0].Format = "CSV"
	token, j = signedSnapshot(t, j, c, objects[:1])
	if _, err := Snapshot(token, keys, j, c); err == nil {
		t.Fatal("format mismatch")
	}
}

func scanDocument(t *testing.T, j wire.ScanJob, src *Source) (map[string]any, map[string]any) {
	t.Helper()
	raw, err := (Handler{Config: testConfig(), Now: func() time.Time { return j.Issued }}).scan(context.Background(), &Secret{Private: censusTestKey(0x42), Receipt: receipt}, j, src)
	if err != nil {
		t.Fatal(err)
	}
	body := mapTest(t, raw)
	docRaw, err := wire.DecodeDocument(body["document_b64"].(string), wire.MaxScanDocument)
	if err != nil {
		t.Fatal(err)
	}
	return body, mapTest(t, docRaw)
}

func TestCensusHandlerEnvelopeAndTypedRefusals(t *testing.T) {
	v := generateCensusReceipts(t)["cf_receipt_success_complete.json"].(censusReceiptVector)
	j := verifyCensusSpec(t, v.Spec)
	j.ScannerVersion = ScannerVersion
	j.ReceiptKeyID = receipt
	s, _ := censusSource(t, []Object{{Key: "a.txt", ETag: "pin", Format: "txt", Size: 3}}, map[string][]byte{"a.txt": []byte("abc")})
	body, d := scanDocument(t, j, s)
	if body["member_sha256s"] != nil || d["content_census"] == nil || d["unread_binding_sha256"] == nil || d["coverage"].(map[string]any)["objects_in_census"] != json.Number("1") {
		t.Fatal(body, d)
	}
	for _, test := range []struct {
		name  string
		count int
		data  []byte
		code  string
	}{
		{"five_tables", 5, []byte("a,b,c,d,e,f\n1,2,3,4,5,6\n"), "summary_budget_exceeded"},
		{"wide_row", 1, []byte("a\n" + strings.Repeat("z", (16<<20)+1) + "\n"), "resource_limit_exceeded"},
	} {
		t.Run(test.name, func(t *testing.T) {
			objects := []Object{}
			data := map[string][]byte{}
			for i := 0; i < test.count; i++ {
				key := fmt.Sprintf("%d.csv", i)
				objects = append(objects, Object{Key: key, ETag: "pin", Format: "csv", Size: int64(len(test.data))})
				data[key] = test.data
			}
			s, _ := censusSource(t, objects, data)
			j.Envelope.Variant = "probe"
			_, d := scanDocument(t, j, s)
			p := d["probe"].(map[string]any)
			if p["source_reachable"] != false || p["refusal_reason"] != test.code || p["census_preflight"] != nil {
				t.Fatal(p)
			}
		})
	}
	for _, err := range []error{core.ErrSummaryBudget, core.ErrResourceLimit, core.ErrArtifactChanged, core.ErrPermissionDenied, core.ErrUnsupported, core.ErrTimeout, core.ErrScannerFailure, core.ErrVerifierUpgradeRequired} {
		if errorCode(fmt.Errorf("wrapped: %w", err)) != err.Error() {
			t.Fatal(err)
		}
	}
}
func TestCensusAdmissionEnvelope(t *testing.T) {
	for _, objects := range [][]Object{
		{{Format: "txt", Size: 1 << 40}},
		{{Format: "zip", Size: 1 << 40}, {Format: "csv", Size: 1}},
		{{Format: "other", Size: 0}},
	} {
		if err := AdmitSize(objects, censusR1BudgetBytes); err != nil {
			t.Fatal(err)
		}
	}
	for _, objects := range [][]Object{
		{{Format: "txt", Size: math.MaxInt64}, {Format: "zip", Size: 1}},
		{{Format: "csv", Size: CF_VERIFY_TEXT_MAX_BYTES + 1}, {Format: "txt", Size: 1}},
		{{Format: "parquet", Size: CF_VERIFY_PARQUET_MAX_BYTES + 1}},
	} {
		if AdmitSize(objects, censusR1BudgetBytes) == nil {
			t.Fatal(objects)
		}
	}
	if !errors.Is(AdmitSize([]Object{{Format: "txt", Size: 1}}, censusR1BudgetBytes+1), core.ErrResourceLimit) {
		t.Fatal("budget")
	}
	for _, format := range []string{"txt", "other", "tar.gz", "zip"} {
		key := "a." + format
		if format == "other" {
			key = "no-extension"
		}
		if _, err := NewSource(&fakeBridge{}, "fixture", []Object{{Key: key, Format: format, ETag: "pin", Size: 1}}); err != nil {
			t.Fatal(format, err)
		}
	}
}
func TestCensusFreePreflightAndWire(t *testing.T) {
	var z bytes.Buffer
	zw := zip.NewWriter(&z)
	w, _ := zw.CreateHeader(&zip.FileHeader{Name: "a.txt", Method: zip.Store})
	w.Write(bytes.Repeat([]byte("z"), 200<<10))
	zw.Close()
	tarData := smallTar(t)
	s, b := censusSource(t, []Object{{Key: "a.tar.gz", ETag: "pin", Format: "tar.gz", Size: int64(len(tarData))}, {Key: "b.zip", ETag: "pin", Format: "zip", Size: int64(z.Len())}, {Key: "c.txt", ETag: "pin", Format: "txt", Size: 3}}, map[string][]byte{"a.tar.gz": tarData, "b.zip": z.Bytes(), "c.txt": []byte("abc")})
	result, err := probe(context.Background(), s, censusPolicy())
	if err != nil || result.CensusPreflight == nil {
		t.Fatal(result, err)
	}
	f := result.CensusPreflight
	if f.FloorResult != "meets_floor" || f.AdmissionResult != "within_bounds" || f.ArchiveRequestsBand != "1-9" {
		t.Fatal(f)
	}
	if len(b.requests) != 2 {
		t.Fatal(b.requests)
	}
	for _, r := range b.requests {
		limit := int64(1 << 20)
		if r.Key == "a.tar.gz" {
			limit = 64 << 10
		}
		if r.Range == nil || r.Range.Length > limit {
			t.Fatal(r)
		}
	}
	v := generateCensusReceipts(t)["cf_receipt_success_complete.json"].(censusReceiptVector)
	j := verifyCensusSpec(t, v.Spec)
	j.Envelope.Variant = "probe"
	raw, err := (Handler{Config: testConfig(), Now: func() time.Time { return j.Issued }}).scan(context.Background(), &Secret{Private: censusTestKey(0x42), Receipt: receipt}, j, s)
	if err != nil {
		t.Fatal(err)
	}
	body := mapTest(t, raw)
	docRaw, _ := wire.DecodeDocument(body["document_b64"].(string), wire.MaxScanDocument)
	doc := mapTest(t, docRaw)
	probeDoc := doc["probe"].(map[string]any)
	aggregate := probeDoc["census_preflight"].(map[string]any)
	if len(aggregate) != 3 || probeDoc["source_reachable"] != true {
		t.Fatal(probeDoc)
	}
	for _, x := range aggregate {
		if _, ok := x.(string); !ok {
			t.Fatal("not enum", x)
		}
	}
}

func TestCensusWorkClosedSchemasAndEligibility(t *testing.T) {
	v := generateCensusReceipts(t)["cf_receipt_success_complete.json"].(censusReceiptVector).Spec
	raw, _ := wire.DecodeDocument(strings.Split(v.Token, ".")[1], 64<<10)
	for _, variant := range []string{"scan", "probe"} {
		env := mapTest(t, raw)
		if variant == "probe" {
			env["variant"] = "probe"
			delete(env, "d6_b64")
			delete(env, "d6_hash")
			editPayload(env, func(p map[string]any) {
				for k := range p {
					if !strings.Contains(" "+probeFields+censusFields+" ", " "+k+" ") {
						delete(p, k)
					}
				}
				p["probe_id"] = "22222222-2222-4222-8222-222222222222"
				p["planned_processed_bytes"] = censusR1BudgetBytes
			})
		}
		now, _ := utc(v.Now)
		verify := func(env map[string]any, version string) error {
			_, err := VerifyWork(signCensusSpec(t, env), map[string]ed25519.PublicKey{censusPlatformKID: censusTestKey(0x24).Public().(ed25519.PublicKey)}, v.GatewayID, v.RunnerID, version, now)
			return err
		}
		for _, version := range []string{"0.2.0", "0.2.1", "1.0.0"} {
			if err := verify(env, version); err != nil {
				t.Fatal(variant, version, err)
			}
		}
		for _, version := range []string{"0.1.2", "0.0.9", "0.2.0-beta", "bad"} {
			if !errors.Is(verify(env, version), core.ErrVerifierUpgradeRequired) {
				t.Fatal(variant, version)
			}
		}
		for _, field := range []string{"spec_version", "scan_mode", "binding_method", "planned_processed_bytes", "unknown", "content_read_budget_bytes", "archive_allowance_bytes", "archive_caps", "pattern_versions"} {
			changed := mapTest(t, canonicalTest(t, env))
			editPayload(changed, func(p map[string]any) {
				p[field] = "unknown"
				if field == "spec_version" {
					p[field] = "1"
				}
			})
			if verify(changed, ScannerVersion) == nil {
				t.Fatal(variant, field)
			}
		}
		for _, value := range []any{int64(-1), censusR1BudgetBytes + 1, "1", json.Number("1.0"), nil} {
			changed := mapTest(t, canonicalTest(t, env))
			editPayload(changed, func(p map[string]any) { p["planned_processed_bytes"] = value })
			if verify(changed, ScannerVersion) == nil {
				t.Fatal(variant, value)
			}
		}
		for _, field := range strings.Fields(censusFields) {
			changed := mapTest(t, canonicalTest(t, env))
			editPayload(changed, func(p map[string]any) { delete(p, field) })
			if verify(changed, ScannerVersion) == nil {
				t.Fatal("missing", variant, field)
			}
		}
	}
}
