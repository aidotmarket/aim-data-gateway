package awsverification

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	core "github.com/aidotmarket/aim-data-gateway/verification"
)

func tableProbeDocument(t *testing.T, census bool) []byte {
	t.Helper()
	f := newFixture(t)
	f.at = time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	j := f.job(t, 1, "probe")
	if census {
		j = censusWork(t, f, censusR1ArchiveAllowanceBytes)
	}
	src, err := NewSource(f.s3, f.h.Config.Bucket, []Object{{Key: "RAW_KEY_MARKER/data.csv", ETag: f.s3.liveETag, Format: "csv", Size: int64(len(f.s3.objects["RAW_KEY_MARKER/data.csv"]))}})
	if err != nil {
		t.Fatal(err)
	}
	body, err := f.h.scan(ctx, &Secret{Receipt: receiptID, Private: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))}, j, src)
	if err != nil {
		t.Fatal(err)
	}
	v, err := core.ParseCanonical(body)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := wire.DecodeDocument(v.(map[string]any)["document_b64"].(string), wire.MaxScanDocument)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestTableOnlyProbeDocumentGolden(t *testing.T) {
	want, err := os.ReadFile("testdata/table_probe.json")
	if err != nil {
		t.Fatal(err)
	}
	if got := tableProbeDocument(t, false); !bytes.Equal(got, want) {
		t.Fatalf("table-only document changed:\n%s", got)
	}
	// A v2 table-only version must also omit the census object.
	v, err := core.ParseCanonical(tableProbeDocument(t, true))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := v.(map[string]any)["probe"].(map[string]any)["census_preflight"]; ok {
		t.Fatal("table-only v2 emitted census preflight")
	}
}

func contractZip(t *testing.T, sizes []int, encrypted int, prefix int) []byte {
	t.Helper()
	var b bytes.Buffer
	b.Write(bytes.Repeat([]byte("s"), prefix))
	z := zip.NewWriter(&b)
	z.SetOffset(int64(prefix))
	for i, n := range sizes {
		w, err := z.CreateHeader(&zip.FileHeader{Name: fmt.Sprintf("PRIVATE_ENTRY_%d.txt", i), Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(bytes.Repeat([]byte("x"), n)); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	data := b.Bytes()
	cd := int(binary.LittleEndian.Uint32(data[len(data)-6:]))
	for i := range sizes {
		if i == encrypted {
			binary.LittleEndian.PutUint16(data[cd+8:], binary.LittleEndian.Uint16(data[cd+8:])|1)
		}
		cd += 46 + int(binary.LittleEndian.Uint16(data[cd+28:])) + int(binary.LittleEndian.Uint16(data[cd+30:])) + int(binary.LittleEndian.Uint16(data[cd+32:]))
	}
	return data
}

func TestMixedProbeClosedCensusPreflight(t *testing.T) {
	f := newFixture(t)
	plain, archive, tar := []byte("PRIVATE_CONTENT"), contractZip(t, []int{11, 7}, 1, 0), tarFixture(t, 5)
	table := f.s3.objects["RAW_KEY_MARKER/data.csv"]
	keys := []string{"RAW_KEY_MARKER/a.txt", "RAW_KEY_MARKER/b.zip", "RAW_KEY_MARKER/c.tar.gz", "RAW_KEY_MARKER/data.csv"}
	formats, data := []string{"txt", "zip", "tar.gz", "csv"}, [][]byte{plain, archive, tar, table}
	f.s3.objects = map[string][]byte{}
	var members []any
	for i, key := range keys {
		f.s3.objects[key] = data[i]
		members = append(members, member(key, formats[i], len(data[i])))
	}
	f.jobWithMembers(t, 1, "probe", members)
	censusWork(t, f, censusR1ArchiveAllowanceBytes)
	if err := f.h.Invoke(ctx); err != nil {
		t.Fatal(err)
	}
	envelope, d := reportDocument(t, f.backend.reports[0])
	probe := d["probe"].(map[string]any)
	if probe["source_reachable"] != true {
		t.Fatal(probe)
	}
	want := map[string]any{
		"known_processed_bytes":          json.Number(fmt.Sprint(len(plain) + 18)),
		"known_readable_stored_bytes":    json.Number(fmt.Sprint(len(plain) + 11)),
		"unknown_expansion_containers":   json.Number("1"),
		"unknown_expansion_stored_bytes": json.Number(fmt.Sprint(len(tar))),
		"zip_entries":                    json.Number("2"),
		"archive_get_requests":           json.Number("3"), // zip tail + one readable entry, plus tar.gz.
	}
	if !reflect.DeepEqual(probe["census_preflight"], want) {
		t.Fatalf("got %#v; want %#v", probe["census_preflight"], want)
	}
	// Close the containing documents too: no old aggregates or per-member data.
	wantProbe := "listing_id source_handle_id connector_type connector_version owner_consent source_reachable objects_discovered size_class supported_capabilities estimated_max_input_tokens preview_requested census_preflight"
	assertFields(t, probe, wantProbe)
	assertFields(t, d, "probe_id spec_id spec_hash nonce_echo install_key_id affected_file_ids signature_algorithm probe receipt_signature")
	assertFields(t, envelope, "op variant runner_id iid document_b64")
	for _, marker := range []string{"RAW_KEY_MARKER", "PRIVATE_ENTRY", "PRIVATE_CONTENT", "RAW_CELL_MARKER", "RAW_ETAG_MARKER"} {
		raw, _ := core.Canonical(d)
		if bytes.Contains(raw, []byte(marker)) {
			t.Fatalf("member data leaked: %s", marker)
		}
	}
}

func assertFields(t *testing.T, got map[string]any, fields string) {
	t.Helper()
	want := map[string]bool{}
	for _, k := range strings.Fields(fields) {
		want[k] = true
	}
	if len(got) != len(want) {
		t.Fatalf("field set: %v; want %s", got, fields)
	}
	for k := range got {
		if !want[k] {
			t.Fatalf("unexpected field %s", k)
		}
	}
}

func TestZipPreflightPlanCountsAndCaps(t *testing.T) {
	p := scanPolicy(wire.ScanJob{Payload: map[string]any{"scan_mode": core.ContentCensusV1}}, nil)
	many := make([]int, 10002)
	for _, tc := range []struct {
		name                           string
		sizes                          []int
		encrypted, prefix              int
		allowance                      int64
		known, readable, entries, gets int64
	}{
		{"plain_zip", []int{11, 7}, -1, 0, 64, 18, 18, 2, 3},
		{"full_prefix", []int{11, 7}, -1, 5, 1024, 18, 18, 2, 4},
		{"encrypted_prefix", []int{11, 7}, 1, 5, 1024, 18, 11, 2, 2},
		{"allowance_stop", []int{11, 7, 1}, -1, 5, 12, 11, 11, 3, 2},
		{"no_entry_fits", []int{11}, -1, 5, 10, 0, 0, 1, 1},
		{"entry_cap", many, -1, 0, 64, 0, 0, 10001, 10001},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := contractZip(t, tc.sizes, tc.encrypted, tc.prefix)
			p.ArchiveAllowanceBytes = tc.allowance
			z := core.PreflightZip(data[max(0, len(data)-(1<<20)):], int64(len(data)), p)
			if z.Reason != "" {
				t.Fatal(z.Reason)
			}
			got := zipPreflight(z, data[max(0, len(data)-(1<<20)):], int64(len(data)), p)
			if got.err != nil || got.KnownProcessedBytes != tc.known || got.KnownReadableStoredBytes != tc.readable || got.ZipEntries != tc.entries || got.ArchiveGetRequests != tc.gets {
				t.Fatalf("got %+v; want %+v", got, tc)
			}
		})
	}
}

func TestArchivePreflightRefusedAndUnconfirmedCounts(t *testing.T) {
	for _, tc := range []struct {
		name, format string
		data         []byte
		entries      int64
	}{
		{"ratio_cap", "zip", zipFixture(t, 16<<20, zip.Deflate), 1},
		{"directory_cap", "zip", func() []byte {
			b := contractZip(t, []int{1}, -1, 0)
			binary.LittleEndian.PutUint32(b[len(b)-10:], 2<<20)
			return b
		}(), 1},
		{"not_tar", "tar.gz", []byte("not a tar.gz"), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			key := "RAW_KEY_MARKER/a." + tc.format
			f.s3.objects = map[string][]byte{key: tc.data}
			src, err := NewSource(f.s3, f.h.Config.Bucket, []Object{{Key: key, ETag: f.s3.liveETag, Format: tc.format, Size: int64(len(tc.data))}})
			if err != nil {
				t.Fatal(err)
			}
			p := scanPolicy(wire.ScanJob{Payload: map[string]any{"scan_mode": core.ContentCensusV1}}, nil)
			got := preflight(ctx, src, src.Members()[0], p)
			want := censusPreflight{ZipEntries: tc.entries, ArchiveGetRequests: 1}
			if got.err != nil || got.censusPreflight != want {
				t.Fatalf("got %+v; want %+v", got, want)
			}
		})
	}
}

func TestZipPreflightGETFormulaMatchesC1(t *testing.T) {
	for _, tc := range []struct {
		name              string
		encrypted, prefix int
		gets              int64
	}{
		{"all_readable", -1, 0, 3},
		{"prefix", -1, 5, 4},
		{"encrypted", 1, 5, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			data := contractZip(t, []int{1024, 1024}, tc.encrypted, tc.prefix)
			key := "RAW_KEY_MARKER/a.zip"
			f.s3.objects = map[string][]byte{key: data}
			src, err := NewSource(f.s3, f.h.Config.Bucket, []Object{{Key: key, ETag: f.s3.liveETag, Format: "zip", Size: int64(len(data))}})
			if err != nil {
				t.Fatal(err)
			}
			c := &collectedCommitments{Digests: map[string]string{}}
			p := scanPolicy(wire.ScanJob{Payload: map[string]any{"scan_mode": core.ContentCensusV1, "planned_processed_bytes": json.Number(fmt.Sprint(censusR1ArchiveAllowanceBytes))}}, c)
			planned := preflight(ctx, src, src.Members()[0], p)
			p.RunStats = &core.RunStats{}
			if _, err := core.Scan(ctx, src, p); err != nil {
				t.Fatal(err)
			}
			if planned.ArchiveGetRequests != tc.gets || p.RunStats.GETs.Load() != tc.gets {
				t.Fatalf("planned %d; C1 actual %d; want %d", planned.ArchiveGetRequests, p.RunStats.GETs.Load(), tc.gets)
			}
		})
	}
}
