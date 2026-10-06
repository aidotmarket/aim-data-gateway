package cloudflareverification

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aidotmarket/aim-data-gateway/verification"
)

func TestSnapshotClosedShapeAndBinding(t *testing.T) {
	raw, e := os.ReadFile("../../contract/vectors/verification/r2_listing/csv_etag.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		Snapshot  map[string]any
		Canonical string `json:"snapshot_canonical"`
	}
	if json.Unmarshal(raw, &v) != nil {
		t.Fatal("vector")
	}
	parsed, e := verification.ParseCanonical([]byte(v.Canonical))
	if e != nil {
		t.Fatal(e)
	}
	v.Snapshot = parsed.(map[string]any)
	b := SnapshotBinding{v.Snapshot["connection_id"].(string), v.Snapshot["bucket"].(string), v.Snapshot["listing_id"].(string), v.Snapshot["listing_version_id"].(string), v.Snapshot["source_handle_id"].(string)}
	canonical, e := verification.Canonical(v.Snapshot)
	if e != nil {
		t.Fatal(e)
	}
	hash := func(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
	if _, e := ParseSnapshot(canonical, hash(canonical), b); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(map[string]any){
		func(s map[string]any) { s["source_kind"] = "s3_listing" },
		func(s map[string]any) { s["source_handle_id"] = "changed" },
		func(s map[string]any) { s["bucket"] = "changed" },
		func(s map[string]any) { s["extra"] = true },
		func(s map[string]any) { s["members"] = nil },
		func(s map[string]any) { s["members"].([]any)[0].(map[string]any)["version_id"] = "v1" },
		func(s map[string]any) { s["members"].([]any)[0].(map[string]any)["provider"] = "aws" },
		func(s map[string]any) {
			m := s["members"].([]any)[0].(map[string]any)
			delete(m, "size_bytes")
			m["other"] = 0
		},
		func(s map[string]any) { s["members"].([]any)[0].(map[string]any)["size_bytes"] = nil },
		func(s map[string]any) { s["members"].([]any)[0].(map[string]any)["size_bytes"] = 1.5 },
		func(s map[string]any) { s["members"].([]any)[0].(map[string]any)["format"] = "tsv" },
		func(s map[string]any) { s["members"].([]any)[0].(map[string]any)["etag"] = "\"quoted\"" },
	} {
		copy, e := verification.ParseCanonical(canonical)
		if e != nil {
			t.Fatal(e)
		}
		s := copy.(map[string]any)
		change(s)
		changed, _ := verification.Canonical(s)
		if _, e := ParseSnapshot(changed, hash(changed), b); e == nil {
			t.Fatal("accepted", string(changed))
		}
	}
	for _, bad := range [][]byte{append(append([]byte(nil), canonical...), '\n'), bytes.Replace(canonical, []byte(`"provider":"r2"`), []byte(`"provider":"r2","provider":"r2"`), 1), bytes.Repeat([]byte{'x'}, MaxSnapshot+1)} {
		if _, e := ParseSnapshot(bad, hash(bad), b); e == nil {
			t.Fatal("encoding/size")
		}
	}
	if _, e := ParseSnapshot(canonical, strings.Repeat("a", 64), b); e == nil {
		t.Fatal("hash binding")
	}
}

func TestAdmissionBoundaries(t *testing.T) {
	for _, objects := range [][]Object{
		{{Format: "csv", Size: CF_VERIFY_TEXT_MAX_BYTES}},
		{{Format: "parquet", Size: CF_VERIFY_PARQUET_MAX_BYTES}},
		{{Format: "csv", Size: 2_000_000_000}, {Format: "parquet", Size: 350_000_000}},
	} {
		if e := AdmitSize(objects); e != nil {
			t.Fatal("exact bound", e)
		}
		objects[len(objects)-1].Size++
		if AdmitSize(objects) == nil {
			t.Fatal("over bound")
		}
	}
	for _, objects := range [][]Object{{{Format: "zip", Size: 1}}, {{Format: "csv", Size: -1}}, {{Format: "csv", Size: 1 << 62}}, {{Format: "csv", Size: 4_000_000_001}}} {
		if AdmitSize(objects) == nil {
			t.Fatal(objects)
		}
	}
	objects := make([]Object, MaxMembers)
	for i := range objects {
		objects[i] = Object{Key: fmt.Sprintf("%05d.csv", i), ETag: "etag", Format: "csv"}
	}
	f := &fakeBridge{}
	if _, e := NewSource(f, "fixture", objects); e != nil {
		t.Fatal("member limit", e)
	}
	if _, e := NewSource(f, "fixture", append(objects, Object{Key: "z.csv", ETag: "etag", Format: "csv"})); e == nil {
		t.Fatal("member excess")
	}
	if WorstReportSize(MaxMembers) != 2097115 || WorstReportSize(MaxMembers+1) <= MaxReport {
		t.Fatal("report envelope")
	}
	if len(f.heads)+len(f.requests) != 0 {
		t.Fatal("pre-read admission")
	}
	for _, pair := range [][2]string{{"", "pin"}, {"key", ""}, {"a\x00b", "pin"}, {"key", "p\x00in"}, {"\xff", "pin"}, {"key", "\xff"}, {"\xc3", "\xa9"}} {
		if _, e := Identity(pair[0], pair[1]); e == nil {
			t.Fatal(pair)
		}
	}
	s, _ := fixture(t, []byte("n\n12\n"), "csv")
	m := s.Members()
	m[0].OrderingKey[0] = 'x'
	m[0].Identity = "changed"
	if reflect.DeepEqual(m, s.Members()) {
		t.Fatal("mutable member view")
	}
	if _, e := s.Open(context.Background(), "nonmember"); e != verification.ErrArtifactChanged {
		t.Fatal("scope", e)
	}
}

func TestSharedBridgeCases(t *testing.T) {
	raw, e := os.ReadFile("../../contract/vectors/verification/r2_listing/bridge_cases.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		Cases []struct {
			Name, Operation, Fault string
			Expected               string `json:"expected_error"`
		}
	}
	if e = json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			format := "csv"
			data := []byte("n\n" + strings.Repeat("12\n", 20))
			if c.Operation == "scan_parquet" {
				format = "parquet"
				var e error
				data, e = os.ReadFile("../../verification/testdata/oracle/all_approved_types.parquet")
				if e != nil {
					t.Fatal(e)
				}
			}
			if c.Fault == "none" {
				format = "parquet"
				data = bytes.Repeat([]byte{7}, CF_VERIFY_PARQUET_READ_AHEAD_BYTES+101)
			}
			s, f := fixture(t, data, format)
			id := s.members[0].Identity
			if strings.HasPrefix(c.Operation, "scan_") {
				f.mutate = func(f *fakeBridge, r Request) {
					if len(f.requests) == 2 {
						if c.Fault == "etag" {
							f.liveETag = "changed"
						} else {
							changed := append([]byte(nil), data...)
							changed[len(changed)-3] ^= 1
							f.objects[r.Key] = changed
						}
					}
				}
				facts, e := verification.Scan(context.Background(), s, policy())
				if e != verification.ErrArtifactChanged || !reflect.DeepEqual(facts, verification.Facts{}) {
					t.Fatal("mutation", e)
				}
				return
			}
			if c.Operation == "head" {
				f.headFault = c.Fault
			} else {
				f.fault = c.Fault
			}
			var err error
			if c.Operation == "range" {
				at, e := s.OpenAt(context.Background(), id)
				if e != nil {
					t.Fatal(e)
				}
				defer at.Close()
				_, err = at.ReadAt(make([]byte, 1), 0)
				if c.Fault == "retry" {
					if err != verification.ErrArtifactChanged {
						t.Fatal(err)
					}
					_, err = at.ReadAt(make([]byte, 1), 0)
					if len(f.requests) != 2 || !reflect.DeepEqual(f.requests[0], f.requests[1]) {
						t.Fatal("retry pins")
					}
				}
				if c.Fault == "none" {
					if err != nil {
						t.Fatal(err)
					}
					_, err = at.ReadAt(make([]byte, 1), int64(len(data)-1))
					if len(f.requests) != 2 {
						t.Fatal("refills")
					}
				}
			} else {
				body, e := s.Open(context.Background(), id)
				err = e
				if body != nil {
					_, err = io.Copy(io.Discard, body)
					body.Close()
				}
			}
			if c.Expected == "artifact_changed" && err != verification.ErrArtifactChanged || c.Expected != "artifact_changed" && err != nil {
				t.Fatal(c.Expected, err)
			}
			for _, r := range append(f.heads, f.requests...) {
				if r.IfMatch != "etag" || r.Key != "e\u0301."+format || r.Bucket != "fixture" || r.MemberIndex != 0 {
					t.Fatal("unpinned fallback", r)
				}
			}
		})
	}
}

func TestVectorDigestManifest(t *testing.T) {
	dir := "../../contract/vectors/verification/r2_listing"
	raw, e := os.ReadFile(filepath.Join(dir, "VECTORS.sha256"))
	if e != nil {
		t.Fatal(e)
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		parts := strings.Fields(line)
		if len(parts) != 2 || seen[parts[1]] {
			t.Fatal(line)
		}
		seen[parts[1]] = true
		b, e := os.ReadFile(filepath.Join(dir, parts[1]))
		if e != nil {
			t.Fatal(e)
		}
		h := sha256.Sum256(b)
		if hex.EncodeToString(h[:]) != parts[0] {
			t.Fatal("vector digest", parts[1])
		}
	}
	paths, e := filepath.Glob(filepath.Join(dir, "*.json"))
	if e != nil || len(paths) != len(seen) {
		t.Fatal("manifest completeness")
	}
}
