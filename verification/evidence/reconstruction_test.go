//go:build evidence

package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/aidotmarket/aim-data-gateway/internal/wire"
)

type reconstruction struct {
	Runner              string `json:"runner"`
	Fixture             string `json:"fixture"`
	InputSHA256         string `json:"input_sha256"`
	ReportSHA256        string `json:"report_sha256"`
	Recovered           []any  `json:"recovered"`
	Confirmed           []any  `json:"confirmed"`
	Linkable            []any  `json:"linkable"`
	Attempts            []any  `json:"attempts"`
	ExpectationsMatched bool   `json:"expectations_matched"`
}

func csvBytes(t *testing.T, rows [][]string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	must(t, w.WriteAll(rows))
	return b.Bytes()
}

type fixture struct {
	name string
	rows [][]string
}

func newFixtures() []fixture {
	fs := []fixture{
		{"one_row", [][]string{{"id", "title", "optional"}, {"1729", "CP81_uncommon_problem_title", ""}}},
		{"two_row", [][]string{{"id", "title", "optional"}, {"1729", "CP81_first_problem_title", ""}, {"4099", "CP81_second_problem_title", "present"}}},
		{"low_cardinality", [][]string{{"value", "optional"}}},
		{"adversarial_column_name", [][]string{{"CP81_VALUE_IN_COLUMN_NAME_AKIAFAKE", "x\"\\<script>", "null_rate"}, {"hidden_cell", "private_cell", ""}}},
		{"eolymp_shaped", [][]string{{"id", "title", "difficulty", "tags", "solved_count"}}},
	}
	for i := 0; i < 18; i++ {
		nullable := "123"
		if i == 0 {
			nullable = ""
		}
		fs[2].rows = append(fs[2].rows, []string{fmt.Sprintf("category_%d", i%9), nullable})
	}
	for i := 0; i < 20; i++ {
		fs[4].rows = append(fs[4].rows, []string{strconv.Itoa(10001 + i), fmt.Sprintf("Problem %02d", i), strconv.Itoa(i%5 + 1), "graphs", strconv.Itoa(1000 + i)})
	}
	return fs
}

// This attacker sees only decoded reports. Ground truth is supplied separately
// to check its claims; it is never used to produce a recovery candidate.
func attemptAggregates(t *testing.T, obj map[string]any) []any {
	t.Helper()
	r := []any{map[string]any{"property": "exact_row_count", "value": obj["row_count"]}, map[string]any{"property": "column_names", "value": obj["column_names"]}, map[string]any{"property": "column_types", "value": obj["column_types"]}}
	n := int64(obj["row_count"].(float64))
	names := obj["column_names"].([]any)
	for i, name := range names {
		if s, ok := obj["null_rate"].([]any)[i].(string); ok && s != "suppressed_low_occupancy" && n < 100000 {
			// Enumerate counts consistent with the disclosed six-decimal rate.
			var candidates []int64
			for c := int64(0); c <= n; c++ {
				if n > 0 && fmt.Sprintf("%.6f", math.RoundToEven(float64(c)*1e6/float64(n))/1e6) == s {
					candidates = append(candidates, c)
				}
			}
			if len(candidates) == 1 {
				r = append(r, map[string]any{"column": name, "property": "exact_null_count", "value": candidates[0]})
			}
		}
		for _, field := range []string{"numeric_range_buckets", "length_histograms"} {
			if counts, ok := obj[field].([]any)[i].([]any); ok {
				r = append(r, map[string]any{"column": name, "property": field, "counts": counts, "meaning": "fixed bucket occupancies and bounds; no exact cell or min/max"})
				for bucket, count := range counts {
					if count.(float64) == float64(n) && n > 0 {
						bounds := []string{"[-inf,-1000)", "[-1000,-100)", "[-100,-10)", "[-10,0)", "[0,10)", "[10,100)", "[100,1000)", "[1000,+inf)"}
						if field == "length_histograms" {
							bounds = []string{"[0,0]", "[1,1]", "[2,4]", "[5,8]", "[9,16]", "[17,32]", "[33,64]", "[65,128]", "[129,256]", "[257,+inf)"}
						}
						r = append(r, map[string]any{"column": name, "property": "every_row_in_one_bucket", "kind": field, "bucket": bucket, "bounds": bounds[bucket], "row_count": n})
					}
				}
			}
		}
	}
	return r
}

func checkNewFixture(t *testing.T, f fixture, obj map[string]any) {
	t.Helper()
	rows := len(f.rows) - 1
	if obj["row_count"] != float64(rows) {
		t.Error("exact row count changed")
	}
	for i := range f.rows[0] {
		nulls := 0
		distinct := map[string]bool{}
		for _, row := range f.rows[1:] {
			if row[i] == "" {
				nulls++
			} else {
				distinct[row[i]] = true
			}
		}
		check := func(field string, mustSuppress bool) {
			if mustSuppress && obj[field].([]any)[i] != "suppressed_low_occupancy" {
				t.Errorf("%s column %d failed low-occupancy suppression", field, i)
			}
		}
		check("null_rate", rows < 10 || nulls > 0 && nulls < 10 || rows-nulls > 0 && rows-nulls < 10)
		check("approx_distinct_count", rows < 10 || len(distinct) > 0 && len(distinct) <= 9)
		if rows < 10 {
			for _, field := range []string{"length_histograms", "numeric_range_buckets"} {
				v := obj[field].([]any)[i]
				if v != nil && v != "suppressed_low_occupancy" {
					t.Errorf("%s exposed low population", field)
				}
			}
		}
	}
}

func mac(key [32]byte, preimage string) string {
	h := hmac.New(sha256.New, key[:])
	h.Write([]byte(preimage))
	return hex.EncodeToString(h.Sum(nil))
}
func TestE4Reconstruction(t *testing.T) {
	results := []reconstruction{}
	dir := filepath.Join(filepath.Dir(outDir()), "reconstruction")
	// Persist results even on expectation failures (including failed subtests).
	defer func() {
		writeJSON(t, filepath.Join(dir, "results.json"), map[string]any{"release_candidate": baseSHA, "authority": authoritySHA, "results": results, "interpretation": "Suppression protects small occupancies, not row count/schema or all row properties. Cloud member hashes confirm guessed whole-file content and link equal bytes. Dictionary nonmatches are finite empirical evidence, not a cryptographic proof."})
	}()
	for _, kind := range kinds {
		for _, f := range newFixtures() {
			t.Run(kind+"/"+f.name, func(t *testing.T) {
				h := newHarness(t, kind)
				data := csvBytes(t, f.rows)
				local := file{Key: "datasets/eolymp/" + f.name + ".csv", Format: "csv", Data: data}
				frame := h.scan(t, []file{local}, "scan")
				body, doc := document(t, frame)
				if body["variant"] != "scan" {
					t.Fatal("fixture did not scan", body["variant"])
				}
				obj := doc["objects"].([]any)[0].(map[string]any)
				checkNewFixture(t, f, obj)
				r := reconstruction{Runner: kind, Fixture: f.name, InputSHA256: wire.Digest(data), ReportSHA256: wire.Digest(frame), Recovered: attemptAggregates(t, obj), Confirmed: []any{}, Linkable: []any{}, Attempts: []any{}}
				r.Attempts = append(r.Attempts, map[string]any{"attack": "aggregate_cell_recovery", "result": "no exact cell values in aggregate fields; exact row count and schema disclosed"})
				// Guess all fixture strings, including distinctive titles/categories,
				// against the four aggregate fields only (schema is separate).
				aggregates := map[string]any{}
				for _, field := range []string{"null_rate", "approx_distinct_count", "length_histograms", "numeric_range_buckets"} {
					aggregates[field] = obj[field]
				}
				aggregateBytes := canonical(t, aggregates)
				stringCandidates, hits := 0, 0
				for _, row := range f.rows[1:] {
					for _, cell := range row {
						if len(cell) > 6 {
							stringCandidates++
							if bytes.Contains(aggregateBytes, canonical(t, cell)) {
								hits++
							}
						}
					}
				}
				if hits != 0 {
					t.Error("aggregate string dictionary matched cell content", hits)
				}
				r.Attempts = append(r.Attempts, map[string]any{"attack": "distinct_string_value_dictionary", "candidate_tests": stringCandidates, "confirmed_cells": hits, "numeric_counts": "bucket occupancies are counts, not exact cell values"})
				if f.name == "adversarial_column_name" {
					r.Recovered = append(r.Recovered, map[string]any{"property": "value_encoded_as_column_name", "value": f.rows[0][0], "disclosure": "column names pass through by contract; suppression does not sanitize schema text"})
				}
				if kind == "aim_gateway" {
					r.Attempts = append(r.Attempts, gatewayDictionary(t, h, local, doc))
					r.Attempts = append(r.Attempts, gatewayContentDictionary(t, local, doc, &r))
				} else {
					r.Attempts = append(r.Attempts, contentDictionary(t, body, local, &r))
				}
				write(t, filepath.Join(dir, kind, f.name+".frame"), frame)
				r.ExpectationsMatched = !t.Failed()
				results = append(results, r)
			})
		}
		// All committed oracle fixtures, with pinned input/expected digests and
		// seed. Compare aggregate fields to the independent oracle object.
		var manifest struct {
			Files []struct {
				Name, Input, Expected, Format, Seed string
				Refusal                             bool
				InputSHA                            string `json:"input_sha256"`
				ExpectedSHA                         string `json:"expected_sha256"`
			}
		}
		must(t, json.Unmarshal(read(t, "../testdata/oracle/manifest.json"), &manifest))
		for _, v := range manifest.Files {
			t.Run(kind+"/oracle/"+v.Name, func(t *testing.T) {
				data := read(t, "../testdata/oracle/"+v.Input)
				expected := read(t, "../testdata/oracle/"+v.Expected)
				if wire.Digest(data) != v.InputSHA || wire.Digest(expected) != v.ExpectedSHA {
					t.Fatal("oracle digest drift")
				}
				h := newHarness(t, kind)
				h.seed = v.Seed
				frame := h.scan(t, []file{{Key: "oracle/" + v.Input, Format: v.Format, Data: data}}, "scan")
				body, doc := document(t, frame)
				r := reconstruction{Runner: kind, Fixture: "oracle/" + v.Name, InputSHA256: wire.Digest(data), ReportSHA256: wire.Digest(frame), Recovered: []any{}, Confirmed: []any{}, Linkable: []any{}, Attempts: []any{}}
				if v.Refusal {
					if body["variant"] != "terminal" {
						t.Error("expected refusal")
					}
					r.Attempts = append(r.Attempts, map[string]any{"attack": "aggregate_recovery", "result": "terminal refusal; no facts"})
				} else {
					if body["variant"] != "scan" {
						t.Fatal("oracle scan refused", doc)
					}
					obj := doc["objects"].([]any)[0].(map[string]any)
					var want map[string]any
					must(t, json.Unmarshal(expected, &want))
					for _, field := range []string{"column_names", "column_types", "null_rate", "approx_distinct_count", "length_histograms", "numeric_range_buckets", "row_count", "row_count_method"} {
						if !reflect.DeepEqual(obj[field], want[field]) {
							t.Errorf("oracle mismatch %s: got %v want %v", field, obj[field], want[field])
						}
					}
					r.Recovered = attemptAggregates(t, obj)
				}
				write(t, filepath.Join(dir, kind, "oracle", v.Name+".frame"), frame)
				r.ExpectationsMatched = !t.Failed()
				results = append(results, r)
			})
		}
		t.Run(kind+"/repeated_content", func(t *testing.T) {
			h := newHarness(t, kind)
			data := []byte("id,title,difficulty,tags,solved_count\n1,Sum,1,math,1200\n2,Paths,2,graphs,350\n")
			first := h.scan(t, []file{{"archive/problems.csv", "csv", data}, {"datasets/problems.csv", "csv", data}}, "scan")
			second := h.scan(t, []file{{"exports/problems.csv", "csv", data}}, "scan")
			b1, d1 := document(t, first)
			b2, d2 := document(t, second)
			r := reconstruction{Runner: kind, Fixture: "repeated_content", InputSHA256: wire.Digest(data), ReportSHA256: wire.Digest(first), Recovered: []any{}, Confirmed: []any{}, Linkable: []any{}, Attempts: []any{}}
			if kind != "aim_gateway" {
				a := b1["member_sha256s"].([]any)
				b := b2["member_sha256s"].([]any)
				if len(a) != 2 || len(b) != 1 || a[0] != a[1] || a[0] != b[0] || a[0] != wire.Digest(data) {
					t.Error("expected duplicate linkability missing")
				}
				r.Linkable = append(r.Linkable, map[string]any{"within_report": true, "across_reports": true, "hash": a[0], "meaning": "identical whole-file bytes, even under different keys"})
			} else {
				if b1["member_sha256s"] != nil || b2["member_sha256s"] != nil {
					t.Error("unexpected gateway member hashes")
				}
				r.Attempts = append(r.Attempts, map[string]any{"attack": "per_file_hash_equality", "result": "member_sha256s absent on gateway"})
			}
			objects := d1["objects"].([]any)
			if objects[0].(map[string]any)["object_id"] == objects[1].(map[string]any)["object_id"] {
				t.Error("different keys should have different object IDs")
			}
			if d1["artifact_locator_commitment"] == d2["artifact_locator_commitment"] {
				t.Error("different manifests should differ")
			}
			acrossObjectID := d2["objects"].([]any)[0].(map[string]any)["object_id"]
			for _, object := range objects {
				if object.(map[string]any)["object_id"] == acrossObjectID {
					t.Error("different keys across reports should have different object IDs")
				}
			}
			r.Attempts = append(r.Attempts, map[string]any{"attack": "keyed_identity_equality", "object_ids_equal_within_report": false, "object_ids_equal_across_reports": false, "locator_commitments_equal_across_reports": false, "meaning": "different keys/manifests produce different keyed identities despite equal content"})
			firstObject := objects[0].(map[string]any)
			secondObject := d2["objects"].([]any)[0].(map[string]any)
			delete(firstObject, "object_id")
			delete(secondObject, "object_id")
			if !reflect.DeepEqual(firstObject, secondObject) {
				t.Error("equal content changed aggregates")
			}
			r.Linkable = append(r.Linkable, map[string]any{"equal_aggregate_signature": true, "meaning": "matching row count/schema/suppressed aggregates is consistent with duplicates, but does not prove equal content"})
			write(t, filepath.Join(dir, kind, "repeated_first.frame"), first)
			write(t, filepath.Join(dir, kind, "repeated_second.frame"), second)
			r.ExpectationsMatched = !t.Failed()
			results = append(results, r)
		})
	}
	t.Logf("E4: %d per-runner fixture results; artifacts %s", len(results), dir)
}

func gatewayContentDictionary(t *testing.T, f file, doc map[string]any, r *reconstruction) any {
	t.Helper()
	id := wire.Digest([]byte(f.Key))[:32]
	candidates := [][]byte{[]byte("id,title\n"), f.Data, append(append([]byte(nil), f.Data...), '\n')}
	confirmed := 0
	for _, data := range candidates {
		var preimage bytes.Buffer
		must(t, binary.Write(&preimage, binary.BigEndian, uint64(len(id))))
		preimage.WriteString(id)
		must(t, binary.Write(&preimage, binary.BigEndian, uint64(len(data))))
		digest := sha256.Sum256(data)
		preimage.Write(digest[:])
		if wire.Digest(preimage.Bytes()) == doc["content_sha256"] {
			confirmed++
			r.Confirmed = append(r.Confirmed, map[string]any{"attack": "gateway_whole_snapshot_content_dictionary", "candidate_sha256": wire.Digest(data), "meaning": "exact snapshot guess confirmed when public file identity and size are known"})
		}
	}
	if confirmed != 1 {
		t.Error("whole snapshot dictionary should confirm exact candidate", confirmed)
	}
	return map[string]any{"attack": "gateway_whole_snapshot_content_dictionary", "public_file_id_granted": true, "candidates": len(candidates), "confirmed": confirmed, "field": "content_sha256"}
}

func gatewayDictionary(t *testing.T, h *harness, f file, doc map[string]any) any {
	t.Helper()
	obj := doc["objects"].([]any)[0].(map[string]any)
	manifest := wire.Digest(canonical(t, []file{f}))
	gateway := h.gateway.GatewayID
	paths := []string{"data/problems.csv", "exports/problems.csv", "datasets/eolymp/problems.csv", "backups/problems.csv", "s3://customer-data/problems.csv", "r2://datasets/problems.csv", f.Key}
	keys := [][32]byte{{}, sha256.Sum256(h.private.Public().(ed25519.PublicKey)), sha256.Sum256(h.private.Seed()), sha256.Sum256([]byte(manifest))}
	attempts, hits := 0, 0
	for _, key := range keys {
		locator := mac(key, "gateway_listing\x00"+gateway+"\x00"+manifest)
		attempts++
		if locator == doc["artifact_locator_commitment"] {
			hits++
		}
		for _, path := range paths {
			id := wire.Digest([]byte(path))[:32]
			object := mac(key, "object\x00gateway_listing\x00"+gateway+"\x00"+id+"\x00"+wire.Digest(f.Data))
			attempts++
			if object == obj["object_id"] {
				hits++
			}
			unkeyed := sha256.Sum256([]byte("object\x00gateway_listing\x00" + gateway + "\x00" + id + "\x00" + wire.Digest(f.Data)))
			attempts++
			if hex.EncodeToString(unkeyed[:]) == obj["object_id"] {
				hits++
			}
		}
	}
	// Positive controls prove the exact preimage/candidate is included; only this
	// control may use the customer key, never the attacker loop above.
	id := wire.Digest([]byte(f.Key))[:32]
	if mac(h.key, "gateway_listing\x00"+gateway+"\x00"+manifest) != doc["artifact_locator_commitment"] || mac(h.key, "object\x00gateway_listing\x00"+gateway+"\x00"+id+"\x00"+wire.Digest(f.Data)) != obj["object_id"] {
		t.Error("dictionary positive control failed")
	}
	if hits != 0 {
		t.Error("commitment dictionary unexpectedly matched", hits)
	}
	return map[string]any{"attack": "locator_and_object_dictionary", "paths": paths, "candidate_keys": []string{"zero", "sha256_receipt_public", "sha256_receipt_seed_stronger_than_cloud_access", "sha256_manifest"}, "attempts": attempts, "matches_without_customer_key": hits, "customer_key_positive_control": true, "exact_content_and_public_identity_granted": true}
}

func contentDictionary(t *testing.T, body map[string]any, f file, r *reconstruction) any {
	t.Helper()
	corpus := []file{{"empty.csv", "csv", []byte("id,title\n")}, {"sum.csv", "csv", []byte("id,title,difficulty,tags,solved_count\n1,Sum,1,math,1200\n")}, {"users.csv", "csv", []byte("id,name\n1,Alice\n2,Bob\n")}, f, {"changed.csv", "csv", append(append([]byte(nil), f.Data...), '\n')}}
	confirmed := 0
	hashes := body["member_sha256s"].([]any)
	for _, candidate := range corpus {
		digest := wire.Digest(candidate.Data)
		for index, value := range hashes {
			if value == digest {
				confirmed++
				r.Confirmed = append(r.Confirmed, map[string]any{"candidate": candidate.Key, "member_index": index, "sha256": digest, "meaning": "whole-file guess confirmed, including its cells and rows"})
			}
		}
	}
	if confirmed != 1 {
		t.Errorf("content dictionary confirmed %d candidates, expected 1", confirmed)
	}
	return map[string]any{"attack": "candidate_content_dictionary", "candidates": len(corpus), "confirmed": confirmed, "expected_disclosed_behavior": true}
}
