//go:build evidence

package evidence

import (
	"bytes"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httputil"
	"path/filepath"
	"strings"
	"testing"
	"time"

	aws "github.com/aidotmarket/aim-data-gateway/internal/awsverification"
	cf "github.com/aidotmarket/aim-data-gateway/internal/cloudflareverification"
	"github.com/aidotmarket/aim-data-gateway/internal/config"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	"github.com/apache/arrow-go/v18/parquet"
	pf "github.com/apache/arrow-go/v18/parquet/file"
	"github.com/apache/arrow-go/v18/parquet/schema"
)

type capture struct {
	Runner           string         `json:"runner"`
	Class            string         `json:"class"`
	File             string         `json:"file"`
	Bytes            int            `json:"bytes"`
	SHA256           string         `json:"bytes_sha256"`
	MarkerHits       map[string]int `json:"marker_hits"`
	DecodedDocuments int            `json:"inspected_layers"`
}

// Recursively inspect JSON strings, all JWS segments and embedded base64
// documents. Searching parsed strings also catches JSON-escaped source text.
func searchLayers(raw []byte, visit func([]byte), depth int) {
	if depth > 12 {
		return
	}
	visit(raw)
	var v any
	if json.Unmarshal(raw, &v) == nil {
		var walk func(any)
		walk = func(v any) {
			switch x := v.(type) {
			case map[string]any:
				for k, v := range x {
					visit([]byte(k))
					walk(v)
				}
			case []any:
				for _, v := range x {
					walk(v)
				}
			case string:
				searchLayers([]byte(x), visit, depth+1)
			}
		}
		walk(v)
	}
	s := strings.TrimPrefix(string(raw), "Bearer ")
	parts := []string{s}
	if strings.Count(s, ".") == 2 {
		parts = strings.Split(s, ".")
	}
	for _, part := range parts {
		for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.StdEncoding, base64.RawStdEncoding} {
			b, e := enc.DecodeString(part)
			if e == nil && len(b) > 0 && !bytes.Equal(b, raw) {
				searchLayers(b, visit, depth+1)
				break
			}
		}
	}
}

func seededFiles(t *testing.T) []file {
	t.Helper()
	v := vector(t, "snapshot")
	sources := v["source_hex"].(map[string]any)
	// Extend a committed CSV source in memory; no vector/fixture is changed.
	ids := []string{"32f29f33d51165a6808e62cc3dfe85d0", "92f7a3adf19d2990c721c18a591c9ce2"}
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	must(t, w.Write([]string{"id", "local_note"}))
	for _, id := range ids {
		raw, e := hex.DecodeString(sources[id].(string))
		must(t, e)
		rows, e := csv.NewReader(bytes.NewReader(raw)).ReadAll()
		must(t, e)
		for _, row := range rows[1:] {
			must(t, w.Write([]string{row[0], strings.Join(markers, " | ")}))
		}
	}
	w.Flush()
	must(t, w.Error())
	// A real column-comment marker is also present in Parquet footer metadata.
	// The scanner reads this file through its real random-access adapter.
	node, e := schema.NewPrimitiveNode("id", parquet.Repetitions.Required, parquet.Types.Int64, -1, -1)
	must(t, e)
	root, e := schema.NewGroupNode("schema", parquet.Repetitions.Required, schema.FieldList{node}, -1)
	must(t, e)
	var pq bytes.Buffer
	writer := pf.NewParquetWriter(&pq, root)
	must(t, writer.AppendKeyValueMetadata("column.id.comment", markers[4]))
	group := writer.AppendRowGroup()
	column, e := group.NextColumn()
	must(t, e)
	_, e = column.(*pf.Int64ColumnChunkWriter).WriteBatch([]int64{4, 5, 6}, nil, nil)
	must(t, e)
	must(t, column.Close())
	must(t, group.Close())
	must(t, writer.Close())
	return []file{{Key: markers[1] + "/" + markers[3] + "/data.csv", Format: "csv", Data: b.Bytes()}, {Key: markers[1] + "/" + markers[3] + "/comment.parquet", Format: "parquet", Data: pq.Bytes()}}
}

func TestE2ByteCaptures(t *testing.T) {
	var captures []capture
	for _, kind := range kinds {
		t.Run(kind, func(t *testing.T) {
			h := newHarness(t, kind)
			save := func(class string, raw []byte) {
				if frameObserver != nil {
					frameObserver(t, kind, class, raw)
				}
				if len(raw) == 0 {
					t.Fatal("empty capture", class)
				}
				c := capture{Runner: kind, Class: class, File: kind + "/" + class + ".frame", Bytes: len(raw), SHA256: wire.Digest(raw), MarkerHits: map[string]int{}}
				for _, marker := range markers {
					c.MarkerHits[marker] = 0
				}
				searchLayers(raw, func(b []byte) {
					c.DecodedDocuments++
					for _, marker := range markers {
						c.MarkerHits[marker] += bytes.Count(b, []byte(marker))
					}
				}, 0)
				// Preserve offending frames and summary before making the test fail.
				write(t, filepath.Join(outDir(), c.File), raw)
				captures = append(captures, c)
				for marker, n := range c.MarkerHits {
					if n != 0 {
						t.Errorf("%s leaked %q (%d hits)", class, marker, n)
					}
				}
			}
			save("registration", h.registration)
			files := seededFiles(t)
			for _, variant := range []string{"probe", "scan"} {
				before := h.reads
				b := h.scan(t, files, variant)
				if h.reads <= before {
					t.Fatal("seeded source was not read")
				}
				body, doc := document(t, b)
				if body["variant"] != variant {
					t.Fatalf("expected %s, got %v", variant, body["variant"])
				}
				if variant == "probe" {
					if _, ok := doc["affected_file_ids"]; !ok {
						t.Fatal("affected_file_ids absent")
					}
					if doc["probe"].(map[string]any)["source_reachable"] != true {
						t.Fatal("probe unreachable")
					}
				}
				if variant == "scan" && kind != "aim_gateway" {
					hashes := body["member_sha256s"].([]any)
					if len(hashes) != 2 || hashes[0] != wire.Digest(files[1].Data) || hashes[1] != wire.Digest(files[0].Data) {
						t.Fatal("member hash not real scanned content")
					}
				}
				save(variant, b)
				if kind != "aim_gateway" {
					client := &http.Client{Transport: trip(func(req *http.Request) (*http.Response, error) {
						raw, e := httputil.DumpRequestOut(req, true)
						must(t, e)
						save(variant+"_http_request", raw)
						// Search the authorization token as a separate structured frame
						// so its JWS segments are decoded as well as the raw HTTP bytes.
						save(variant+"_request_claims", []byte(strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")))
						return response(req, string(canonical(t, map[string]any{"iid": body["iid"], "status": "stored"}))), nil
					})}
					if kind == "aws_s3_verifier" {
						must(t, (aws.HTTPBackend{Client: client, Config: h.awsConfig, Now: func() time.Time { return at }}).Report(ctx, h.awsSecret, b, body["iid"].(string)))
					} else {
						must(t, (cf.HTTPBackend{Client: client, Config: h.cfConfig, Now: func() time.Time { return at }}).Report(ctx, h.cfSecret, b, body["iid"].(string)))
					}
				}
				if kind == "aim_gateway" {
					entry, e := h.gateway.Log.Read(h.gateway.Log.Sequence())
					must(t, e)
					raw, e := wire.Canonical(entry)
					must(t, e)
					save(variant+"_audit", raw)
				}
			}
			bad := []file{{Key: markers[1] + "/" + markers[3] + "/broken.csv", Format: "csv", Data: []byte("id,note\n1,\"" + strings.Join(markers, " | ") + "\n")}}
			unreachable := h.scan(t, bad, "probe")
			unreachableBody, unreachableDoc := document(t, unreachable)
			if unreachableBody["variant"] != "probe" || unreachableDoc["probe"].(map[string]any)["source_reachable"] != false {
				t.Fatal("invalid source should yield unreachable probe")
			}
			save("probe_unreachable", unreachable)
			if kind == "aim_gateway" {
				previousConfig := h.gateway.Config
				cfg := previousConfig()
				cfg.Columns = map[string]config.Columns{}
				for _, f := range files {
					cfg.Columns[f.Key] = config.Columns{Drop: []string{"id"}}
				}
				h.gateway.Config = func() config.Config { return cfg }
				affected := h.scan(t, files, "probe")
				_, affectedDoc := document(t, affected)
				if len(affectedDoc["affected_file_ids"].([]any)) != len(files) {
					t.Fatal("hidden-column probe omitted affected IDs")
				}
				save("probe_affected_file_ids", affected)
				h.gateway.Config = previousConfig
			}
			b := h.scan(t, bad, "scan")
			body, doc := document(t, b)
			if body["variant"] != "terminal" || doc["terminal_error_code"] == nil {
				t.Fatal("malformed source did not produce terminal")
			}
			save("terminal", b)
			if kind == "aim_gateway" {
				entry, e := h.gateway.Log.Read(h.gateway.Log.Sequence())
				must(t, e)
				raw, e := wire.Canonical(entry)
				must(t, e)
				save("terminal_audit", raw)
			}
			if kind == "aim_gateway" {
				// Actual snapshot-request signing and HTTP serialization, captured
				// before any network operation. Gateway has no outbound work poll.
				h.gateway.HTTP = &http.Client{Transport: trip(func(r *http.Request) (*http.Response, error) {
					save("snapshot_claims", []byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")))
					return response(r, "local-snapshot-response"), nil
				})}
				_, e := gatewaySnapshot(h.gateway, ctx, job(t, kind, "scan"))
				must(t, e)
				entry, e := h.gateway.Log.Append("error", wire.GatewayError{Code: "consent_refused", Message: "consent_refused"})
				must(t, e)
				raw, e := wire.Canonical(entry)
				must(t, e)
				save("audit_error", raw)
				m, e := h.gateway.Keys.Registration(h.gateway.GatewayID, at)
				must(t, e)
				entry, e = h.gateway.Log.Append("scan_report", m)
				must(t, e)
				raw, e = wire.Canonical(entry)
				must(t, e)
				save("registration_audit", raw)
			} else {
				current := "work"
				client := &http.Client{Transport: trip(func(r *http.Request) (*http.Response, error) {
					save(current+"_claims", []byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")))
					if current == "work" {
						return response(r, `{"work_jws":null}`), nil
					}
					return response(r, "local-snapshot-response"), nil
				})}
				if kind == "aws_s3_verifier" {
					b := aws.HTTPBackend{Client: client, Config: h.awsConfig, Now: func() time.Time { return at }}
					_, e := b.Work(ctx, h.awsSecret)
					must(t, e)
					current = "snapshot"
					_, e = b.Snapshot(ctx, h.awsSecret, job(t, kind, "scan").Text("manifest_hash"))
					must(t, e)
				} else {
					b := cf.HTTPBackend{Client: client, Config: h.cfConfig, Now: func() time.Time { return at }}
					_, e := b.Work(ctx, h.cfSecret)
					must(t, e)
					current = "snapshot"
					_, e = b.Snapshot(ctx, h.cfSecret, job(t, kind, "scan").Text("manifest_hash"))
					must(t, e)
				}
				var log bytes.Buffer
				if kind == "aws_s3_verifier" {
					must(t, (aws.Logs{Output: &log}).Event(ctx, "refused", wire.Digest(bad[0].Data)))
				} else {
					must(t, (cf.Logs{Output: &log}).Event(ctx, "refused", wire.Digest(bad[0].Data)))
				}
				save("audit_error", log.Bytes())
			}
		})
	}
	writeJSON(t, filepath.Join(outDir(), "summary.json"), map[string]any{
		"release_candidate": baseSHA, "authority": authoritySHA, "markers": markers, "captures": captures,
		"scope":       "local real serializers; private scanner entry points, not signed admission or live TLS",
		"class_notes": map[string]string{"aim_gateway.work": "inbound control instruction; no customer-to-cloud work poll", "cloud.audit_error": "fixed refused event and hash, not a gateway error envelope"},
	})
	t.Logf("E2: %d frames; source markers searched raw, JSON-unescaped and base64/JWS-decoded; artifacts %s", len(captures), outDir())
}

func TestMarkerSearchPositiveControls(t *testing.T) {
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.StdEncoding, base64.RawStdEncoding} {
		raw := canonical(t, map[string]any{"document_b64": enc.EncodeToString(canonical(t, map[string]any{"cell": markers[0]}))})
		hits := 0
		searchLayers(raw, func(b []byte) { hits += bytes.Count(b, []byte(markers[0])) }, 0)
		if hits == 0 {
			t.Error("embedded marker positive control missed")
		}
	}
	raw := []byte(`{"cell":"CP81_CELL_73\u006319b"}`)
	hits := 0
	searchLayers(raw, func(b []byte) { hits += bytes.Count(b, []byte(markers[0])) }, 0)
	if hits == 0 {
		t.Error("JSON-escaped marker positive control missed")
	}
}
