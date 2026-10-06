package cloudflareverification

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/aidotmarket/aim-data-gateway/verification"
)

func TestSharedControlVectors(t *testing.T) {
	raw, e := os.ReadFile("../../contract/vectors/verification/r2_listing/control.json")
	if e != nil {
		t.Fatal(e)
	}
	type document struct {
		Canonical string
		SHA       string `json:"sha256"`
	}
	type control struct {
		document
		Payload, Receipt, Body document
		Token                  string
	}
	var v map[string]json.RawMessage
	if e = json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	scanKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{66}, 32)).Public().(ed25519.PublicKey)
	receiptKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32)).Public().(ed25519.PublicKey)
	values := map[string]map[string]any{}
	check := func(d document) map[string]any {
		t.Helper()
		h := sha256.Sum256([]byte(d.Canonical))
		if hex.EncodeToString(h[:]) != d.SHA {
			t.Fatal("document hash")
		}
		value, e := verification.ParseCanonical([]byte(d.Canonical))
		if e != nil {
			t.Fatal(e)
		}
		return value.(map[string]any)
	}
	for _, name := range []string{"scan_spec", "probe_spec", "probe_report", "scan_report", "terminal_report", "http_auth"} {
		var c control
		if e = json.Unmarshal(v[name], &c); e != nil {
			t.Fatal(e)
		}
		m := check(c.document)
		values[name] = m
		if c.Token != "" {
			parts := strings.Split(c.Token, ".")
			if len(parts) != 3 {
				t.Fatal("token")
			}
			sig, e := base64.RawURLEncoding.DecodeString(parts[2])
			if e != nil {
				t.Fatal(e)
			}
			key, typ := scanKey, "aim-scan-spec+jwt"
			if name == "http_auth" {
				key, typ = receiptKey, "aim-verification-request+jwt"
			}
			headerRaw, e := base64.RawURLEncoding.DecodeString(parts[0])
			if e != nil {
				t.Fatal(e)
			}
			header, e := verification.ParseCanonical(headerRaw)
			if e != nil || header.(map[string]any)["typ"] != typ || header.(map[string]any)["alg"] != "EdDSA" {
				t.Fatal("header", e)
			}
			if !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) || ed25519.Verify(key, []byte(parts[0]+"."+parts[1]+"changed"), sig) {
				t.Fatal("signature")
			}
			claims, e := base64.RawURLEncoding.DecodeString(parts[1])
			if e != nil || string(claims) != c.Canonical {
				t.Fatal("claims bytes", e)
			}
			if name != "http_auth" {
				p := check(c.Payload)
				values[name+"_payload"] = p
				payload, e := base64.RawURLEncoding.DecodeString(m["payload_b64"].(string))
				if e != nil || string(payload) != c.Payload.Canonical || m["spec_hash"] != c.Payload.SHA {
					t.Fatal("spec binding", e)
				}
				if m["aud"] != m["runner_id"] || p["source_kind"] != "r2_listing" || p["connector_type"] != "r2_verifier" || p["connector_version"] != "r2_verifier-v1" {
					t.Fatal("Cloudflare spec")
				}
			} else {
				body := check(c.Body)
				values["report_body"] = body
				if m["body_sha256"] != c.Body.SHA || m["kind"] != "cloudflare" || m["method"] != "POST" || m["path"] != "/api/v1/verification-runners/"+m["runner_id"].(string)+"/report" || len(c.Token) > 4096 {
					t.Fatal("HTTP binding")
				}
				if m["binary_sha256"] != strings.Repeat("b", 64) || m["worker_identity"].(map[string]any)["sha256"] != strings.Repeat("c", 64) {
					t.Fatal("release identity")
				}
			}
		} else {
			binding := check(c.Receipt)
			sig, e := base64.StdEncoding.DecodeString(m["receipt_signature"].(string))
			if e != nil || !ed25519.Verify(receiptKey, []byte(c.Receipt.Canonical), sig) {
				t.Fatal("receipt signature", e)
			}
			for k, want := range binding {
				got, _ := verification.Canonical(m[k])
				expected, _ := verification.Canonical(want)
				if !bytes.Equal(got, expected) {
					t.Fatal("receipt binding", k)
				}
			}
		}
	}
	inputRaw, e := os.ReadFile("../../contract/vectors/verification/r2_listing/csv_etag.json")
	if e != nil {
		t.Fatal(e)
	}
	var input struct {
		Snapshot struct {
			Bucket  string
			Members []struct {
				Key, ETag, Format string
				Size              int64 `json:"size_bytes"`
			}
		}
		Hash    string `json:"snapshot_sha256"`
		Members []struct {
			Source string `json:"source_hex"`
		}
	}
	if e = json.Unmarshal(inputRaw, &input); e != nil {
		t.Fatal(e)
	}
	f := &fakeBridge{objects: map[string][]byte{}}
	objects := []Object{}
	for i, m := range input.Snapshot.Members {
		data, e := hex.DecodeString(input.Members[i].Source)
		if e != nil {
			t.Fatal(e)
		}
		f.objects[m.Key] = data
		objects = append(objects, Object{Key: m.Key, ETag: m.ETag, Size: m.Size, Format: m.Format})
	}
	s, e := NewSource(f, input.Snapshot.Bucket, objects)
	if e != nil {
		t.Fatal(e)
	}
	p := policy()
	p.Commitments = Commitments{Bucket: input.Snapshot.Bucket, ManifestHash: input.Hash, Key: [32]byte(bytes.Repeat([]byte{99}, 32))}
	facts, e := verification.Scan(context.Background(), s, p)
	if e != nil {
		t.Fatal(e)
	}
	factRaw, _ := verification.Canonical(facts)
	factMap, e := verification.ParseCanonical(factRaw)
	if e != nil {
		t.Fatal(e)
	}
	for k, want := range factMap.(map[string]any) {
		got, _ := verification.Canonical(values["scan_report"][k])
		expected, _ := verification.Canonical(want)
		if !bytes.Equal(got, expected) {
			t.Fatal("report facts", k)
		}
	}
	probe, e := verification.Probe(context.Background(), s, p)
	if e != nil {
		t.Fatal(e)
	}
	probeMap := values["probe_report"]["probe"].(map[string]any)
	n, _ := probeMap["objects_discovered"].(json.Number).Int64()
	tokens, _ := probeMap["estimated_max_input_tokens"].(json.Number).Int64()
	if int(n) != probe.ObjectsDiscovered || int(tokens) != probe.EstimatedMaxInputTokens || probeMap["size_class"] != probe.SizeClass {
		t.Fatal("probe aggregates", probe)
	}
	for _, name := range []string{"scan_spec_payload", "probe_spec_payload"} {
		if values[name]["manifest_hash"] != input.Hash {
			t.Fatal("snapshot linkage")
		}
	}
	if values["scan_report"]["spec_hash"] != values["scan_spec"]["spec_hash"] || values["terminal_report"]["spec_hash"] != values["scan_spec"]["spec_hash"] || values["probe_report"]["spec_hash"] != values["probe_spec"]["spec_hash"] {
		t.Fatal("report linkage")
	}
	documentRaw, e := base64.RawURLEncoding.DecodeString(values["report_body"]["document_b64"].(string))
	if e != nil {
		t.Fatal(e)
	}
	expected, _ := verification.Canonical(values["scan_report"])
	if !bytes.Equal(documentRaw, expected) {
		t.Fatal("report HTTP bytes")
	}
	companions := values["report_body"]["member_sha256s"].([]any)
	for i, o := range objects {
		h := sha256.Sum256(f.objects[o.Key])
		if companions[i] != hex.EncodeToString(h[:]) {
			t.Fatal("digest companion")
		}
	}
}
