package awsverification

import (
	"crypto/ed25519"
	"encoding/json"
	"path"
	"strings"

	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	core "github.com/aidotmarket/aim-data-gateway/verification"
)

func Snapshot(token string, keys map[string]ed25519.PublicKey, j wire.ScanJob, c Config) ([]Object, error) {
	var w struct {
		Audience string `json:"aud"`
		Runner   string `json:"runner_id"`
		Hash     string `json:"manifest_hash"`
		Payload  string `json:"payload_b64"`
	}
	_, e := wire.VerifyControl(token, "aim-scan-snapshot+jwt", "aud runner_id manifest_hash payload_b64", keys, &w, wire.MaxSnapshot)
	if e != nil || w.Audience != j.Envelope.Audience || w.Runner != j.Envelope.RunnerID || w.Hash != j.Text("manifest_hash") {
		return nil, ErrRefused
	}
	b, e := wire.DecodeDocument(w.Payload, 12<<20)
	if e != nil || wire.Digest(b) != w.Hash {
		return nil, ErrRefused
	}
	m, e := closed(b, "snapshot_version source_kind connection_id bucket listing_id listing_version_id source_handle_id members")
	if e != nil {
		return nil, ErrRefused
	}
	for k, v := range map[string]string{
		"snapshot_version":   "verification-source-snapshot-v1",
		"source_kind":        "s3_listing",
		"connection_id":      c.Connection,
		"bucket":             c.Bucket,
		"listing_id":         j.Text("listing_id"),
		"listing_version_id": j.Text("listing_version_id"),
		"source_handle_id":   j.Text("source_handle_id"),
	} {
		if m[k] != v {
			return nil, ErrRefused
		}
	}
	a, ok := m["members"].([]any)
	if !ok || len(a) == 0 || len(a) > MaxMembers {
		return nil, ErrRefused
	}
	objects := make([]Object, 0, len(a))
	for _, v := range a {
		b, e := core.Canonical(v)
		if e != nil {
			return nil, ErrRefused
		}
		fields := "provider key etag size_bytes format"
		if m, ok := v.(map[string]any); ok {
			if _, ok = m["version_id"]; ok {
				fields += " version_id"
			}
		}
		m, e := closed(b, fields)
		if e != nil || m["provider"] != "aws" {
			return nil, ErrRefused
		}
		var o struct {
			Key     string `json:"key"`
			ETag    string `json:"etag"`
			Version string `json:"version_id"`
			Size    int64  `json:"size_bytes"`
			Format  string `json:"format"`
		}
		if json.Unmarshal(b, &o) != nil || !c.permits(o.Key) || o.ETag == "" || strings.ContainsAny(o.ETag, "\"\r\n\x00") {
			return nil, ErrRefused
		}
		if _, exists := m["version_id"]; exists && o.Version == "" {
			return nil, ErrRefused
		}
		ext := strings.TrimPrefix(strings.ToLower(path.Ext(o.Key)), ".")
		if ext == "ndjson" {
			ext = "jsonl"
		}
		if o.Format != ext {
			return nil, ErrRefused
		}
		objects = append(objects, Object{
			Key:       o.Key,
			ETag:      o.ETag,
			VersionID: o.Version,
			Size:      o.Size,
			Format:    o.Format,
		})
	}
	return objects, AdmitSize(objects)
}
