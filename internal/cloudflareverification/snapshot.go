package cloudflareverification

import (
	"crypto/ed25519"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
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
	raw, e := wire.DecodeDocument(w.Payload, MaxSnapshot)
	if e != nil {
		return nil, ErrRefused
	}
	objects, e := ParseSnapshot(raw, w.Hash, SnapshotBinding{ConnectionID: c.Connection, Bucket: c.Bucket, ListingID: j.Text("listing_id"), ListingVersionID: j.Text("listing_version_id"), SourceHandleID: j.Text("source_handle_id")})
	if e != nil {
		return nil, e
	}
	for _, o := range objects {
		if !c.permits(o.Key) {
			return nil, ErrRefused
		}
	}
	return objects, nil
}
