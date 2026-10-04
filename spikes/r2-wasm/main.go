package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	h "github.com/aidotmarket/aim-data-gateway/spikes/harness"
	v "github.com/aidotmarket/aim-data-gateway/verification"
)

func scan(data []byte, format string) string {
	o := h.Object{Key: "spike/wasm-fixture", ETag: "memory", Format: format}
	m := v.Member{Identity: h.Identity(o), Size: int64(len(data)), SHA256: sha256.Sum256(data), Format: format}
	c := h.Commitments{Kind: "r2_listing", Bucket: "synthetic", Manifest: hex.EncodeToString(m.SHA256[:]), Objects: map[string]h.Object{m.Identity: o}}
	facts, e := v.Scan(context.Background(), h.Memory{Member: m, Data: data}, h.Policy(c))
	if e != nil {
		return `{"error":"` + e.Error() + `"}`
	}
	digest, e := h.Digest(facts)
	if e != nil {
		return `{"error":"canonicalization"}`
	}
	return `{"facts_sha256":"` + digest + `"}`
}
func main() { run() }
