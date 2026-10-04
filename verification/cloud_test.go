package verification

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

type opaqueCommitments struct{}

func (opaqueCommitments) LocatorCommitment() string { return strings.Repeat("a", 64) }
func (opaqueCommitments) ObjectID(m Member) string {
	h := sha256.Sum256(append([]byte(m.Identity), m.SHA256[:]...))
	return hex.EncodeToString(h[:])
}

func TestCloudScannerOpaqueContract(t *testing.T) {
	p := testPolicy()
	p.Commitments = opaqueCommitments{}
	data := []byte("n\n" + strings.Repeat("12\n", 20))
	for _, id := range []string{"e\u0301.csv\x00pin", "é.csv\x00pin", "\xff\x00opaque-pin"} {
		src := sourceFor(data, "csv")
		src.members[0].Identity = id
		src.members[0].OrderingKey = []byte(id)
		src.members[0].SHA256 = [32]byte{}
		src.data = map[string][]byte{id: data}
		facts, e := Scan(context.Background(), src, p)
		if e != nil || len(facts.Objects) != 1 || src.opens[id] != 2 {
			t.Fatal("opaque identity/no extra traversal", id, e)
		}
	}
	for _, mode := range []string{"empty", "mismatch", "missing_strategy", "duplicate", "wrong_order", "gateway_digest"} {
		t.Run(mode, func(t *testing.T) {
			src := sourceFor(data, "csv")
			local := p
			id := "key\x00pin"
			src.members[0].Identity = id
			src.members[0].OrderingKey = []byte(id)
			src.data = map[string][]byte{id: data}
			switch mode {
			case "empty":
				src.members[0].Identity = ""
				src.members[0].OrderingKey = []byte{}
			case "mismatch":
				src.members[0].OrderingKey = []byte("different")
			case "missing_strategy":
				local.Commitments = nil
			case "duplicate":
				src.members = append(src.members, src.members[0])
			case "wrong_order":
				m := src.members[0]
				m.Identity = "a\x00pin"
				m.OrderingKey = []byte(m.Identity)
				src.members = append(src.members, m)
			case "gateway_digest":
				src = sourceFor(data, "csv")
				src.members[0].SHA256 = [32]byte{}
				local = testPolicy()
			}
			if facts, e := Scan(context.Background(), src, local); e != ErrArtifactChanged || len(facts.Objects) != 0 {
				t.Fatal("contract refusal", e)
			}
		})
	}
}
