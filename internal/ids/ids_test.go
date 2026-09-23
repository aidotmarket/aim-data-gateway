package ids

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestDerivationAndNames(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	k, e := Derive(secret)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := Derive(secret[:31]); e == nil {
		t.Fatal("accepted short secret")
	}
	a := FileID(k, "one", "nested/data.csv")
	b := FileID(k, "two", "nested/data.csv")
	if a == b || len(a) != 32 {
		t.Fatal(a, b)
	}
	m := hmac.New(sha256.New, k.ID[:])
	m.Write([]byte("one\x00nested/data.csv"))
	if a != hex.EncodeToString(m.Sum(nil))[:32] {
		t.Fatal("file id mismatch")
	}
	h := sha256.Sum256([]byte("data"))
	if len(ContentCommitment(k, h)) != 64 {
		t.Fatal("commitment length")
	}
	if got := DisplayName(a, "text/csv"); got != "file-"+a[:8]+".csv" {
		t.Fatal(got)
	}
}
