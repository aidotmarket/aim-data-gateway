package wire

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

func TestJWSAndInstructionKinds(t *testing.T) {
	private := ed25519.NewKeyFromSeed(make([]byte, 32))
	keys := map[string]ed25519.PublicKey{"kid": private.Public().(ed25519.PublicKey)}
	for _, op := range []string{"offer", "unoffer", "describe", "revoke", "prepare", "key_rotation", "minimum_version"} {
		in := Instruction{Op: op, Audience: "gateway", IID: "iid", IssuedAt: 1}
		typ, _, e := in.Kind()
		if e != nil {
			t.Fatal(e)
		}
		token, e := Sign(typ, "kid", in, private)
		if e != nil {
			t.Fatal(e)
		}
		var out Instruction
		if e := Verify(token, typ, keys, &out); e != nil || out.Op != op {
			t.Fatal(op, e)
		}
		if e := Verify(token, "wrong", keys, &out); e == nil {
			t.Fatal("wrong type accepted")
		}
		parts := strings.Split(token, ".")
		parts[1] = "AA"
		if e := Verify(strings.Join(parts, "."), typ, keys, &out); e == nil {
			t.Fatal("tamper accepted")
		}
	}
}
func TestCanonical(t *testing.T) {
	b, e := Canonical(map[string]any{"z": 1, "a": map[string]any{"b": 2, "a": 1}})
	if e != nil {
		t.Fatal(e)
	}
	if string(b) != "{\"a\":{\"a\":1,\"b\":2},\"z\":1}" {
		t.Fatal(string(b))
	}
}
