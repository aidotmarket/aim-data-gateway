package audit

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChainAcrossRotationAndTamper(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	dir := t.TempDir()
	l, e := Open(dir, key)
	if e != nil {
		t.Fatal(e)
	}
	first, e := l.Append("hello", map[string]any{"gid": "test"})
	if e != nil {
		t.Fatal(e)
	}
	l.size = RotationBytes - 1
	second, e := l.Append("inventory", map[string]any{"generation": 1})
	if e != nil {
		t.Fatal(e)
	}
	if second.Seq != 2 || second.PrevHash == "" || first.PrevHash != "" {
		t.Fatal(first, second)
	}
	if _, e := Open(dir, key); e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(dir, "000001.jsonl")
	b, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	b = []byte(strings.Replace(string(b), "generation", "alteration", 1))
	if e := os.WriteFile(p, b, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := Open(dir, key); e == nil {
		t.Fatal("accepted tampered audit entry")
	}
}
