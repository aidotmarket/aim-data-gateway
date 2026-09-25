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
	if _, e := l.Append("hello", map[string]any{"gid": "test"}); e == nil {
		t.Fatal("hello entered audit log")
	}
	first, e := l.Append("inventory", map[string]any{"generation": 0})
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
	if got, err := l.Read(1); err != nil || got.Seq != 1 {
		t.Fatalf("first rotation: %+v %v", got, err)
	}
	if got, err := l.Read(2); err != nil || got.Seq != 2 {
		t.Fatalf("second rotation: %+v %v", got, err)
	}
	if reopened, e := Open(dir, key); e != nil {
		t.Fatal(e)
	} else if got, err := reopened.Read(1); err != nil || got.Seq != 1 {
		t.Fatalf("reopened rotation: %+v %v", got, err)
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

func TestIndexedTailAvoidsHistoryReads(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	dir := t.TempDir()
	l, err := Open(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 200; n++ {
		if _, err := l.Append("inventory", map[string]int{"generation": n}); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(filepath.Join(dir, "000000.jsonl")); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 100; n++ {
		if l.Sequence() != 200 {
			t.Fatal("lost tail")
		}
		entry, err := l.Read(200)
		if err != nil || entry.Seq != 200 {
			t.Fatalf("tail: %+v %v", entry, err)
		}
	}
}
