package audit

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTornTailRecovery(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	dir := t.TempDir()
	l, err := Open(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	first, err := l.Append("inventory", map[string]int{"generation": 1})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "000000.jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte(`{"seq":2,"body":`))
	f.Close()
	recovered, err := Open(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	fragments, err := filepath.Glob(filepath.Join(dir, "torn-*.fragment"))
	if err != nil || len(fragments) != 1 {
		t.Fatalf("fragments: %v %v", fragments, err)
	}
	b, err := os.ReadFile(fragments[0])
	if err != nil || string(b) != `{"seq":2,"body":` {
		t.Fatalf("fragment: %q %v", b, err)
	}
	second, err := recovered.Append("inventory", map[string]int{"generation": 2})
	if err != nil || second.Seq != 2 {
		t.Fatalf("next: %+v %v", second, err)
	}
	hash, err := Hash(first)
	if err != nil || second.PrevHash != hash {
		t.Fatalf("chain: %+v %v", second, err)
	}
}

func TestInvalidAuditLinesFailClosed(t *testing.T) {
	for _, middle := range []bool{false, true} {
		key := ed25519.NewKeyFromSeed(make([]byte, 32))
		dir := t.TempDir()
		l, err := Open(dir, key)
		if err != nil {
			t.Fatal(err)
		}
		l.Append("inventory", map[string]int{"generation": 1})
		path := filepath.Join(dir, "000000.jsonl")
		if middle {
			b, _ := os.ReadFile(path)
			os.WriteFile(path, append([]byte("bad\n"), b...), 0600)
		} else {
			f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
			f.Write([]byte("bad\n"))
			f.Close()
		}
		if _, err = Open(dir, key); err == nil {
			t.Fatal("accepted bad terminated line")
		}
	}
}

func TestStartupSyncGatesRestart(t *testing.T) {
	for _, rotate := range []bool{false, true} {
		name := "first"
		if rotate {
			name = "rotation"
		}
		t.Run(name, func(t *testing.T) {
			key := ed25519.NewKeyFromSeed(make([]byte, 32))
			dir := filepath.Join(t.TempDir(), "audit")
			l, err := Open(dir, key)
			if err != nil {
				t.Fatal(err)
			}
			if rotate {
				if _, err = l.Append("inventory", map[string]int{"generation": 1}); err != nil {
					t.Fatal(err)
				}
				if _, err = l.Append("inventory", map[string]int{"generation": 2}); err != nil {
					t.Fatal(err)
				}
				l.size = RotationBytes - 1
			}
			l.syncDir = func(path string) error {
				if path != dir {
					t.Fatalf("synced %s", path)
				}
				return errors.New("directory sync failed")
			}
			if _, err = l.Append("inventory", map[string]int{"generation": 3}); err == nil {
				t.Fatal("append reported durable before directory sync")
			}
			if _, err = l.Append("inventory", map[string]int{"generation": 4}); err == nil {
				t.Fatal("uncertain log accepted another append")
			}

			for _, failedSync := range []string{"file", "audit directory", "parent directory"} {
				var synced []string
				fileSync := func(f *os.File) error {
					synced = append(synced, "file")
					if failedSync == "file" {
						return errors.New("file sync failed")
					}
					return f.Sync()
				}
				dirSync := func(path string) error {
					part := "parent directory"
					if path == dir {
						part = "audit directory"
					}
					synced = append(synced, part)
					if failedSync == part {
						return errors.New(part + " sync failed")
					}
					return syncDirectory(path)
				}
				if reopened, err := openWithSync(dir, key, fileSync, dirSync); err == nil || reopened != nil {
					t.Fatalf("restart accepted failed %s sync", failedSync)
				}
				if len(synced) == 0 || synced[len(synced)-1] != failedSync {
					t.Fatalf("sync order before %s failure: %v", failedSync, synced)
				}
			}
			var synced []string
			reopened, err := openWithSync(dir, key, func(f *os.File) error {
				synced = append(synced, "file")
				return f.Sync()
			}, func(path string) error {
				if path == dir {
					synced = append(synced, "audit directory")
				} else {
					synced = append(synced, "parent directory")
				}
				return syncDirectory(path)
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(synced) < 3 || synced[len(synced)-2] != "audit directory" || synced[len(synced)-1] != "parent directory" {
				t.Fatalf("startup barrier order: %v", synced)
			}
			if _, err := reopened.Append("inventory", map[string]int{"generation": 4}); err != nil {
				t.Fatalf("append after durable restart: %v", err)
			}
		})
	}
}

func TestStartupSyncsEmptyAuditDirectoryAndParent(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	dir := filepath.Join(t.TempDir(), "audit")
	for _, failedPath := range []string{dir, filepath.Dir(dir)} {
		if l, err := openWithSync(dir, key, (*os.File).Sync, func(path string) error {
			if path == failedPath {
				return errors.New("directory sync failed")
			}
			return syncDirectory(path)
		}); err == nil || l != nil {
			t.Fatalf("accepted unsynced directory %s", failedPath)
		}
	}
	if _, err := Open(dir, key); err != nil {
		t.Fatalf("restart did not recover directory creation: %v", err)
	}
}

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
