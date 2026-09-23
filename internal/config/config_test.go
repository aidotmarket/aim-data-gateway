package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStrictConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.toml")
	body := "sources = [{name = 'a', path = '" + dir + "'}]\n[door]\nlisten = ':8080'\n"
	if e := os.WriteFile(path, []byte(body), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := Load(path); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, []byte(body+"tls_cert = 'bad'\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := Load(path); e == nil {
		t.Fatal("accepted TLS field")
	}
}
