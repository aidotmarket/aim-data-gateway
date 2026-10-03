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

func TestVerificationDefaultAndOptOut(t *testing.T) {
	source := t.TempDir()
	for _, v := range []struct {
		setting string
		want    bool
	}{{"", true}, {"verification_enabled = false\n", false}} {
		path := filepath.Join(t.TempDir(), "gateway.toml")
		text := v.setting + "[[sources]]\nname = \"data\"\npath = \"" + source + "\"\n"
		if e := os.WriteFile(path, []byte(text), 0600); e != nil {
			t.Fatal(e)
		}
		cfg, e := Load(path)
		if e != nil || cfg.VerificationEnabled != v.want {
			t.Fatal(cfg, e)
		}
	}
}
