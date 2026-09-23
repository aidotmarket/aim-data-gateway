package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aidotmarket/aim-data-gateway/internal/config"
	"github.com/aidotmarket/aim-data-gateway/internal/ids"
	"github.com/aidotmarket/aim-data-gateway/internal/inventory"
)

func TestRunAndPreview(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "sources")
	os.Mkdir(source, 0700)
	os.WriteFile(filepath.Join(source, "PRIVATE_FILENAME.csv"), []byte("safe,secret\n1,PRIVATE_VALUE\n"), 0600)
	configPath := filepath.Join(root, "gateway.toml")
	os.WriteFile(configPath, []byte("sources = [{name = 'one', path = '"+source+"'}]\n[columns.\"PRIVATE_FILENAME.csv\"]\ndrop = ['secret']\n"), 0600)
	secretPath := filepath.Join(root, "secret.bin")
	os.WriteFile(secretPath, make([]byte, 32), 0600)
	t.Setenv("AIM_GATEWAY_CONFIG", configPath)
	t.Setenv("AIM_GATEWAY_SECRET", secretPath)
	if e := execute([]string{"run"}); e != nil {
		t.Fatal(e)
	}
	c, e := config.Load(configPath)
	if e != nil {
		t.Fatal(e)
	}
	keys, _ := ids.Derive(make([]byte, 32))
	records, e := inventory.Scan(c, keys)
	if e != nil {
		t.Fatal(e)
	}
	old := os.Stdout
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	e = execute([]string{"preview", records[0].Phase1.FileID})
	w.Close()
	os.Stdout = old
	if e != nil {
		t.Fatal(e)
	}
	output, e := io.ReadAll(r)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(output), "PRIVATE_FILENAME") || strings.Contains(string(output), "PRIVATE_VALUE") || strings.Contains(string(output), "secret") {
		t.Fatal("preview leaked configured private fields")
	}
	var payload map[string]json.RawMessage
	if e = json.Unmarshal(output, &payload); e != nil {
		t.Fatal(e)
	}
	if len(payload) != 2 {
		t.Fatal(payload)
	}
}
