package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aidotmarket/aim-data-gateway/internal/config"
	"github.com/aidotmarket/aim-data-gateway/internal/ids"
	"github.com/aidotmarket/aim-data-gateway/internal/inventory"
	"github.com/aidotmarket/aim-data-gateway/internal/ledger"
	"github.com/aidotmarket/aim-data-gateway/internal/pairing"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
)

func TestDefaultVersionIsPrerelease(t *testing.T) {
	if version != "0.0.0-dev" {
		t.Fatalf("source build version = %q, want 0.0.0-dev prerelease", version)
	}
}

func TestApproveCommand(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "data")
	os.Mkdir(source, 0700)
	configPath := filepath.Join(root, "gateway.toml")
	writeConfig := func(required bool) {
		value := "false"
		if required {
			value = "true"
		}
		if err := os.WriteFile(configPath, []byte("sources = [{name = 'data', path = '"+source+"'}]\noffer_requires_local_approval = "+value+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig(true)
	public, _, _ := ed25519.GenerateKey(nil)
	key := base64.RawURLEncoding.EncodeToString(public)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(pairing.Pins{GatewayID: "11111111-1111-4111-8111-111111111111", PermissionKeys: []wire.Key{{KID: "permission", Alg: "EdDSA", Key: key}}, ListingKeys: []wire.Key{{KID: "listing", Alg: "EdDSA", Key: key}}, MinimumVersion: "1.0.0", CanaryHost: "canary.test", CanaryZone: "test"})
	}))
	defer srv.Close()
	stateDir := filepath.Join(root, "state")
	state, err := pairing.Pair(context.Background(), stateDir, "code", "1.0.0", srv.URL, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	l, err := ledger.Open(filepath.Join(stateDir, "gateway.db"), state.Private, "gateway")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	fid, sha, lvid := strings.Repeat("a", 32), strings.Repeat("b", 64), "listing-1"
	_, err = l.DB.Exec(`INSERT INTO files(fid,relative_path) VALUES(?,?)`, fid, "sample.csv")
	if err != nil {
		t.Fatal(err)
	}
	if err = l.PutOffer(context.Background(), ledger.Offer{FileID: fid, SHA256: sha, ListingVersionID: lvid, State: "offered", KeyClass: "listing"}); err != nil {
		t.Fatal(err)
	}
	_, err = l.DB.Exec(`INSERT INTO permissions(jti,oid,fid,sha256,sd,td,ro,state) VALUES('active','order',?,?,1,9999999999,0,'bound')`, fid, sha)
	if err != nil {
		t.Fatal(err)
	}
	_, err = l.DB.Exec(`INSERT INTO requests(jti,start,end,written_through,open,isolated) VALUES('active',0,0,-1,1,0)`)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AIM_GATEWAY_CONFIG", configPath)
	t.Setenv("AIM_GATEWAY_STATE", stateDir)
	if err = execute([]string{"approve", fid}); err != nil {
		t.Fatal(err)
	}
	var open int
	if err = l.DB.QueryRow(`SELECT open FROM requests WHERE jti='active'`).Scan(&open); err != nil || open != 1 {
		t.Fatalf("approval settled live request: %d %v", open, err)
	}
	o, err := l.Offer(context.Background(), fid, sha, lvid)
	if err != nil || !o.ApprovedAt.Valid {
		t.Fatalf("offer: %+v %v", o, err)
	}
	if err = execute([]string{"approve", fid}); err == nil {
		t.Fatal("accepted no pending offers")
	}
	if err = l.PutOffer(context.Background(), ledger.Offer{FileID: fid, SHA256: sha, ListingVersionID: lvid, State: "withdrawn", KeyClass: "listing"}); err != nil {
		t.Fatal(err)
	}
	if err = execute([]string{"approve", fid}); err == nil {
		t.Fatal("approved withdrawn offer")
	}
	writeConfig(false)
	if err = execute([]string{"approve", fid}); err != nil {
		t.Fatal(err)
	}
	o, err = l.Offer(context.Background(), fid, sha, lvid)
	if err != nil || o.State != "withdrawn" {
		t.Fatalf("approval-off wrote: %+v %v", o, err)
	}
}

func TestPreviewAfterPairingUsesStateSecret(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "data.csv"), []byte("value,label\n1,a\n"), 0600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "gateway.toml")
	if err := os.WriteFile(configPath, []byte("sources = [{name = 'one', path = '"+source+"'}]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	public, _, _ := ed25519.GenerateKey(nil)
	key := base64.RawURLEncoding.EncodeToString(public)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(pairing.Pins{GatewayID: "11111111-1111-4111-8111-111111111111", PermissionKeys: []wire.Key{{KID: "permission", Alg: "EdDSA", Key: key}}, ListingKeys: []wire.Key{{KID: "listing", Alg: "EdDSA", Key: key}}, MinimumVersion: "1.0.0", CanaryHost: "canary.test", CanaryZone: "test"})
	}))
	defer srv.Close()
	stateDir := filepath.Join(dir, "state")
	state, err := pairing.Pair(context.Background(), stateDir, "code", "1.0.0", srv.URL, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pairing.Load(stateDir); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AIM_GATEWAY_STATE", stateDir)
	t.Setenv("AIM_GATEWAY_SECRET", "")
	t.Setenv("AIM_GATEWAY_CONFIG", configPath)
	c, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := ids.Derive(state.Secret)
	if err != nil {
		t.Fatal(err)
	}
	records, err := inventory.Scan(c, keys)
	if err != nil || len(records) != 1 {
		t.Fatalf("scan: %v %d", err, len(records))
	}
	if err = execute([]string{"preview", records[0].Phase1.FileID}); err != nil {
		t.Fatal(err)
	}
}

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
	if e := execute([]string{"run"}); e == nil {
		t.Fatal("unpaired run started")
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
