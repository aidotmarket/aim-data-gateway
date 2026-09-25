package pairing

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/aidotmarket/aim-data-gateway/internal/wire"
)

func TestPairSingleUse(t *testing.T) {
	public, _, _ := ed25519.GenerateKey(nil)
	called := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		var body map[string]string
		if r.URL.Path != "/api/v1/gateway-channel/pair" || r.Method != "POST" || json.NewDecoder(r.Body).Decode(&body) != nil || body["code"] != "ABCD-EFGH-IJKL" || body["version"] != "1.0.0" {
			t.Error("invalid pair request")
		}
		b, err := hex.DecodeString(body["gateway_public_key"])
		if err != nil || len(b) != ed25519.PublicKeySize {
			t.Error("invalid public key")
		}
		key := base64.RawURLEncoding.EncodeToString(public)
		_ = json.NewEncoder(w).Encode(Pins{GatewayID: "11111111-1111-4111-8111-111111111111", PermissionKeys: []wire.Key{{KID: "permission", Alg: "EdDSA", Key: key}}, ListingKeys: []wire.Key{{KID: "listing", Alg: "EdDSA", Key: key}}, MinimumVersion: "1.0.0", CanaryHost: "canary.test", CanaryZone: "test"})
	}))
	defer srv.Close()
	dir := t.TempDir()
	state, err := Pair(context.Background(), dir, "ABCD-EFGH-IJKL", "1.0.0", srv.URL+"/api/v1/gateway-channel/pair", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Private) != ed25519.PrivateKeySize || len(state.Secret) != 32 {
		t.Fatal("incomplete state")
	}
	for _, name := range []string{"identity.key", "secret.bin", "pins.json"} {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0600 {
			t.Fatalf("%s mode %v", name, st.Mode())
		}
	}
	if _, err := Load(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := Pair(context.Background(), dir, "ABCD-EFGH-IJKL", "1.0.0", srv.URL, srv.Client()); err == nil {
		t.Fatal("paired volume accepted another code")
	}
	if called != 1 {
		t.Fatalf("pair called %d times", called)
	}
}
