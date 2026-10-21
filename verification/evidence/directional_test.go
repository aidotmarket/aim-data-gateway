//go:build evidence

package evidence

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/wire"
)

// Verify the backend's committed issuance vectors without constructing or
// re-signing the tokens in Go. The backend signer test reproduces these tokens
// through its real _sign path with test-only KMS.
func TestE1DirectionalBackendSpecs(t *testing.T) {
	const backend = "/var/tmp/cp81-backend-0f7b61ff"
	sha, err := exec.Command("rtk", "proxy", "git", "-C", backend, "rev-parse", "HEAD").Output()
	must(t, err)
	if strings.TrimSpace(string(sha)) != "0f7b61ff58463a1bd1fe40f89d824059d1bb2bc3" {
		t.Fatalf("incorrect backend checkout: %s", sha)
	}
	results := []map[string]any{}
	for _, name := range []string{"scan_spec", "probe_spec"} {
		path := filepath.Join(backend, "tests/contract/gateway/verification", name+".json")
		var v struct {
			Token  string `json:"token"`
			Public string `json:"test_only_public_hex"`
			Input  struct {
				Audience string `json:"aud"`
				Runner   string `json:"runner_id"`
				Issued   int64  `json:"iat"`
			} `json:"input"`
		}
		must(t, json.Unmarshal(read(t, path), &v))
		pub, err := hex.DecodeString(v.Public)
		must(t, err)
		var header struct {
			Kid string `json:"kid"`
		}
		// Decode only the header to select the vector's public pin.
		segment := strings.Split(v.Token, ".")[0]
		raw, err := base64.RawURLEncoding.DecodeString(segment)
		must(t, err)
		must(t, json.Unmarshal(raw, &header))
		_, err = wire.VerifyScan(v.Token, map[string]ed25519.PublicKey{header.Kid: pub}, v.Input.Audience, v.Input.Runner, "1.2.3", time.Unix(v.Input.Issued, 0).UTC())
		r := map[string]any{"path": path, "sha256": wire.Digest(read(t, path)), "accept": err == nil, "validator": "wire.VerifyScan", "at": time.Unix(v.Input.Issued, 0).UTC()}
		if err != nil {
			r["error"] = err.Error()
			t.Errorf("backend %s rejected: %v", name, err)
		}
		results = append(results, r)
	}
	writeJSON(t, filepath.Join(conformanceDir, "directional-go.json"), map[string]any{"backend_actual": "0f7b61ff58463a1bd1fe40f89d824059d1bb2bc3", "results": results})
	t.Logf("backend committed scan/probe specs: %d verified", len(results))
}
