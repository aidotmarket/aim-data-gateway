package cloudflareverification

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	core "github.com/aidotmarket/aim-data-gateway/verification"
)

func TestDeploymentConfigPythonCanonical(t *testing.T) {
	raw, err := os.ReadFile("../../contract/vectors/verification/deployment_config/unicode.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Config        Config `json:"deployment_config"`
		Hash          string `json:"deployment_config_sha256"`
		Bootstrap     Config `json:"bootstrap_config"`
		BootstrapHash string `json:"bootstrap_sha256"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		config Config
		hash   string
	}{{vector.Config, vector.Hash}, {vector.Bootstrap, vector.BootstrapHash}} {
		// Validate already uses this codec after removing transport-only fields.
		scope := test.config
		scope.Token, scope.ConfigHash = "", ""
		encoded, err := core.Canonical(scope)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(encoded)
		if got := hex.EncodeToString(digest[:]); got != test.hash {
			t.Fatalf("deployment config hash: got %s, want %s", got, test.hash)
		}
	}
	if err := vector.Bootstrap.Validate(); err != nil {
		t.Fatal(err)
	}
}
