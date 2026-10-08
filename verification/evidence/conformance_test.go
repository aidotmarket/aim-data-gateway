//go:build evidence

package evidence

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aidotmarket/aim-data-gateway/internal/wire"
)

const cp81Authority = "5d8267dc"
const conformanceDir = "/Users/max/koskadeux-state/s1791/cp81/conformance"
const keyflowDir = "/Users/max/koskadeux-state/s1791/cp81/keyflow"

// This exercises the existing receiving boundary, without adding a validator.
// Report/probe payloads currently receive canonical JSON validation only in Go.
// The Python comparison must expose that gap rather than hide it with a copy
// of Pydantic's constraints implemented in the evidence package.
func TestE1Conformance(t *testing.T) {
	var corpus struct {
		Cases []struct {
			ID    string          `json:"id"`
			Class string          `json:"cls"`
			Input json.RawMessage `json:"input"`
		} `json:"cases"`
	}
	must(t, json.Unmarshal(read(t, filepath.Join(conformanceDir, "corpus.json")), &corpus))
	results := []map[string]any{}
	for _, c := range corpus.Cases {
		var v any
		decoder := json.NewDecoder(bytes.NewReader(c.Input))
		decoder.UseNumber()
		must(t, decoder.Decode(&v))
		raw := canonical(t, v)
		var err error
		validator := "wire.ValidateScanReportBody (canonical decoded document only)"
		switch c.Class {
		case "scan_spec":
			validator = "wire.VerifyScan (fresh test signature over corpus payload)"
			vec := vector(t, "scan_spec")
			in := vec["input"].(map[string]any)
			in["iat"] = int64(in["iat"].(float64))
			in["payload_b64"] = base64.RawURLEncoding.EncodeToString(raw)
			in["spec_hash"] = wire.Digest(raw)
			seed, e := hex.DecodeString(vec["test_only_seed_hex"].(string))
			must(t, e)
			priv := ed25519.NewKeyFromSeed(seed)
			header := canonical(t, map[string]any{"alg": "EdDSA", "typ": "aim-scan-spec+jwt", "kid": "test-only-scan-key"})
			signed := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(canonical(t, in))
			token := signed + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(signed)))
			_, err = wire.VerifyScan(token, map[string]ed25519.PublicKey{"test-only-scan-key": priv.Public().(ed25519.PublicKey)}, in["aud"].(string), in["runner_id"].(string), "1.2.3", at)
		case "registration":
			validator = "wire.ValidateScanReportBody (registration)"
			err = wire.ValidateScanReportBody(raw)
		case "quote_probe":
			// No standalone QuoteProbeRequest Go validator exists. Exercise the real
			// probe transport document boundary with this request inside its document.
			doc := vector(t, "probe_report")["input"].(map[string]any)
			doc["probe"] = v
			err = reportBoundary(t, "probe", canonical(t, doc))
		default:
			variant := map[string]string{"scan_report": "scan", "terminal_report": "terminal", "probe_report": "probe"}[c.Class]
			err = reportBoundary(t, variant, raw)
		}
		if strings.HasSuffix(c.ID, "/baseline") && err != nil {
			t.Errorf("committed baseline rejected: %s: %v", c.ID, err)
		}
		r := map[string]any{"id": c.ID, "accept": err == nil, "validator": validator}
		if err == nil {
			r["sha256"] = wire.Digest(raw)
		} else {
			r["error"] = err.Error()
		}
		results = append(results, r)
	}
	writeJSON(t, filepath.Join(conformanceDir, "go-results.json"), map[string]any{"authority": cp81Authority, "gateway_base": "7fcbd770c7ffb7e21284e28767eeafedfe878c23", "results": results})
	t.Logf("E1 recorded %d cases; compare with run_python.py; acceptance differences are evidence, not test failures", len(results))
}

func reportBoundary(t *testing.T, variant string, raw []byte) error {
	return wire.ValidateScanReportBody(canonical(t, map[string]any{"op": "scan_report", "variant": variant, "runner_id": "66666666-6666-4666-8666-666666666666", "iid": "88888888-8888-4888-8888-888888888888", "document_b64": base64.RawURLEncoding.EncodeToString(raw)}))
}
