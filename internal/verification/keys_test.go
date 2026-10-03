package verification

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	core "github.com/aidotmarket/aim-data-gateway/verification"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIndependentDurableKeys(t *testing.T) {
	dir := t.TempDir()
	k, e := OpenKeys(dir, "1.2.3", "sha256:"+strings.Repeat("a", 64))
	if e != nil {
		t.Fatal(e)
	}
	k2, e := OpenKeys(dir, "1.2.3", "sha256:"+strings.Repeat("a", 64))
	if e != nil || !bytes.Equal(k.Private, k2.Private) || k.Commitment != k2.Commitment {
		t.Fatal("key drift", e)
	}
	if bytes.Equal(k.Private[:32], k.Commitment[:]) {
		t.Fatal("derived commitment")
	}
	for _, name := range []string{"verification-receipt.key", "verification-commitment.key", "verification-registration.json"} {
		st, e := os.Stat(filepath.Join(dir, name))
		if e != nil || st.Mode().Perm() != 0600 {
			t.Fatal("permissions", name, e)
		}
	}
	os.Remove(filepath.Join(dir, "verification-receipt.key"))
	if _, e := OpenKeys(dir, "1.2.3", "sha256:"+strings.Repeat("a", 64)); e == nil {
		t.Fatal("lost key regenerated")
	}
}
func TestRegistrationProofAndAck(t *testing.T) {
	f := newRunner(t)
	f.r.Keys.Binding.RunnerID = ""
	body, e := f.r.Keys.Registration(f.r.GatewayID, f.at)
	if e != nil {
		t.Fatal(e)
	}
	proof, _ := base64.RawURLEncoding.DecodeString(body["key_proof"].(string))
	delete(body, "key_proof")
	raw, _ := core.Canonical(body)
	if !ed25519.Verify(f.r.Keys.Private.Public().(ed25519.PublicKey), raw, proof) {
		t.Fatal("proof")
	}
	v := loadVector(t, "runner_ack")
	v.Input["registration_nonce"] = f.r.Keys.Binding.RegistrationNonce
	v.Input["scanner_version"] = f.r.Keys.Binding.ScannerVersion
	v.Input["image_digest"] = f.r.Keys.Binding.ImageDigest
	token, e := wire.Sign("aim-scan-runner-ack+jwt", "test-only-scan-key", v.Input, f.key)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.r.Keys.Acknowledge(token, f.r.GatewayID, f.r.Pins(), f.at); e != nil {
		t.Fatal(e)
	}
	binding := f.r.Keys.Snapshot()
	if binding.RunnerID == "" || binding.ReceiptKeyID == "" {
		t.Fatal("not bound")
	}
	k, e := LoadPreviewKeys(f.dir)
	if e != nil || k.Binding.RunnerID != binding.RunnerID {
		t.Fatal("binding not durable", e)
	}
	v.Input["receipt_key_id"] = "99999999-9999-4999-8999-999999999999"
	token, _ = wire.Sign("aim-scan-runner-ack+jwt", "test-only-scan-key", v.Input, f.key)
	if e = f.r.Keys.Acknowledge(token, f.r.GatewayID, f.r.Pins(), f.at); e == nil {
		t.Fatal("replacement without rotation")
	}
	b, _ := json.Marshal(binding)
	if bytes.Contains(b, f.r.Keys.Private[:32]) {
		t.Fatal("private key leak")
	}
}
