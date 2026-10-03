package verification

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	core "github.com/aidotmarket/aim-data-gateway/verification"
)

type Binding struct {
	RunnerID          string `json:"runner_id"`
	ReceiptKeyID      string `json:"receipt_key_id"`
	RegistrationNonce string `json:"registration_nonce"`
	ScannerVersion    string `json:"scanner_version"`
	ImageDigest       string `json:"image_digest"`
	Ack               string `json:"ack"`
}
type Keys struct {
	Private    ed25519.PrivateKey
	Commitment [32]byte
	Binding    Binding
	dir        string
	mu         sync.Mutex
}

func atomicFile(dir, name string, data []byte) error {
	f, e := os.CreateTemp(dir, ".verification-")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(tmp, filepath.Join(dir, name)); e != nil {
		return e
	}
	d, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func random32() ([]byte, error) { b := make([]byte, 32); _, e := rand.Read(b); return b, e }
func OpenKeys(dir, version, digest string) (*Keys, error) {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	lock, e := os.OpenFile(filepath.Join(dir, "verification-keys.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	defer lock.Close()
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); e != nil {
		return nil, e
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	k := &Keys{dir: dir}
	raw, e := os.ReadFile(filepath.Join(dir, "verification-receipt.key"))
	if os.IsNotExist(e) {
		// Partial initialization or lost keys fail closed. Never reset consent identity.
		for _, name := range []string{"verification-commitment.key", "verification-binding.json", "verification-registration.json"} {
			if _, e := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(e) {
				return nil, errors.New("verification_key_missing")
			}
		}
		seed, e := random32()
		if e != nil {
			return nil, e
		}
		raw = ed25519.NewKeyFromSeed(seed)
		if e = atomicFile(dir, "verification-receipt.key", raw); e != nil {
			return nil, e
		}
		c, e := random32()
		if e != nil {
			return nil, e
		}
		if e = atomicFile(dir, "verification-commitment.key", c); e != nil {
			return nil, e
		}
	} else if e != nil {
		return nil, e
	}
	if len(raw) != 64 || !ed25519.NewKeyFromSeed(raw[:32]).Equal(ed25519.PrivateKey(raw)) {
		return nil, errors.New("verification_key_invalid")
	}
	k.Private = raw
	c, e := os.ReadFile(filepath.Join(dir, "verification-commitment.key"))
	if e != nil || len(c) != 32 {
		return nil, errors.New("verification_key_missing")
	}
	copy(k.Commitment[:], c)
	for _, name := range []string{"verification-receipt.key", "verification-commitment.key"} {
		st, e := os.Stat(filepath.Join(dir, name))
		if e != nil || st.Mode().Perm() != 0600 {
			return nil, errors.New("verification_key_permissions")
		}
	}
	b, e := os.ReadFile(filepath.Join(dir, "verification-binding.json"))
	if e == nil {
		if e = json.Unmarshal(b, &k.Binding); e != nil {
			return nil, e
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}

	if k.Binding.RegistrationNonce == "" || k.Binding.ScannerVersion != version || k.Binding.ImageDigest != digest {
		var pending Binding
		b, e = os.ReadFile(filepath.Join(dir, "verification-registration.json"))
		if e == nil {
			if e = json.Unmarshal(b, &pending); e != nil {
				return nil, e
			}
		} else if !os.IsNotExist(e) {
			return nil, e
		}
		if pending.RegistrationNonce == "" || pending.ScannerVersion != version || pending.ImageDigest != digest {
			nonce, e := random32()
			if e != nil {
				return nil, e
			}
			pending = Binding{RunnerID: k.Binding.RunnerID, ReceiptKeyID: k.Binding.ReceiptKeyID, RegistrationNonce: base64.RawURLEncoding.EncodeToString(nonce), ScannerVersion: version, ImageDigest: digest}
			b, e = json.Marshal(pending)
			if e != nil {
				return nil, e
			}
			if e = atomicFile(dir, "verification-registration.json", b); e != nil {
				return nil, e
			}
		}
		k.Binding = pending
	}

	return k, nil
}
func (k *Keys) Snapshot() Binding { k.mu.Lock(); defer k.mu.Unlock(); return k.Binding }
func (k *Keys) Registration(gateway string, at time.Time) (map[string]any, error) {
	b := k.Snapshot()
	body := map[string]any{"op": "scan_report", "variant": "register", "gateway_id": gateway, "scanner_version": b.ScannerVersion, "image_digest": b.ImageDigest, "receipt_public_key": base64.RawURLEncoding.EncodeToString(k.Private.Public().(ed25519.PublicKey)), "registration_nonce": b.RegistrationNonce, "registered_at_utc": timestamp(at)}
	raw, e := core.Canonical(body)
	if e != nil {
		return nil, e
	}
	body["key_proof"] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(k.Private, raw))
	return body, nil
}
func (k *Keys) Acknowledge(token, gateway string, pins map[string]ed25519.PublicKey, at time.Time) error {
	var a struct {
		Op       string `json:"op"`
		Variant  string `json:"variant"`
		Audience string `json:"aud"`
		IID      string `json:"iid"`
		Issued   int64  `json:"iat"`
		Nonce    string `json:"registration_nonce"`
		Runner   string `json:"runner_id"`
		Receipt  string `json:"receipt_key_id"`
		Version  string `json:"scanner_version"`
		Digest   string `json:"image_digest"`
	}
	_, e := wire.VerifyControl(token, "aim-scan-runner-ack+jwt", "op variant aud iid iat registration_nonce runner_id receipt_key_id scanner_version image_digest", pins, &a, 4096)
	if e != nil {
		return e
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	b := k.Binding
	if a.Op != "scan_spec" || a.Variant != "registered" || a.Audience != gateway || a.Nonce != b.RegistrationNonce || a.Version != b.ScannerVersion || a.Digest != b.ImageDigest || a.Issued < at.Unix()-300 || a.Issued > at.Unix()+300 || !uuidID(a.Runner) || !uuidID(a.Receipt) || !uuidID(a.IID) {
		return wire.ErrVerification
	}
	if b.RunnerID != "" && (b.RunnerID != a.Runner || b.ReceiptKeyID != a.Receipt) {
		return wire.ErrVerification
	}
	b.RunnerID, b.ReceiptKeyID, b.Ack = a.Runner, a.Receipt, token
	raw, e := json.Marshal(b)
	if e == nil {
		e = atomicFile(k.dir, "verification-binding.json", raw)
	}
	if e == nil {
		k.Binding = b
	}
	return e
}
func timestamp(t time.Time) string {
	t = t.UTC().Truncate(time.Microsecond)
	if t.Nanosecond() == 0 {
		return t.Format("2006-01-02T15:04:05Z")
	}
	return t.Format("2006-01-02T15:04:05.000000Z")
}

// LoadPreviewKeys only reads retained keys and binding. It never creates files.
func LoadPreviewKeys(dir string) (*Keys, error) {
	k := &Keys{dir: dir}
	raw, e := os.ReadFile(filepath.Join(dir, "verification-receipt.key"))
	if e != nil {
		return nil, e
	}
	if len(raw) != 64 {
		return nil, errors.New("verification_key_invalid")
	}
	k.Private = raw
	raw, e = os.ReadFile(filepath.Join(dir, "verification-commitment.key"))
	if e != nil || len(raw) != 32 {
		return nil, errors.New("verification_key_missing")
	}
	copy(k.Commitment[:], raw)
	raw, e = os.ReadFile(filepath.Join(dir, "verification-binding.json"))
	if e != nil {
		return nil, e
	}
	if e = json.Unmarshal(raw, &k.Binding); e != nil {
		return nil, e
	}
	return k, nil
}

// VerifyBinding checks retained acknowledgments at their signed registration time.
func (k *Keys) VerifyBinding(gateway string, pins map[string]ed25519.PublicKey) error {
	b := k.Snapshot()
	if b.Ack == "" {
		return wire.ErrVerification
	}
	parts := strings.Split(b.Ack, ".")
	if len(parts) != 3 {
		return wire.ErrVerification
	}
	raw, e := wire.DecodeDocument(parts[1], 4096)
	if e != nil {
		return e
	}
	var v struct {
		Issued int64 `json:"iat"`
	}
	if e = json.Unmarshal(raw, &v); e != nil {
		return e
	}
	return k.Acknowledge(b.Ack, gateway, pins, time.Unix(v.Issued, 0))
}
