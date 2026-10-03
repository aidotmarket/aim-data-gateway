package verification

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/aidotmarket/aim-data-gateway/internal/ledger"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
)

type LocalAudit struct {
	mu     sync.Mutex
	path   string
	key    ed25519.PrivateKey
	last   int64
	hash   string
	Sync   func(*os.File) error
	failed error
}

func OpenLocalAudit(dir string, key ed25519.PrivateKey) (*LocalAudit, error) {
	a := &LocalAudit{path: filepath.Join(dir, "verification-audit.jsonl"), key: key, Sync: (*os.File).Sync}
	f, e := os.OpenFile(a.path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	defer f.Close()

	reader := bufio.NewReaderSize(f, 16384)
	var offset int64
	for {
		line, readErr := reader.ReadSlice('\n')
		if readErr == io.EOF && len(line) == 0 {
			break
		}
		if readErr == io.EOF {
			// Preserve a torn final append, then reconstruct its durable event by ID.
			if e = atomicFile(dir, "verification-audit.torn", line); e != nil {
				return nil, e
			}
			if e = f.Truncate(offset); e != nil {
				return nil, e
			}
			break
		}
		if readErr != nil {
			return nil, errors.New("verification_audit_invalid")
		}
		offset += int64(len(line))
		raw := line[:len(line)-1]
		var v map[string]any
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		if e = d.Decode(&v); e != nil {
			return nil, e
		}
		canon, e := wire.Canonical(v)
		if e != nil || !bytes.Equal(raw, canon) {
			return nil, errors.New("verification_audit_invalid")
		}
		sig, _ := v["sig"].(string)
		prev, _ := v["prev_hash"].(string)
		n, ok := v["event_id"].(json.Number)
		if !ok {
			return nil, errors.New("verification_audit_invalid")
		}
		id, e := n.Int64()
		if e != nil || id <= a.last || prev != a.hash || len(v) != 8 {
			return nil, errors.New("verification_audit_invalid")
		}
		delete(v, "sig")
		unsigned, e := wire.Canonical(v)
		s, err := hex.DecodeString(sig)
		if e != nil || err != nil || !ed25519.Verify(key.Public().(ed25519.PublicKey), unsigned, s) {
			return nil, errors.New("verification_audit_invalid")
		}
		a.last = id
		h := sha256.Sum256(raw)
		a.hash = hex.EncodeToString(h[:])
	}
	if e = f.Sync(); e != nil {
		return nil, e
	}
	d, e := os.Open(dir)
	if e != nil {
		return nil, e
	}
	defer d.Close()
	if e = d.Sync(); e != nil {
		return nil, e
	}
	return a, nil
}
func (a *LocalAudit) Mirror(ctx context.Context, l *ledger.Ledger) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failed != nil {
		return a.failed
	}
	events, e := l.VerificationEvents(ctx, a.last)
	if e != nil {
		return e
	}
	for _, v := range events {
		body := map[string]any{"event_id": v.ID, "time": v.Time, "spec_hash": v.SpecHash, "spec_id": v.SpecID, "result": v.Result, "refusal_code": v.RefusalCode, "prev_hash": a.hash}
		raw, e := wire.Canonical(body)
		if e != nil {
			return e
		}
		body["sig"] = hex.EncodeToString(ed25519.Sign(a.key, raw))
		raw, e = wire.Canonical(body)
		if e != nil {
			return e
		}
		f, e := os.OpenFile(a.path, os.O_APPEND|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		_, e = f.Write(append(raw, '\n'))
		if e == nil {
			e = a.Sync(f)
		}
		ce := f.Close()
		if e == nil {
			e = ce
		}
		if e != nil {
			a.failed = e
			return e
		}
		a.last = v.ID
		h := sha256.Sum256(raw)
		a.hash = hex.EncodeToString(h[:])
	}
	return nil
}
