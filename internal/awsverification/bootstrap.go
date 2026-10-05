package awsverification

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	core "github.com/aidotmarket/aim-data-gateway/verification"
)

type Pin struct {
	Key   wire.Key
	Until int64
}
type Secret struct {
	Private                                      ed25519.PrivateKey
	Commitment                                   [32]byte
	Runner, Receipt, Version, Digest, Connection string
	Registration                                 []byte
	Nonce, Ack                                   string
	Rotation                                     string
	Pins                                         []Pin
}
type SecretStore interface {
	Load(context.Context) (*Secret, error)
	Save(context.Context, *Secret) error
}
type RegistrationAck struct {
	Runner  string     `json:"runner_id"`
	Receipt string     `json:"receipt_key_id"`
	Keys    []wire.Key `json:"scan_spec_keys"`
	JWS     string     `json:"ack_jws"`
}

func timestamp(t time.Time) string {
	t = t.UTC().Truncate(time.Microsecond)
	if t.Nanosecond() == 0 {
		return t.Format("2006-01-02T15:04:05Z")
	}
	return t.Format("2006-01-02T15:04:05.000000Z")
}
func (s *Secret) keys(at time.Time) map[string]ed25519.PublicKey {
	m := map[string]ed25519.PublicKey{}
	for _, p := range s.Pins {
		if p.Until != 0 && p.Until < at.Unix() {
			continue
		}
		b, e := wire.DecodeDocument(p.Key.Key, 32)
		if e == nil && len(b) == 32 {
			m[p.Key.KID] = b
		}
	}
	return m
}
func (s *Secret) validate(c Config) error {
	if len(s.Private) != 64 || !ed25519.NewKeyFromSeed(s.Private[:32]).Equal(s.Private) || s.Commitment == [32]byte{} || s.Version != c.Version || s.Digest != c.Digest || s.Connection != c.Connection {
		return ErrRefused
	}
	if s.Runner != "" && (!uuid.MatchString(s.Runner) || !uuid.MatchString(s.Receipt) || s.Ack == "" || len(s.Pins) == 0) {
		return ErrRefused
	}
	return nil
}
func Bootstrap(ctx context.Context, c Config, l Ledger, store SecretStore, backend Backend, at time.Time) (*Secret, error) {
	s, e := store.Load(ctx)
	if e != nil {
		return nil, ErrRefused
	}
	if s == nil {
		if b, e := wire.DecodeDocument(c.Token, 32); e != nil || len(b) != 32 {
			return nil, ErrRefused
		}
		// A crashed lease with no persisted secret is ambiguous. Never replace keys.
		if e = l.put(ctx, "bootstrap", map[string]string{"state": "initializing"}, at, "attribute_not_exists(pk)"); e != nil {
			return nil, e
		}
		_, priv, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return nil, ErrRefused
		}
		s = &Secret{
			Private:    priv,
			Version:    c.Version,
			Digest:     c.Digest,
			Connection: c.Connection,
		}
		if _, e = rand.Read(s.Commitment[:]); e != nil {
			return nil, ErrRefused
		}
		s.Nonce, e = randomToken()
		if e != nil {
			return nil, ErrRefused
		}
		m := map[string]any{
			"registration_token": c.Token,
			"connection_id":      c.Connection,
			"kind":               "aws",
			"receipt_public_key": base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)),
			"scanner_version":    c.Version,
			"image_digest":       c.Digest,
			"registration_nonce": s.Nonce,
			"registered_at_utc":  timestamp(at),
		}
		b, e := core.Canonical(m)
		if e != nil {
			return nil, ErrRefused
		}
		m["key_proof"] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, b))
		s.Registration, e = core.Canonical(m)
		if e != nil {
			return nil, ErrRefused
		}
		if e = store.Save(ctx, s); e != nil {
			return nil, ErrRefused
		}
	} else {
		var lease map[string]string
		ok, e := l.get(ctx, "bootstrap", &lease)
		if e != nil || !ok || lease["state"] != "initializing" {
			return nil, ErrRefused
		}
	}
	if e = s.validate(c); e != nil {
		return nil, e
	}
	if s.Runner != "" {
		return s, nil
	}
	if len(s.Registration) == 0 {
		return nil, ErrRefused
	}
	a, e := backend.Register(ctx, s.Registration)
	if e != nil {
		return nil, ErrRefused
	}
	if !uuid.MatchString(a.Runner) || !uuid.MatchString(a.Receipt) || len(a.Keys) == 0 || wire.ValidateKeySet(a.Keys) != nil {
		return nil, ErrRefused
	}
	keys := map[string]ed25519.PublicKey{}
	for _, k := range a.Keys {
		b, _ := wire.DecodeDocument(k.Key, 32)
		keys[k.KID] = b
	}
	var ack struct {
		Op      string `json:"op"`
		Variant string `json:"variant"`
		Aud     string `json:"aud"`
		IID     string `json:"iid"`
		Issued  int64  `json:"iat"`
		Nonce   string `json:"registration_nonce"`
		Runner  string `json:"runner_id"`
		Receipt string `json:"receipt_key_id"`
		Version string `json:"scanner_version"`
		Digest  string `json:"image_digest"`
	}
	_, e = wire.VerifyControl(a.JWS, "aim-scan-runner-ack+jwt", "op variant aud iid iat registration_nonce runner_id receipt_key_id scanner_version image_digest", keys, &ack, 4096)
	// Exact retry may return an old stored acknowledgment. Bind its issuance to
	// the durable original request, rather than making lost replies unrecoverable.
	var request struct {
		At string `json:"registered_at_utc"`
	}
	if json.Unmarshal(s.Registration, &request) != nil {
		return nil, ErrRefused
	}
	issued, e2 := utc(request.At)
	if e != nil || e2 != nil || ack.Op != "scan_spec" || ack.Variant != "registered" || ack.Aud != a.Runner || ack.Runner != a.Runner || ack.Receipt != a.Receipt || !uuid.MatchString(ack.IID) || ack.Nonce != s.Nonce || ack.Version != c.Version || ack.Digest != c.Digest || ack.Issued < issued.Unix()-300 || ack.Issued > issued.Unix()+300 {
		return nil, ErrRefused
	}
	s.Runner, s.Receipt, s.Ack = a.Runner, a.Receipt, a.JWS
	s.Registration = nil
	for _, k := range a.Keys {
		s.Pins = append(s.Pins, Pin{Key: k})
	}
	if e = store.Save(ctx, s); e != nil {
		return nil, ErrRefused
	}
	return s, nil
}
func Rotate(ctx context.Context, store SecretStore, s *Secret, token string, at time.Time) error {
	if token != "" && s.Rotation == token {
		return nil
	}
	i, e := wire.VerifyScanRotation(token, s.keys(at))
	if e != nil || i.Audience != s.Runner {
		return ErrRefused
	}
	if wire.ValidateKeySet(i.Keys) != nil {
		return ErrRefused
	}
	next := *s
	next.Rotation = token
	next.Pins = append([]Pin(nil), s.Pins...)
	for n := range next.Pins {
		if next.Pins[n].Until == 0 {
			next.Pins[n].Until = at.Add(7 * 24 * time.Hour).Unix()
		}
	}
	for _, k := range i.Keys {
		for _, p := range s.Pins {
			if p.Key.KID == k.KID {
				return ErrRefused
			}
		}
		next.Pins = append(next.Pins, Pin{Key: k})
	}
	if e = store.Save(ctx, &next); e != nil {
		return ErrRefused
	}
	*s = next
	return nil
}
