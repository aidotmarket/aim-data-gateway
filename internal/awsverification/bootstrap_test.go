package awsverification

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/wire"
)

func TestRegistrationExpiredConsumedAndExactRetry(t *testing.T) {
	for _, mode := range []string{
		"expired",
		"consumed",
		"lost_reply",
		"crash_binding",
	} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			switch mode {
			case "expired":
				f.backend.expired = true
			case "consumed":
				f.backend.consumed = true
			case "lost_reply":
				f.backend.lostRegister = true
			case "crash_binding":
				f.secrets.failSaveAt = 2
			}
			if _, e := Bootstrap(ctx, f.h.Config, f.h.Ledger, f.secrets, f.backend, f.at); e == nil {
				t.Fatal("expected refusal/crash")
			}
			original := copySecret(f.secrets.s)
			if original == nil || len(original.Registration) == 0 {
				t.Fatal("pending exact request not durable")
			}
			if mode == "expired" || mode == "consumed" {
				if _, e := Bootstrap(ctx, f.h.Config, f.h.Ledger, f.secrets, f.backend, f.at.Add(time.Hour)); e == nil {
					t.Fatal("old token revived")
				}
				return
			}
			f.backend.lostRegister = false
			f.secrets.failSaveAt = 0
			s, e := Bootstrap(ctx, f.h.Config, f.h.Ledger, f.secrets, f.backend, f.at.Add(time.Hour))
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(s.Private, original.Private) || !bytes.Equal(f.backend.registered, original.Registration) || s.Runner != runnerID || len(s.Registration) != 0 {
				t.Fatal("retry changed identity or token retained")
			}
			changed := append([]byte(nil), original.Registration...)
			changed[10] ^= 1
			if _, e = f.backend.Register(ctx, changed); e == nil {
				t.Fatal("changed consumed-token retry accepted")
			}
		})
	}
}
func TestBootstrapCrashAndFirstStartRace(t *testing.T) {
	f := newFixture(t)
	f.secrets.failSaveAt = 1
	if _, e := Bootstrap(ctx, f.h.Config, f.h.Ledger, f.secrets, f.backend, f.at); e == nil {
		t.Fatal("crash expected")
	}
	f.secrets.failSaveAt = 0
	if _, e := Bootstrap(ctx, f.h.Config, f.h.Ledger, f.secrets, f.backend, f.at); e == nil || f.secrets.s != nil {
		t.Fatal("ambiguous bootstrap replaced keys")
	}
	// Race key creation with a deliberately failed secret store. Exactly one
	// contender may reach Save; a lease is not an expiring key replacement right.
	f = newFixture(t)
	f.secrets.failSaveAt = 1
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			Bootstrap(ctx, f.h.Config, f.h.Ledger, f.secrets, f.backend, f.at)
		}()
	}
	wg.Wait()
	if f.secrets.saves != 1 || len(f.backend.registered) != 0 {
		t.Fatal("first-start keys raced")
	}
}
func TestSignedRotationOverlapAndWrongClassRefusal(t *testing.T) {
	f := newFixture(t)
	s, e := Bootstrap(ctx, f.h.Config, f.h.Ledger, f.secrets, f.backend, f.at)
	if e != nil {
		t.Fatal(e)
	}
	newPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x43}, 32))
	newKey := wire.Key{KID: "new-scan-key", Alg: "EdDSA", Key: base64.RawURLEncoding.EncodeToString(newPrivate.Public().(ed25519.PublicKey))}
	claims := map[string]any{
		"op":   "key_rotation",
		"aud":  runnerID,
		"iid":  "88888888-8888-4888-8888-888888888888",
		"iat":  f.at.Unix(),
		"keys": []wire.Key{newKey},
	}
	token, _ := signJWS(newPrivate, newKey.KID, "aim-keys+jwt", claims)
	if Rotate(ctx, f.secrets, s, token, f.at) == nil {
		t.Fatal("untrusted/wrong class rotation")
	}
	token, _ = signJWS(platformPrivate, platformKey.KID, "aim-keys+jwt", claims)
	if e = Rotate(ctx, f.secrets, s, token, f.at); e != nil {
		t.Fatal(e)
	}
	if len(s.keys(f.at.Add(7*24*time.Hour))) != 2 || len(s.keys(f.at.Add(7*24*time.Hour+time.Second))) != 1 {
		t.Fatal("overlap wrong")
	}
	if Rotate(ctx, f.secrets, s, token, f.at.Add(time.Hour)) != nil || len(s.Pins) != 2 {
		t.Fatal("exact rotation retry failed or replaced pins")
	}
	f.h.Config.Digest = "sha256:" + string(bytes.Repeat([]byte{'b'}, 64))
	if _, e = Bootstrap(ctx, f.h.Config, f.h.Ledger, f.secrets, f.backend, f.at); e == nil {
		t.Fatal("silently rebound code digest")
	}
}

func TestFifteenMinuteOldRotationAppliedAndAcknowledged(t *testing.T) {
	f := newFixture(t)
	newPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x43}, 32))
	newKey := wire.Key{KID: "new-scan-key", Alg: "EdDSA", Key: base64.RawURLEncoding.EncodeToString(newPrivate.Public().(ed25519.PublicKey))}
	var err error
	f.backend.work, err = signJWS(platformPrivate, platformKey.KID, "aim-keys+jwt", map[string]any{
		"op": "key_rotation", "aud": runnerID, "iid": "88888888-8888-4888-8888-888888888888",
		"iat": f.at.Add(-15 * time.Minute).Unix(), "keys": []wire.Key{newKey},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, delay := range []time.Duration{0, 15 * time.Minute} {
		f.at = f.at.Add(delay)
		if err = f.h.Invoke(ctx); err != nil {
			t.Fatal("old or byte-identical redelivered rotation refused", err)
		}
		if len(f.secrets.s.Pins) != 2 || f.secrets.s.Rotation != f.backend.work || !strings.HasPrefix(f.audit.events[len(f.audit.events)-1], "key_rotation ") {
			t.Fatal("rotation not durably applied and acknowledged")
		}
		if len(f.backend.reports) != 0 || len(f.s3.requests) != 0 {
			t.Fatal("rotation performed scan work")
		}
	}
}

func TestRotationSignedByExpiredOutgoingKeyRefused(t *testing.T) {
	f := newFixture(t)
	s, err := Bootstrap(ctx, f.h.Config, f.h.Ledger, f.secrets, f.backend, f.at)
	if err != nil {
		t.Fatal(err)
	}
	s.Pins[0].Until = f.at.Add(7 * 24 * time.Hour).Unix()
	newPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x43}, 32))
	newKey := wire.Key{KID: "new-scan-key", Alg: "EdDSA", Key: base64.RawURLEncoding.EncodeToString(newPrivate.Public().(ed25519.PublicKey))}
	token, err := signJWS(platformPrivate, platformKey.KID, "aim-keys+jwt", map[string]any{
		"op": "key_rotation", "aud": runnerID, "iid": "88888888-8888-4888-8888-888888888888",
		"iat": f.at.Unix(), "keys": []wire.Key{newKey},
	})
	if err != nil {
		t.Fatal(err)
	}
	saves := f.secrets.saves
	if Rotate(ctx, f.secrets, s, token, f.at.Add(7*24*time.Hour+time.Second)) == nil || f.secrets.saves != saves || len(s.Pins) != 1 || s.Rotation != "" {
		t.Fatal("expired outgoing signer accepted or rotation state changed")
	}
}
