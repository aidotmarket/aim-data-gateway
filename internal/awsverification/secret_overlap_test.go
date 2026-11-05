package awsverification

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type gatedSecretStore struct {
	SecretStore
	arrived chan<- struct{}
	release <-chan struct{}
}

func (s gatedSecretStore) Save(ctx context.Context, next *Secret) error {
	s.arrived <- struct{}{}
	<-s.release
	return s.SecretStore.Save(ctx, next)
}

func rotationToken(t *testing.T, at time.Time, kid string, seed byte) string {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	key := wire.Key{KID: kid, Alg: "EdDSA", Key: base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey))}
	token, err := signJWS(platformPrivate, platformKey.KID, "aim-keys+jwt", map[string]any{
		"op": "key_rotation", "aud": runnerID, "iid": "88888888-8888-4888-8888-888888888888",
		"iat": at.Unix(), "keys": []wire.Key{key},
	})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func secretBoundary(t *testing.T, arrived <-chan struct{}, result <-chan error) {
	t.Helper()
	select {
	case <-arrived:
	case err := <-result:
		t.Fatalf("writer returned before overlap boundary: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("writer did not reach overlap boundary")
	}
}

func secretResult(t *testing.T, result <-chan error, want error) {
	t.Helper()
	select {
	case err := <-result:
		if !errors.Is(err, want) {
			t.Fatalf("writer error = %v, want %v", err, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("writer did not finish")
	}
}

func TestOverlappingSecretTransitionsRejectStaleWriters(t *testing.T) {
	for _, transition := range []string{"bootstrap_completion", "rotation"} {
		t.Run(transition, func(t *testing.T) {
			f := newFixture(t)
			api := &fakeSecretsAPI{}
			store := Secrets{Client: api, ID: "secret", Ledger: f.h.Ledger}
			// Leave the exact registration request durable, as after a lost reply.
			f.backend.lostRegister = true
			if _, err := Bootstrap(ctx, f.h.Config, f.h.Ledger, store, f.backend, f.at); !errors.Is(err, ErrRefused) {
				t.Fatal("expected pending registration", err)
			}
			f.backend.lostRegister = false
			var stale *Secret
			if transition == "rotation" {
				var err error
				stale, err = Bootstrap(ctx, f.h.Config, f.h.Ledger, store, f.backend, f.at)
				if err != nil {
					t.Fatal(err)
				}
			}
			arrived, release, result := make(chan struct{}), make(chan struct{}, 1), make(chan error, 1)
			defer close(release)
			delayed := gatedSecretStore{store, arrived, release}
			oldRotation := rotationToken(t, f.at, "delayed-key", 0x43)
			go func() {
				if transition == "bootstrap_completion" {
					_, err := Bootstrap(ctx, f.h.Config, f.h.Ledger, delayed, f.backend, f.at)
					result <- err
				} else {
					result <- Rotate(ctx, delayed, stale, oldRotation, f.at.Add(time.Hour))
				}
			}()
			secretBoundary(t, arrived, result)
			current, err := Bootstrap(ctx, f.h.Config, f.h.Ledger, store, f.backend, f.at)
			if err != nil {
				t.Fatal(err)
			}
			if err = Rotate(ctx, store, current, rotationToken(t, f.at, "newer-key", 0x44), f.at); err != nil {
				t.Fatal(err)
			}
			puts := len(api.puts)
			release <- struct{}{}
			secretResult(t, result, ErrRefused)
			reloaded, err := Bootstrap(ctx, f.h.Config, f.h.Ledger, store, f.backend, f.at)
			if err != nil || !reflect.DeepEqual(reloaded, current) || len(api.puts) != puts {
				t.Fatal("stale writer changed newer secret or failed to reload", err)
			}
			if len(reloaded.Pins) != 2 || reloaded.Pins[1].Key.KID != "newer-key" || reloaded.Pins[0].Until != f.at.Add(7*24*time.Hour).Unix() {
				t.Fatal("newer pin or original retirement deadline lost")
			}
			if _, exists := reloaded.keys(f.at.Add(7*24*time.Hour + time.Second))[platformKey.KID]; exists {
				t.Fatal("outgoing key revived after retirement")
			}
		})
	}
}

type gatedSecretsAPI struct {
	SecretsAPI
	arrived chan<- struct{}
	release <-chan struct{}
}

func (s gatedSecretsAPI) PutSecretValue(ctx context.Context, i *secretsmanager.PutSecretValueInput, options ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
	s.arrived <- struct{}{}
	<-s.release
	return s.SecretsAPI.PutSecretValue(ctx, i, options...)
}

func TestOverlappingSecretFenceRefusesUntilPutCompletes(t *testing.T) {
	f := newFixture(t)
	api := &fakeSecretsAPI{}
	store := Secrets{Client: api, ID: "secret", Ledger: f.h.Ledger}
	s, err := Bootstrap(ctx, f.h.Config, f.h.Ledger, store, f.backend, f.at)
	if err != nil {
		t.Fatal(err)
	}
	stale := copySecret(s)
	arrived, release, result := make(chan struct{}), make(chan struct{}, 1), make(chan error, 1)
	defer close(release)
	delayed := store
	delayed.Client = gatedSecretsAPI{api, arrived, release}
	go func() { result <- delayed.Save(ctx, s) }()
	secretBoundary(t, arrived, result)
	if _, err = store.Load(ctx); !errors.Is(err, ErrRefused) {
		t.Fatal("incomplete fenced version did not refuse", err)
	}
	if err = store.Save(ctx, stale); !errors.Is(err, ErrRefused) {
		t.Fatal("stale writer passed outstanding fence", err)
	}
	release <- struct{}{}
	secretResult(t, result, nil)
	reloaded, err := store.Load(ctx)
	if err != nil || !reflect.DeepEqual(reloaded, s) {
		t.Fatal("completed fenced version could not reload", err)
	}
	if f.db.items["secret"]["expires_at"] != nil {
		t.Fatal("secret fence can expire and reset history")
	}
}
