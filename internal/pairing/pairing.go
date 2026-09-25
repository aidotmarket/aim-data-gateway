package pairing

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/aidotmarket/aim-data-gateway/internal/wire"
)

const PairURL = "https://api.ai.market/api/v1/gateway-channel/pair"

type Pins struct {
	GatewayID      string            `json:"gateway_id"`
	PermissionKeys []wire.Key        `json:"permission_keys"`
	ListingKeys    []wire.Key        `json:"listing_keys"`
	MinimumVersion string            `json:"minimum_version"`
	CanaryHost     string            `json:"canary_host"`
	CanaryZone     string            `json:"canary_zone"`
	KeyExpires     map[string]string `json:"key_expires,omitempty"`
}

type State struct {
	Private ed25519.PrivateKey
	Secret  []byte
	Pins    Pins
}

// Pair is single-use on an empty volume. URL and client are injectable only by callers/tests;
// the run command always supplies PairURL.
func Pair(ctx context.Context, dir, code, version, url string, client *http.Client) (State, error) {
	if code == "" {
		return State{}, errors.New("pairing code required")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return State{}, err
	}
	if err := os.RemoveAll(filepath.Join(dir, ".pairing-staging")); err != nil {
		return State{}, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return State{}, err
	}
	if len(entries) != 0 {
		return State{}, errors.New("pairing requires an empty state volume")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return State{}, err
	}
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		return State{}, err
	}
	request, err := json.Marshal(map[string]string{
		"code": code, "gateway_public_key": hex.EncodeToString(public), "version": version,
	})
	if err != nil {
		return State{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(request))
	if err != nil {
		return State{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := client.Do(req)
	if err != nil {
		return State{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return State{}, fmt.Errorf("pairing failed: HTTP %d", response.StatusCode)
	}
	var pins Pins
	if err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&pins); err != nil {
		return State{}, err
	}
	if pins.GatewayID == "" || len(pins.PermissionKeys) == 0 || len(pins.ListingKeys) == 0 || pins.MinimumVersion == "" || pins.CanaryHost == "" || pins.CanaryZone == "" {
		return State{}, errors.New("incomplete pairing response")
	}
	for _, keys := range [][]wire.Key{pins.PermissionKeys, pins.ListingKeys} {
		for _, k := range keys {
			b, e := base64.RawURLEncoding.DecodeString(k.Key)
			if k.KID == "" || k.Alg != "EdDSA" || e != nil || len(b) != ed25519.PublicKeySize {
				return State{}, errors.New("invalid pinned key")
			}
		}
	}
	pinsRaw, err := json.Marshal(pins)
	if err != nil {
		return State{}, err
	}
	stage := filepath.Join(dir, ".pairing-staging")
	if err = os.Mkdir(stage, 0700); err != nil {
		return State{}, err
	}
	for _, file := range []struct {
		name string
		data []byte
	}{{"identity.key", private}, {"secret.bin", secret}, {"pins.json", pinsRaw}} {
		f, openErr := os.OpenFile(filepath.Join(stage, file.name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if openErr != nil {
			return State{}, openErr
		}
		_, err = f.Write(file.data)
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return State{}, err
		}
	}
	if err = syncDirectory(stage); err != nil {
		return State{}, err
	}
	for _, name := range []string{"identity.key", "secret.bin", "pins.json"} {
		if err = os.Rename(filepath.Join(stage, name), filepath.Join(dir, name)); err != nil {
			return State{}, err
		}
	}
	if err = syncDirectory(dir); err != nil {
		return State{}, err
	}
	marker := filepath.Join(stage, "complete")
	if err = os.WriteFile(marker, []byte("paired\n"), 0600); err != nil {
		return State{}, err
	}
	markFile, err := os.Open(marker)
	if err != nil {
		return State{}, err
	}
	err = markFile.Sync()
	closeErr := markFile.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return State{}, err
	}
	if err = syncDirectory(stage); err != nil {
		return State{}, err
	}
	if err = os.Rename(marker, filepath.Join(dir, ".pairing-complete")); err != nil {
		return State{}, err
	}
	if err = syncDirectory(dir); err != nil {
		return State{}, err
	}
	if err = os.Remove(stage); err != nil {
		return State{}, err
	}
	return State{private, secret, pins}, nil
}
func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func Load(dir string) (State, error) {
	var s State
	if err := os.RemoveAll(filepath.Join(dir, ".pairing-staging")); err != nil {
		return s, err
	}
	if _, err := os.Stat(filepath.Join(dir, ".pairing-complete")); err != nil {
		return s, errors.New("incomplete pairing: completion marker missing")
	}
	private, err := os.ReadFile(filepath.Join(dir, "identity.key"))
	if err != nil {
		return s, err
	}
	if len(private) != ed25519.PrivateKeySize {
		return s, errors.New("invalid gateway identity")
	}
	secret, err := os.ReadFile(filepath.Join(dir, "secret.bin"))
	if err != nil {
		return s, err
	}
	if len(secret) != 32 {
		return s, errors.New("invalid volume secret")
	}
	b, err := os.ReadFile(filepath.Join(dir, "pins.json"))
	if err != nil {
		return s, err
	}
	if err = json.Unmarshal(b, &s.Pins); err != nil {
		return s, err
	}
	s.Private, s.Secret = private, secret
	return s, nil
}
