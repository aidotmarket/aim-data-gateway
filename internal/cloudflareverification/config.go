package cloudflareverification

import (
	"encoding/json"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	"strings"
)

const APIBaseURL = "https://api.ai.market"
const CF_VERIFY_DEADLINE_SECONDS = 780
const CF_VERIFY_INVOCATION_MAX_SECONDS = 900
const CF_VERIFY_TERMINAL_DEADLINE_SECONDS = 1920

type WorkerIdentity struct {
	Mode   string `json:"mode"`
	SHA256 string `json:"sha256"`
}
type Config struct {
	Connection   string         `json:"connection_id"`
	Bucket       string         `json:"bucket"`
	Prefix       string         `json:"prefix"`
	Jurisdiction string         `json:"jurisdiction"`
	Keys         []string       `json:"keys"`
	Token        string         `json:"registration_token"`
	Version      string         `json:"scanner_version"`
	Release      string         `json:"release_id"`
	Binary       string         `json:"binary_sha256"`
	Worker       WorkerIdentity `json:"worker_identity"`
}

func (c Config) Validate() error {
	if !uuid.MatchString(c.Connection) || c.Bucket == "" || strings.ContainsAny(c.Bucket, "/:*?\\\x00") || c.Jurisdiction != "default" || !identifier.MatchString(c.Version) || !identifier.MatchString(c.Release) || !hex64.MatchString(c.Binary) || !hex64.MatchString(c.Worker.SHA256) || (c.Worker.Mode != "bundle" && c.Worker.Mode != "source_tree_lockfile") || len(c.Keys) == 0 || len(c.Keys) > MaxMembers {
		return ErrRefused
	}
	raw, e := json.Marshal(c)
	if e != nil || len(raw) > 1<<20 {
		return ErrRefused
	}
	seen := map[string]bool{}
	for _, k := range c.Keys {
		if k == "" || strings.ContainsRune(k, 0) || !strings.HasPrefix(k, c.Prefix) || seen[k] {
			return ErrRefused
		}
		seen[k] = true
	}
	return nil
}
func (c Config) permits(key string) bool {
	for _, k := range c.Keys {
		if k == key {
			return true
		}
	}
	return false
}
func (c Config) identity() map[string]any {
	return map[string]any{"release_id": c.Release, "scanner_version": c.Version, "binary_sha256": c.Binary, "worker_identity": c.Worker}
}
func validToken(token string) bool {
	b, e := wire.DecodeDocument(token, 32)
	return e == nil && len(b) == 32
}
