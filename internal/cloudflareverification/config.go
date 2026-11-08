package cloudflareverification

import (
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	core "github.com/aidotmarket/aim-data-gateway/verification"
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
	ConfigHash   string         `json:"deployment_config_sha256,omitempty"`
	Connection   string         `json:"connection_id"`
	Bucket       string         `json:"bucket"`
	Prefix       string         `json:"prefix"`
	Jurisdiction string         `json:"jurisdiction"`
	ReadScope    string         `json:"read_scope,omitempty"`
	Keys         []string       `json:"keys"`
	Token        string         `json:"registration_token,omitempty"`
	Version      string         `json:"scanner_version"`
	Release      string         `json:"release_id"`
	Binary       string         `json:"binary_sha256"`
	Worker       WorkerIdentity `json:"worker_identity"`
}

func (c Config) Validate() error {
	if !uuid.MatchString(c.Connection) || c.Bucket == "" || strings.ContainsAny(c.Bucket, "/:*?\\\x00") || c.Jurisdiction != "default" || !identifier.MatchString(c.Version) || !identifier.MatchString(c.Release) || !hex64.MatchString(c.Binary) || !hex64.MatchString(c.Worker.SHA256) || (c.Worker.Mode != "bundle" && c.Worker.Mode != "source_tree_lockfile") || len(c.Keys) > MaxMembers {
		return ErrRefused
	}
	if strings.ContainsAny(c.Prefix, "*?\x00") || strings.Contains(c.Prefix, "${") {
		return ErrRefused
	}
	switch c.ReadScope {
	case "", "keys":
		if len(c.Keys) == 0 {
			return ErrRefused
		}
	case "prefix":
		if c.Prefix == "" || len(c.Keys) != 0 {
			return ErrRefused
		}
	case "whole_bucket":
		if c.Prefix != "" || len(c.Keys) != 0 {
			return ErrRefused
		}
	default:
		return ErrRefused
	}
	scope := c
	scope.Token, scope.ConfigHash = "", ""
	raw, e := core.Canonical(scope)
	if e != nil || len(raw) > 1<<20 {
		return ErrRefused
	}
	seen := map[string]bool{}
	for _, k := range c.Keys {
		if k == "" || strings.ContainsAny(k, "*?\x00") || strings.Contains(k, "${") || !strings.HasPrefix(k, c.Prefix) || seen[k] {
			return ErrRefused
		}
		seen[k] = true
	}
	return nil
}
func (c Config) permits(key string) bool {
	if key == "" || strings.ContainsRune(key, 0) {
		return false
	}
	if c.ReadScope == "whole_bucket" {
		return true
	}
	if c.ReadScope == "prefix" {
		return c.Prefix != "" && strings.HasPrefix(key, strings.TrimRight(c.Prefix, "/")+"/")
	}
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
