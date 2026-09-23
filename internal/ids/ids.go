package ids

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

type Keys struct{ ID, Commitment [32]byte }

func Derive(secret []byte) (Keys, error) {
	var k Keys
	if len(secret) != 32 {
		return k, errors.New("volume secret must be 32 bytes")
	}
	a, e := hkdf.Key(sha256.New, secret, nil, "aim-gateway/file-id/v1", 32)
	if e != nil {
		return k, e
	}
	copy(k.ID[:], a)
	b, e := hkdf.Key(sha256.New, secret, nil, "aim-gateway/content-commitment/v1", 32)
	if e != nil {
		return k, e
	}
	copy(k.Commitment[:], b)
	return k, nil
}
func FileID(k Keys, source, relative string) string {
	m := hmac.New(sha256.New, k.ID[:])
	m.Write([]byte(source))
	m.Write([]byte{0})
	m.Write([]byte(relative))
	return hex.EncodeToString(m.Sum(nil))[:32]
}
func ContentCommitment(k Keys, rawSHA [32]byte) string {
	m := hmac.New(sha256.New, k.Commitment[:])
	m.Write(rawSHA[:])
	return hex.EncodeToString(m.Sum(nil))
}
func DisplayName(id, media string) string {
	ext := map[string]string{"text/csv": "csv", "text/tab-separated-values": "tsv", "application/x-ndjson": "jsonl", "application/vnd.apache.parquet": "parquet"}[media]
	if ext == "" {
		ext = "bin"
	}
	if len(id) < 8 {
		return ""
	}
	return "file-" + strings.ToLower(id[:8]) + "." + ext
}
