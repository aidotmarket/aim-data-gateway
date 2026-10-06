// Package cloudflareverification adapts an admitted, immutable R2 snapshot.
// The caller owns signed-work authorization, durable admission and bridge custody.
package cloudflareverification

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode/utf8"

	"github.com/aidotmarket/aim-data-gateway/verification"
	"golang.org/x/text/unicode/norm"
)

func Identity(key, etag string) (string, error) {
	if key == "" || etag == "" || strings.ContainsRune(key+etag, 0) || !utf8.ValidString(key) || !utf8.ValidString(etag) {
		return "", verification.ErrArtifactChanged
	}
	return norm.NFC.String(key) + "\x00" + norm.NFC.String(etag), nil
}

type Commitments struct {
	Bucket, ManifestHash string
	Key                  [32]byte
}

func (c Commitments) mac(preimage string) string {
	h := hmac.New(sha256.New, c.Key[:])
	h.Write([]byte(norm.NFC.String(preimage)))
	return hex.EncodeToString(h.Sum(nil))
}
func (c Commitments) LocatorCommitment() string {
	return c.mac("r2_listing\x00" + c.Bucket + "\x00" + c.ManifestHash)
}
func (c Commitments) ObjectID(m verification.Member) string {
	return c.mac("object\x00r2_listing\x00" + c.Bucket + "\x00" + m.Identity + "\x00" + hex.EncodeToString(m.SHA256[:]))
}
