package wire

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

type Permission struct {
	Audience         string `json:"aud"`
	OrderID          string `json:"oid"`
	ListingVersionID string `json:"lvid"`
	FileID           string `json:"fid"`
	SHA256           string `json:"sha256"`
	JTI              string `json:"jti"`
	IssuedAt         int64  `json:"iat"`
	StartDeadline    int64  `json:"sd"`
	TransferDeadline int64  `json:"td"`
	ResumeOffset     int64  `json:"ro"`
}
type Instruction struct {
	Op               string `json:"op"`
	Audience         string `json:"aud"`
	IID              string `json:"iid"`
	IssuedAt         int64  `json:"iat"`
	FileID           string `json:"fid,omitempty"`
	SHA256           string `json:"sha256,omitempty"`
	ListingVersionID string `json:"lvid,omitempty"`
	ConfirmationID   string `json:"cid,omitempty"`
	ExpiresAt        int64  `json:"exp,omitempty"`
	JTI              string `json:"jti,omitempty"`
	OrderID          string `json:"oid,omitempty"`
	Keys             []Key  `json:"keys,omitempty"`
	Version          string `json:"version,omitempty"`
}
type Key struct {
	KID string `json:"kid"`
	Alg string `json:"alg"`
	Key string `json:"key"`
}
type RevokeAck struct {
	Op          string `json:"op"`
	JTI         string `json:"jti"`
	StateBefore string `json:"state_before"`
}
type PrepareAck struct {
	Op               string  `json:"op"`
	IID              string  `json:"iid"`
	OrderID          string  `json:"oid"`
	FileID           string  `json:"fid"`
	Ready            bool    `json:"ready"`
	Refusal          *string `json:"refusal"`
	ResumeOffset     int64   `json:"resume_offset"`
	TransmittedBytes int64   `json:"transmitted_bytes"`
	IntervalCount    int     `json:"interval_count"`
	MaxServeCount    int     `json:"max_serve_count"`
}
type Interval [2]int64

func (i Interval) Length() int64 {
	if i[1] < i[0] {
		return 0
	}
	return i[1] - i[0] + 1
}

type Receipt struct {
	Op                    string     `json:"op"`
	OrderID               string     `json:"oid"`
	FileID                string     `json:"fid"`
	SHA256                string     `json:"sha256"`
	SizeBytes             int64      `json:"size_bytes"`
	JTIs                  []string   `json:"jtis"`
	Transmitted           []Interval `json:"transmitted"`
	TransmittedBytes      int64      `json:"transmitted_bytes"`
	MaxServesReachedBytes int64      `json:"max_serves_reached_bytes"`
	Outcome               string     `json:"outcome"`
	BlocksVerified        bool       `json:"blocks_verified"`
	FirstByteAt           string     `json:"first_byte_at"`
	LastByteAt            string     `json:"last_byte_at"`
	Seq                   uint64     `json:"seq"`
}

func (i Instruction) Kind() (typ, keyClass string, err error) {
	switch i.Op {
	case "offer", "unoffer":
		return "aim-offer+jwt", "listing", nil
	case "describe":
		return "aim-describe+jwt", "listing", nil
	case "revoke":
		return "aim-revoke+jwt", "permission", nil
	case "prepare":
		return "aim-prepare+jwt", "permission", nil
	case "key_rotation":
		return "aim-keys+jwt", "outgoing", nil
	case "minimum_version":
		return "aim-minver+jwt", "listing", nil
	default:
		return "", "", errors.New("unknown instruction")
	}
}
func Canonical(v any) ([]byte, error) {
	raw, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var x any
	if e = dec.Decode(&x); e != nil {
		return nil, e
	}
	var b bytes.Buffer
	if e = write(&b, x); e != nil {
		return nil, e
	}
	return b.Bytes(), nil
}
func write(w io.Writer, v any) error {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		io.WriteString(w, "{")
		for i, k := range keys {
			if i > 0 {
				io.WriteString(w, ",")
			}
			j, _ := json.Marshal(k)
			w.Write(j)
			io.WriteString(w, ":")
			if e := write(w, x[k]); e != nil {
				return e
			}
		}
		io.WriteString(w, "}")
	case []any:
		io.WriteString(w, "[")
		for i, y := range x {
			if i > 0 {
				io.WriteString(w, ",")
			}
			if e := write(w, y); e != nil {
				return e
			}
		}
		io.WriteString(w, "]")
	default:
		b, e := json.Marshal(x)
		if e != nil {
			return e
		}
		_, e = w.Write(b)
		return e
	}
	return nil
}

var b64 = base64.RawURLEncoding

type Header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KID       string `json:"kid"`
}

func Sign(typ, kid string, claims any, private ed25519.PrivateKey) (string, error) {
	if len(private) != ed25519.PrivateKeySize {
		return "", errors.New("invalid private key")
	}
	h, e := Canonical(Header{"EdDSA", typ, kid})
	if e != nil {
		return "", e
	}
	p, e := Canonical(claims)
	if e != nil {
		return "", e
	}
	input := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	sig := ed25519.Sign(private, []byte(input))
	return input + "." + b64.EncodeToString(sig), nil
}
func Verify(token, typ string, keys map[string]ed25519.PublicKey, out any) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("invalid compact JWS")
	}
	h, e := b64.DecodeString(parts[0])
	if e != nil {
		return e
	}
	var header Header
	if e = json.Unmarshal(h, &header); e != nil {
		return e
	}
	if header.Algorithm != "EdDSA" || header.Type != typ {
		return errors.New("wrong JWS algorithm or type")
	}
	key := keys[header.KID]
	if len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("unknown kid %q", header.KID)
	}
	sig, e := b64.DecodeString(parts[2])
	if e != nil {
		return e
	}
	if !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return errors.New("invalid signature")
	}
	p, e := b64.DecodeString(parts[1])
	if e != nil {
		return e
	}
	dec := json.NewDecoder(bytes.NewReader(p))
	dec.DisallowUnknownFields()
	if e = dec.Decode(out); e != nil {
		return e
	}
	if dec.Decode(new(any)) != io.EOF {
		return errors.New("trailing claims")
	}
	return nil
}
