package wire

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/inventory"
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

// Gateway answers use aim-<message name>+jwt as their JWS type.
type Hello struct {
	GatewayID string `json:"gid"`
	Nonce     string `json:"nonce"`
	Version   string `json:"version"`
	Time      string `json:"ts"`
}
type Description struct {
	FileID   string   `json:"file_id"`
	SHA256   string   `json:"sha256"`
	RowCount int64    `json:"row_count"`
	Columns  []Column `json:"columns"`
}
type Column struct {
	Name           string `json:"name"`
	Type           string `json:"type"`
	NullRatePct    *int   `json:"null_rate_pct"`
	DistinctBucket string `json:"distinct_bucket"`
}
type CanaryResult struct {
	State string `json:"state"`
	DNS   string `json:"dns"`
	TCP   string `json:"tcp"`
	Proxy string `json:"proxy"`
	Label string `json:"label"`
	At    string `json:"at"`
}
type OfferAck struct {
	IID     string  `json:"iid"`
	FileID  string  `json:"fid"`
	Ready   bool    `json:"ready"`
	Refusal *string `json:"refusal"`
}
type GatewayError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
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
	if e = strict(h, &header); e != nil {
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
	return strict(p, out)
}

func strict(data []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	if dec.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}

var hex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)
var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

var revokeStates = []string{"active", "expired", "closed", "unknown"}
var refusalCodes = []string{"not_offered", "outside_ceiling", "awaiting_local_approval", "file_changed", "file_missing", "coverage_exhausted", "complete"}
var receiptOutcomes = []string{"in_progress", "complete", "aborted_block_mismatch", "aborted_deadline"}

func validReadiness(ready bool, refusal *string) bool {
	if ready {
		return refusal == nil
	}
	return refusal != nil && slices.Contains(refusalCodes, *refusal)
}

func required(token string, names ...string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("invalid compact JWS")
	}
	p, err := b64.DecodeString(parts[1])
	if err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := strict(p, &fields); err != nil {
		return err
	}
	for _, name := range names {
		value, ok := fields[name]
		if !ok || (string(value) == "null" && name != "refusal") {
			return fmt.Errorf("missing claim %s", name)
		}
	}
	return nil
}

func VerifyPermission(token string, keys map[string]ed25519.PublicKey) (Permission, error) {
	var p Permission
	if err := Verify(token, "aim-permission+jwt", keys, &p); err != nil {
		return p, err
	}
	if err := required(token, "aud", "oid", "lvid", "fid", "sha256", "jti", "iat", "sd", "td", "ro"); err != nil {
		return p, err
	}
	if !uuid.MatchString(p.Audience) || !uuid.MatchString(p.OrderID) || !uuid.MatchString(p.ListingVersionID) || !hex32.MatchString(p.FileID) || !hex64.MatchString(p.SHA256) || !uuid.MatchString(p.JTI) || p.IssuedAt <= 0 || p.StartDeadline <= p.IssuedAt || p.TransferDeadline < p.StartDeadline || p.ResumeOffset < 0 {
		return p, errors.New("invalid permission claims")
	}
	return p, nil
}

func VerifyInstruction(token string, keys map[string]ed25519.PublicKey) (Instruction, error) {
	var i Instruction
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return i, errors.New("invalid compact JWS")
	}
	p, err := b64.DecodeString(parts[1])
	if err != nil {
		return i, err
	}
	if err := strict(p, &i); err != nil {
		return i, err
	}
	typ, _, err := i.Kind()
	if err != nil {
		return i, err
	}
	if err := Verify(token, typ, keys, &i); err != nil {
		return i, err
	}
	if err := required(token, "op", "aud", "iid", "iat"); err != nil {
		return i, err
	}
	if !uuid.MatchString(i.Audience) || !uuid.MatchString(i.IID) || i.IssuedAt <= 0 {
		return i, errors.New("invalid instruction claims")
	}
	if i.ExpiresAt != 0 && i.ExpiresAt <= time.Now().Unix() {
		return i, errors.New("expired instruction")
	}
	var extra []string
	switch i.Op {
	case "offer", "unoffer":
		extra = []string{"fid", "sha256", "lvid"}
		if !hex32.MatchString(i.FileID) || !hex64.MatchString(i.SHA256) || !uuid.MatchString(i.ListingVersionID) {
			return i, errors.New("invalid offer claims")
		}
	case "describe":
		extra = []string{"fid", "cid", "exp"}
		if !hex32.MatchString(i.FileID) || !uuid.MatchString(i.ConfirmationID) || i.ExpiresAt != i.IssuedAt+900 {
			return i, errors.New("invalid describe claims")
		}
	case "revoke":
		extra = []string{"jti"}
		if !uuid.MatchString(i.JTI) {
			return i, errors.New("invalid revoke claims")
		}
	case "prepare":
		extra = []string{"oid", "fid", "sha256"}
		if !uuid.MatchString(i.OrderID) || !hex32.MatchString(i.FileID) || !hex64.MatchString(i.SHA256) {
			return i, errors.New("invalid prepare claims")
		}
	case "key_rotation":
		extra = []string{"keys"}
		if len(i.Keys) == 0 {
			return i, errors.New("missing keys")
		}
		for _, k := range i.Keys {
			raw, err := b64.DecodeString(k.Key)
			if k.KID == "" || k.Alg != "EdDSA" || err != nil || len(raw) != ed25519.PublicKeySize {
				return i, errors.New("invalid rotation key")
			}
		}
	case "minimum_version":
		extra = []string{"version"}
		if i.Version == "" {
			return i, errors.New("missing version")
		}
	}
	if err := required(token, extra...); err != nil {
		return i, err
	}
	return i, nil
}

// VerifyGatewayAnswer verifies the gateway signature and the declared answer type.
func VerifyGatewayAnswer(token, name string, keys map[string]ed25519.PublicKey, out any) error {
	if err := Verify(token, "aim-"+name+"+jwt", keys, out); err != nil {
		return err
	}
	switch name {
	case "revoke_ack":
		v, ok := out.(*RevokeAck)
		if !ok || v.Op != name || !uuid.MatchString(v.JTI) || !slices.Contains(revokeStates, v.StateBefore) {
			return errors.New("invalid revoke ack")
		}
		return required(token, "op", "jti", "state_before")
	case "prepare_ack":
		v, ok := out.(*PrepareAck)
		if !ok || v.Op != name || !uuid.MatchString(v.IID) || !uuid.MatchString(v.OrderID) || !hex32.MatchString(v.FileID) || !validReadiness(v.Ready, v.Refusal) {
			return errors.New("invalid prepare ack")
		}
		return required(token, "op", "iid", "oid", "fid", "ready", "refusal", "resume_offset", "transmitted_bytes", "interval_count", "max_serve_count")
	case "receipt":
		v, ok := out.(*Receipt)
		if !ok || v.Op != name || !uuid.MatchString(v.OrderID) || !hex32.MatchString(v.FileID) || !hex64.MatchString(v.SHA256) || !slices.Contains(receiptOutcomes, v.Outcome) {
			return errors.New("invalid receipt")
		}
		return required(token, "op", "oid", "fid", "sha256", "size_bytes", "jtis", "transmitted", "transmitted_bytes", "max_serves_reached_bytes", "outcome", "blocks_verified", "first_byte_at", "last_byte_at", "seq")
	case "hello":
		v, ok := out.(*Hello)
		if !ok || !uuid.MatchString(v.GatewayID) || v.Nonce == "" || v.Version == "" || v.Time == "" {
			return errors.New("invalid hello")
		}
		return required(token, "gid", "nonce", "version", "ts")
	case "inventory":
		v, ok := out.(*inventory.Batch)
		if !ok || v.Files == nil {
			return errors.New("invalid inventory")
		}
		for _, f := range v.Files {
			if !hex32.MatchString(f.FileID) || !hex64.MatchString(f.ContentCommitment) || f.DisplayName == "" || f.MediaType == "" || f.FirstSeenAt.IsZero() || f.ChangedAt.IsZero() {
				return errors.New("invalid inventory file")
			}
		}
		return required(token, "generation", "files")
	case "description":
		v, ok := out.(*Description)
		if !ok || !hex32.MatchString(v.FileID) || !hex64.MatchString(v.SHA256) || v.Columns == nil {
			return errors.New("invalid description")
		}
		return required(token, "file_id", "sha256", "row_count", "columns")
	case "canary_result":
		v, ok := out.(*CanaryResult)
		if !ok || v.State == "" || v.DNS == "" || v.TCP == "" || v.Proxy == "" || v.Label == "" || v.At == "" {
			return errors.New("invalid canary result")
		}
		return required(token, "state", "dns", "tcp", "proxy", "label", "at")
	case "offer_ack":
		v, ok := out.(*OfferAck)
		if !ok || !uuid.MatchString(v.IID) || !hex32.MatchString(v.FileID) || !validReadiness(v.Ready, v.Refusal) {
			return errors.New("invalid offer ack")
		}
		return required(token, "iid", "fid", "ready", "refusal")
	case "error":
		v, ok := out.(*GatewayError)
		if !ok || v.Code == "" || v.Message == "" {
			return errors.New("invalid gateway error")
		}
		return required(token, "code", "message")
	default:
		return errors.New("unknown gateway answer")
	}
}
