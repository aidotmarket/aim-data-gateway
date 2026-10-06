package cloudflareverification

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/aidotmarket/aim-data-gateway/verification"
)

const (
	CF_VERIFY_TEXT_MAX_BYTES           = int64(4_000_000_000)
	CF_VERIFY_PARQUET_MAX_BYTES        = int64(700_000_000)
	CF_VERIFY_ESTIMATED_TEXT_BPS       = int64(8_000_000)
	CF_VERIFY_ESTIMATED_PARQUET_BPS    = int64(1_200_000)
	CF_VERIFY_OVERHEAD_SECONDS         = 120
	CF_VERIFY_ESTIMATE_MAX_SECONDS     = 720
	CF_VERIFY_PARQUET_READ_AHEAD_BYTES = 4_194_304
	MaxMembers                         = 17_033
	MaxSnapshot                        = 12 << 20
	MaxReport                          = 2 << 20
)

var ErrRefused = errors.New("verification_refused")

type Object struct {
	Key, ETag, Format string
	Size              int64
	SHA256            [32]byte
	DigestPresent     bool
}

// SnapshotBinding comes from the authorized job and installed connection, never
// from mutable draft selection. Signature verification belongs to the caller.
type SnapshotBinding struct {
	ConnectionID, Bucket, ListingID, ListingVersionID, SourceHandleID string
}

// ParseSnapshot accepts only the exact Python-canonical frozen payload and hash.
// It validates all members before returning anything usable by a bridge.
func ParseSnapshot(raw []byte, manifestHash string, binding SnapshotBinding) ([]Object, error) {
	if len(raw) > MaxSnapshot {
		return nil, ErrRefused
	}
	h := sha256.Sum256(raw)
	if hex.EncodeToString(h[:]) != manifestHash {
		return nil, ErrRefused
	}
	v, err := verification.ParseCanonical(raw)
	m, ok := v.(map[string]any)
	if err != nil || !ok || len(m) != 8 {
		return nil, ErrRefused
	}
	for k, want := range map[string]string{
		"snapshot_version": "verification-source-snapshot-v1", "source_kind": "r2_listing",
		"connection_id": binding.ConnectionID, "bucket": binding.Bucket,
		"listing_id": binding.ListingID, "listing_version_id": binding.ListingVersionID,
		"source_handle_id": binding.SourceHandleID,
	} {
		if want == "" || m[k] != want {
			return nil, ErrRefused
		}
	}
	a, ok := m["members"].([]any)
	if !ok || len(a) == 0 || len(a) > MaxMembers {
		return nil, ErrRefused
	}
	objects := make([]Object, 0, len(a))
	for _, v := range a {
		m, ok := v.(map[string]any)
		if !ok || len(m) != 5 || m["provider"] != "r2" {
			return nil, ErrRefused
		}
		for _, k := range []string{"provider", "key", "etag", "size_bytes", "format"} {
			if _, ok := m[k]; !ok {
				return nil, ErrRefused
			}
		}
		n, ok := m["size_bytes"].(json.Number)
		if !ok {
			return nil, ErrRefused
		}
		if _, err := n.Int64(); err != nil {
			return nil, ErrRefused
		}
		b, e := verification.Canonical(m)
		var o struct {
			Key    string `json:"key"`
			ETag   string `json:"etag"`
			Size   int64  `json:"size_bytes"`
			Format string `json:"format"`
		}
		if e != nil || json.Unmarshal(b, &o) != nil {
			return nil, ErrRefused
		}
		objects = append(objects, Object{Key: o.Key, ETag: o.ETag, Size: o.Size, Format: o.Format})
	}
	if err = validateObjects(binding.Bucket, objects); err != nil {
		return nil, ErrRefused
	}
	return objects, nil
}

// WorstReportSize mirrors the released AWS companion/body envelope boundary.
func WorstReportSize(members int) int {
	if members < 1 || members > MaxMembers {
		return MaxReport + 1
	}
	return 955734 + 171 + 67*members - 1
}

func AdmitSize(objects []Object) error {
	if len(objects) == 0 || len(objects) > MaxMembers || WorstReportSize(len(objects)) > MaxReport {
		return ErrRefused
	}
	var t, p int64
	for _, o := range objects {
		if o.Size < 0 || o.Size > CF_VERIFY_TEXT_MAX_BYTES {
			return ErrRefused
		}
		switch o.Format {
		case "csv", "tsv", "jsonl":
			t += o.Size
		case "parquet":
			p += o.Size
		default:
			return ErrRefused
		}
		if t > CF_VERIFY_TEXT_MAX_BYTES || p > CF_VERIFY_PARQUET_MAX_BYTES {
			return ErrRefused
		}
	}
	// Exact rational inequalities; checked totals keep these products in int64.
	if 7*t+40*p > 28_000_000_000 || 3*t+20*p > int64(CF_VERIFY_ESTIMATE_MAX_SECONDS-CF_VERIFY_OVERHEAD_SECONDS)*24_000_000 {
		return ErrRefused
	}
	return nil
}

func validateObjects(bucket string, objects []Object) error {
	if bucket == "" || strings.ContainsRune(bucket, 0) || !utf8.ValidString(bucket) {
		return verification.ErrArtifactChanged
	}
	if err := AdmitSize(objects); err != nil {
		return err
	}
	previous := ""
	for _, o := range objects {
		id, err := Identity(o.Key, o.ETag)
		ext := strings.TrimPrefix(strings.ToLower(path.Ext(o.Key)), ".")
		if ext == "ndjson" {
			ext = "jsonl"
		}
		if err != nil || strings.ContainsAny(o.ETag, "\"\r\n") || o.Format != ext || previous >= id {
			return verification.ErrArtifactChanged
		}
		previous = id
	}
	return nil
}

type Source struct {
	bridge  Bridge
	bucket  string
	members []verification.Member
	objects map[string]Object
	indices map[string]int
}

// NewSource preserves signed member order. Go string comparison is unsigned
// UTF-8 byte order; equal/NFC-colliding or out-of-order identities refuse here.
func NewSource(bridge Bridge, bucket string, objects []Object) (*Source, error) {
	if bridge == nil {
		return nil, verification.ErrArtifactChanged
	}
	if err := validateObjects(bucket, objects); err != nil {
		return nil, err
	}
	s := &Source{bridge: bridge, bucket: bucket, objects: map[string]Object{}, indices: map[string]int{}}
	for i, o := range objects {
		id, _ := Identity(o.Key, o.ETag)
		s.objects[id], s.indices[id] = o, i
		s.members = append(s.members, verification.Member{Identity: id, OrderingKey: []byte(id), Size: o.Size, Format: o.Format, SHA256: o.SHA256, DigestPresent: o.DigestPresent})
	}
	return s, nil
}

func (s *Source) Members() []verification.Member {
	out := append([]verification.Member(nil), s.members...)
	for i := range out {
		out[i].OrderingKey = append([]byte(nil), out[i].OrderingKey...)
	}
	return out
}

func (s *Source) request(ctx context.Context, id string) (Request, Object, error) {
	o, ok := s.objects[id]
	if !ok || ctx.Err() != nil {
		return Request{}, o, verification.ErrArtifactChanged
	}
	r := Request{MemberIndex: s.indices[id], Bucket: s.bucket, Key: o.Key, IfMatch: o.ETag}
	h, err := s.bridge.Head(ctx, r)
	if err != nil || h == nil || h.Size != o.Size || h.ETag != o.ETag {
		return r, o, verification.ErrArtifactChanged
	}
	return r, o, nil
}

func (s *Source) Open(ctx context.Context, id string) (io.ReadCloser, error) {
	r, o, err := s.request(ctx, id)
	if err != nil {
		return nil, err
	}
	body, err := get(ctx, s.bridge, r, o.Size)
	if err != nil {
		return nil, err
	}
	return &fullReader{ctx: ctx, body: body, remaining: o.Size}, nil
}

func (s *Source) OpenAt(ctx context.Context, id string) (verification.RandomAccess, error) {
	r, o, err := s.request(ctx, id)
	if err != nil {
		return nil, err
	}
	return &reader{ctx: ctx, bridge: s.bridge, request: r, size: o.Size, capacity: min(int64(CF_VERIFY_PARQUET_READ_AHEAD_BYTES), o.Size)}, nil
}
