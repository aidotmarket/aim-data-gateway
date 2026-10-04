// Package awsverification adapts an already authorized immutable S3 snapshot.
// Provider integration and signed-work admission are owned by Chunk 2b.
package awsverification

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/aidotmarket/aim-data-gateway/verification"
	"golang.org/x/text/unicode/norm"
)

const AWS_VERIFY_PARQUET_READ_AHEAD_BYTES = 4_194_304

// Request keeps raw provider names. End is inclusive; -1 means a full GET.
// A provider implementation must apply VersionID else IfMatch to HEAD and GET.
type Request struct {
	Bucket, Key, VersionID, IfMatch string
	Start, End                      int64
}
type Head struct {
	Size            int64
	VersionID, ETag string
}
type S3 interface {
	Head(context.Context, Request) (Head, error)
	Get(context.Context, Request) (io.ReadCloser, error)
}
type Object struct {
	Key, VersionID, ETag, Format string
	Size                         int64
	SHA256                       [32]byte
	DigestPresent                bool
}

func Identity(key, pin string) (string, error) {
	if key == "" || pin == "" || strings.ContainsRune(key+pin, 0) || !utf8.ValidString(key+pin) {
		return "", verification.ErrArtifactChanged
	}
	return norm.NFC.String(key) + "\x00" + norm.NFC.String(pin), nil
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
	return c.mac("s3_listing\x00" + c.Bucket + "\x00" + c.ManifestHash)
}
func (c Commitments) ObjectID(m verification.Member) string {
	return c.mac("object\x00s3_listing\x00" + c.Bucket + "\x00" + m.Identity + "\x00" + hex.EncodeToString(m.SHA256[:]))
}

type Source struct {
	client    S3
	bucket    string
	members   []verification.Member
	objects   map[string]Object
	readAhead int64
}

// NewSource rejects canonical collisions before any provider operation. It never
// lists a prefix or changes the signed member order; input must already be sorted.
func NewSource(client S3, bucket string, objects []Object) (*Source, error) {
	if client == nil || bucket == "" || len(objects) == 0 {
		return nil, verification.ErrArtifactChanged
	}
	s := &Source{client: client, bucket: bucket, objects: map[string]Object{}, readAhead: AWS_VERIFY_PARQUET_READ_AHEAD_BYTES}
	for _, o := range objects {
		if o.VersionID == "null" {
			o.VersionID = ""
		}
		pin := o.VersionID
		if pin == "" {
			pin = o.ETag
		}
		id, err := Identity(o.Key, pin)
		if err != nil || o.Size < 0 {
			return nil, verification.ErrArtifactChanged
		}
		if _, exists := s.objects[id]; exists {
			return nil, verification.ErrArtifactChanged
		}
		if len(s.members) > 0 && s.members[len(s.members)-1].Identity >= id {
			return nil, verification.ErrArtifactChanged
		}
		s.objects[id] = o
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
	if !ok {
		return Request{}, o, verification.ErrArtifactChanged
	}
	r := Request{Bucket: s.bucket, Key: o.Key, VersionID: o.VersionID, End: -1}
	if r.VersionID == "" {
		r.IfMatch = "\"" + o.ETag + "\""
	}
	h, err := s.client.Head(ctx, r)
	if err != nil || h.Size != o.Size || o.VersionID != "" && h.VersionID != o.VersionID || o.VersionID == "" && h.ETag != o.ETag {
		return r, o, verification.ErrArtifactChanged
	}
	return r, o, nil
}
func (s *Source) Open(ctx context.Context, id string) (io.ReadCloser, error) {
	r, _, err := s.request(ctx, id)
	if err != nil {
		return nil, err
	}
	return s.client.Get(ctx, r)
}
func (s *Source) OpenAt(ctx context.Context, id string) (verification.RandomAccess, error) {
	r, o, err := s.request(ctx, id)
	if err != nil {
		return nil, err
	}
	return &reader{ctx: ctx, client: s.client, request: r, size: o.Size, capacity: min(s.readAhead, o.Size)}, nil
}

type reader struct {
	mu                    sync.Mutex
	ctx                   context.Context
	client                S3
	request               Request
	size, capacity, start int64
	cache                 []byte
	closed                bool
}

func (r *reader) Size() int64          { return r.size }
func (r *reader) BufferedBytes() int64 { return r.capacity }
func (r *reader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	r.cache = nil
	return nil
}
func (r *reader) ReadAt(dst []byte, off int64) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || off < 0 {
		return 0, verification.ErrArtifactChanged
	}
	if len(dst) == 0 {
		return 0, nil
	}
	done := 0
	for len(dst) > 0 && off < r.size {
		if r.ctx.Err() != nil {
			return done, r.ctx.Err()
		}
		if len(r.cache) == 0 || off < r.start || off >= r.start+int64(len(r.cache)) {
			req := r.request
			req.Start = off
			req.End = off + min(r.capacity, r.size-off) - 1
			body, err := r.client.Get(r.ctx, req)
			if err != nil {
				return done, verification.ErrArtifactChanged
			}
			if r.cache == nil {
				r.cache = make([]byte, r.capacity)
			}
			r.cache = r.cache[:req.End-off+1]
			_, err = io.ReadFull(body, r.cache)
			var extra [1]byte
			n, endErr := body.Read(extra[:])
			closeErr := body.Close()
			if err != nil || n != 0 || endErr != io.EOF || closeErr != nil {
				r.cache = nil
				return done, verification.ErrArtifactChanged
			}
			r.start = off
		}
		n := copy(dst, r.cache[off-r.start:])
		done += n
		off += int64(n)
		dst = dst[n:]
	}
	if len(dst) > 0 {
		return done, io.EOF
	}
	return done, nil
}
