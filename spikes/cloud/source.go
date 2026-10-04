// Package cloud adapts S3 and R2 using identical pinned reads.
package cloud

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	h "github.com/aidotmarket/aim-data-gateway/spikes/harness"
	v "github.com/aidotmarket/aim-data-gateway/verification"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"golang.org/x/text/unicode/norm"
)

type API interface {
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}
type Source struct {
	Client  API
	Bucket  string
	members []v.Member
	objects map[string]h.Object
	meter   *h.Meter
}

func Factory(client API, kind string) h.Factory {
	return func(ctx context.Context, e h.Event, meter *h.Meter) (v.Source, h.Commitments, error) {
		c := h.Commitments{Kind: kind, Bucket: e.Bucket, Objects: map[string]h.Object{}}
		s := &Source{Client: client, Bucket: e.Bucket, objects: c.Objects, meter: meter}
		if e.Bucket == "" || strings.ContainsRune(e.Bucket, 0) || !norm.NFC.IsNormalString(e.Bucket) || len(e.Objects) == 0 || len(e.Objects) > 100000 {
			return nil, c, errors.New("invalid event")
		}
		type entry struct {
			Kind   string `json:"provider"`
			Bucket string `json:"bucket"`
			Key    string `json:"key"`
			Pin    string `json:"pin"`
			Size   int64  `json:"size"`
		}
		manifest := []entry{}
		objects := append([]h.Object(nil), e.Objects...)
		sort.Slice(objects, func(i, j int) bool {
			return objects[i].Key+"\x00"+objects[i].VersionID+objects[i].ETag < objects[j].Key+"\x00"+objects[j].VersionID+objects[j].ETag
		})
		for _, o := range objects {
			if !strings.HasPrefix(o.Key, "spike/") || strings.ContainsRune(o.Key+o.VersionID+o.ETag, 0) || !norm.NFC.IsNormalString(o.Key+o.VersionID+o.ETag) {
				return nil, c, errors.New("invalid pin or key outside spike/")
			}
			in := &s3.HeadObjectInput{Bucket: aws.String(e.Bucket), Key: aws.String(o.Key)}
			if o.VersionID != "" {
				in.VersionId = aws.String(o.VersionID)
			} else if o.ETag != "" {
				in.IfMatch = aws.String(o.ETag)
			}
			head, err := client.HeadObject(ctx, in)
			if err != nil {
				return nil, c, err
			}
			if head.ContentLength == nil || *head.ContentLength < 0 {
				return nil, c, errors.New("missing size")
			}
			if o.VersionID != "" {
				if aws.ToString(head.VersionId) != o.VersionID {
					return nil, c, v.ErrArtifactChanged
				}
			} else {
				if o.ETag == "" {
					o.ETag = aws.ToString(head.ETag)
				}
				if o.ETag == "" || o.ETag != aws.ToString(head.ETag) {
					return nil, c, v.ErrArtifactChanged
				}
			}
			id := h.Identity(o)
			if _, exists := s.objects[id]; exists {
				return nil, c, errors.New("duplicate identity")
			}
			s.objects[id] = o
			s.members = append(s.members, v.Member{Identity: id, Size: *head.ContentLength, Format: o.Format})
			pin := o.VersionID
			if pin == "" {
				pin = o.ETag
			}
			manifest = append(manifest, entry{kind, e.Bucket, o.Key, pin, *head.ContentLength})
		}
		var err error
		c.Manifest, err = h.Digest(manifest)
		if err != nil {
			return nil, c, err
		}
		sort.Slice(s.members, func(i, j int) bool { return s.members[i].Identity < s.members[j].Identity })
		return s, c, nil
	}
}
func (s *Source) Members() []v.Member { return append([]v.Member(nil), s.members...) }
func (s *Source) get(ctx context.Context, id, span string) (io.ReadCloser, error) {
	o, ok := s.objects[id]
	if !ok {
		return nil, v.ErrArtifactChanged
	}
	in := &s3.GetObjectInput{Bucket: aws.String(s.Bucket), Key: aws.String(o.Key)}
	if o.VersionID != "" {
		in.VersionId = aws.String(o.VersionID)
	} else {
		in.IfMatch = aws.String(o.ETag)
	}
	if span != "" {
		in.Range = aws.String(span)
		s.meter.Ranges++
	}
	out, err := s.Client.GetObject(ctx, in)
	if err != nil {
		return nil, err
	}
	if out.Body == nil {
		return nil, errors.New("missing body")
	}
	if o.VersionID != "" && aws.ToString(out.VersionId) != o.VersionID || o.VersionID == "" && aws.ToString(out.ETag) != o.ETag {
		out.Body.Close()
		return nil, v.ErrArtifactChanged
	}
	return h.Count(out.Body, s.meter), nil
}
func (s *Source) Open(ctx context.Context, id string) (io.ReadCloser, error) {
	return s.get(ctx, id, "")
}
func (s *Source) OpenAt(ctx context.Context, id string) (v.RandomAccess, error) {
	for _, m := range s.members {
		if m.Identity == id {
			return &ranged{ctx: ctx, s: s, id: id, size: m.Size}, nil
		}
	}
	return nil, v.ErrArtifactChanged
}

// One 256 KiB read-ahead cache. Every cache fill is version/ETag conditioned.
type ranged struct {
	mu          sync.Mutex
	ctx         context.Context
	s           *Source
	id          string
	size, start int64
	buf         []byte
	closed      bool
}

func (r *ranged) Size() int64 { return r.size }
func (r *ranged) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	r.buf = nil
	return nil
}
func (r *ranged) ReadAt(p []byte, off int64) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, errors.New("closed")
	}
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	done := 0
	for len(p) > 0 && off < r.size {
		if err := r.ctx.Err(); err != nil {
			return done, err
		}
		if len(r.buf) == 0 || off < r.start || off >= r.start+int64(len(r.buf)) {
			end := min(r.size, off+(256<<10))
			body, err := r.s.get(r.ctx, r.id, fmt.Sprintf("bytes=%d-%d", off, end-1))
			if err != nil {
				return done, err
			}
			stop := context.AfterFunc(r.ctx, func() { body.Close() })
			b, err := io.ReadAll(io.LimitReader(body, end-off+1))
			stop()
			ce := body.Close()
			if err == nil {
				err = ce
			}
			if err != nil {
				return done, err
			}
			if int64(len(b)) != end-off {
				return done, v.ErrArtifactChanged
			}
			r.start = off
			r.buf = b
		}
		n := copy(p, r.buf[off-r.start:])
		done += n
		off += int64(n)
		p = p[n:]
	}
	if len(p) > 0 {
		return done, io.EOF
	}
	return done, nil
}
