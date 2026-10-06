package cloudflareverification

import (
	"context"
	"io"
	"sync"
	"sync/atomic"

	"github.com/aidotmarket/aim-data-gateway/verification"
)

type Range struct{ Offset, Length int64 }

// IfMatch is the raw, unquoted ETag. Every bridge HEAD/GET must enforce it.
// MemberIndex selects only the admitted snapshot member; raw names are preserved
// for provider calls, never used to expand scope. Nil Range means a full GET.
type Request struct {
	MemberIndex          int
	Bucket, Key, IfMatch string
	Range                *Range
}
type Head struct {
	Size int64 // Total object size, also on ranged GETs.
	ETag string
}
type GetResult struct {
	Metadata *Head
	Range    *Range // Exact returned range; nil for a full GET.
	Body     io.ReadCloser
}

// Bridge is injected; this package has no network/provider client. The bridge
// binds its private invocation capability to the durably admitted snapshot and
// checks member index and names. It offers no list/write/delete operation.
// Nil metadata means missing; metadata without a body means failed onlyIf.
// Transport retries must retain the exact request, including IfMatch and range.
// Body.Close must interrupt a concurrent Read (scanner cancellation).
type Bridge interface {
	Head(context.Context, Request) (*Head, error)
	Get(context.Context, Request) (GetResult, error)
}

func get(ctx context.Context, bridge Bridge, req Request, size int64) (io.ReadCloser, error) {
	result, err := bridge.Get(ctx, req)
	valid := err == nil && result.Metadata != nil && result.Body != nil && result.Metadata.Size == size && result.Metadata.ETag == req.IfMatch
	if req.Range == nil {
		valid = valid && result.Range == nil
	} else {
		valid = valid && result.Range != nil && *result.Range == *req.Range
	}
	if !valid {
		if result.Body != nil {
			result.Body.Close()
		}
		return nil, verification.ErrArtifactChanged
	}
	return result.Body, nil
}

// fullReader checks exact length without buffering or a separate hashing pass.
// One final byte is inspected only to refuse an overlong bridge response.
type fullReader struct {
	ctx       context.Context
	body      io.ReadCloser
	remaining int64
	closed    atomic.Bool
	once      sync.Once
	closeErr  error
}

func (r *fullReader) Read(dst []byte) (int, error) {
	if r.closed.Load() {
		return 0, verification.ErrArtifactChanged
	}
	if r.ctx.Err() != nil {
		return 0, r.ctx.Err()
	}
	if len(dst) == 0 {
		return 0, nil
	}
	if r.remaining == 0 {
		var extra [1]byte
		n, err := r.body.Read(extra[:])
		if n != 0 || err != io.EOF {
			return 0, verification.ErrArtifactChanged
		}
		return 0, io.EOF
	}
	n, err := r.body.Read(dst[:min(int64(len(dst)), r.remaining)])
	r.remaining -= int64(n)
	if err != nil && (err != io.EOF || r.remaining != 0) {
		return n, verification.ErrArtifactChanged
	}
	return n, err
}
func (r *fullReader) Close() error {
	r.once.Do(func() { r.closed.Store(true); r.closeErr = r.body.Close() })
	return r.closeErr
}

type reader struct {
	mu                    sync.Mutex
	ctx                   context.Context
	bridge                Bridge
	request               Request
	size, capacity, start int64
	cache                 []byte
	closed                bool
}

func (r *reader) Size() int64 { return r.size }

// The shared scanner reserves this capacity before decoding any Parquet page.
func (r *reader) BufferedBytes() int64 { return r.capacity }
func (r *reader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed, r.cache = true, nil
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
			r.cache = r.cache[:0]
			req := r.request
			req.Range = &Range{Offset: off, Length: min(r.capacity, r.size-off)}
			body, err := get(r.ctx, r.bridge, req, r.size)
			if err != nil {
				return done, err
			}
			// Reuse one fixed buffer. Length remains zero until validation succeeds,
			// so a failed refill cannot expose partial or stale bytes on retry.
			if r.cache == nil {
				r.cache = make([]byte, 0, r.capacity)
			}
			cache := r.cache[:req.Range.Length]
			stop := context.AfterFunc(r.ctx, func() { body.Close() })
			_, err = io.ReadFull(body, cache)
			var extra [1]byte
			n, endErr := body.Read(extra[:])
			stop()
			closeErr := body.Close()
			if err != nil || n != 0 || endErr != io.EOF || closeErr != nil {
				return done, verification.ErrArtifactChanged
			}
			r.start, r.cache = off, cache
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
