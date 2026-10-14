package profile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"math"
	"os"
	"sync"

	"github.com/aidotmarket/aim-data-gateway/internal/inventory"
)

var errSourceChanged = errors.New("description source changed or unverifiable")

type profileSource interface {
	io.ReaderAt
	Stat() (os.FileInfo, error)
}

// verifiedReader exposes only bytes checked against the inventory's pinned blocks.
// One immutable verified block is retained; revisiting an evicted block verifies
// it again. The file stays open and confined for the entire description.
type verifiedReader struct {
	mu     sync.Mutex
	ctx    context.Context
	source profileSource
	record inventory.Record
	buf    []byte
	block  int64
	pos    int64
}

func newVerifiedReader(ctx context.Context, source profileSource, r inventory.Record) (*verifiedReader, error) {
	size := r.Phase1.SizeBytes
	count := int64(0)
	if size > 0 {
		count = (size-1)/inventory.BlockSize + 1
	}
	if size < 0 || int64(len(r.BlockHashes)) != count {
		return nil, errSourceChanged
	}
	v := &verifiedReader{ctx: ctx, source: source, record: r, block: -1}
	if e := v.checkSize(); e != nil {
		return nil, e
	}
	return v, nil
}

func (v *verifiedReader) checkSize() error {
	if e := checkDeadline(v.ctx); e != nil {
		return e
	}
	st, e := v.source.Stat()
	if e != nil {
		return e
	}
	if !st.Mode().IsRegular() || st.Size() != v.record.Phase1.SizeBytes {
		return errSourceChanged
	}
	return nil
}

func (v *verifiedReader) load(index int64) error {
	if e := checkDeadline(v.ctx); e != nil {
		return e
	}
	if v.block == index {
		return nil
	}
	v.block = -1
	start := index * inventory.BlockSize
	n := int(min(int64(inventory.BlockSize), v.record.Phase1.SizeBytes-start))
	if v.buf == nil {
		v.buf = make([]byte, min(int64(inventory.BlockSize), v.record.Phase1.SizeBytes))
	}
	count, e := v.source.ReadAt(v.buf[:n], start)
	if timeout := checkDeadline(v.ctx); timeout != nil {
		return timeout
	}
	if count != n || e != nil && e != io.EOF || sha256.Sum256(v.buf[:n]) != v.record.BlockHashes[index] {
		return errSourceChanged
	}
	v.block = index
	return nil
}

func (v *verifiedReader) ReadAt(dst []byte, off int64) (int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.readAt(dst, off)
}

func (v *verifiedReader) readAt(dst []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative read offset")
	}
	if e := checkDeadline(v.ctx); e != nil {
		return 0, e
	}
	done := 0
	for len(dst) > 0 && off < v.record.Phase1.SizeBytes {
		index := off / inventory.BlockSize
		if e := v.load(index); e != nil {
			return done, e
		}
		end := min(int64(inventory.BlockSize), v.record.Phase1.SizeBytes-index*inventory.BlockSize)
		n := copy(dst, v.buf[off%inventory.BlockSize:end])
		done += n
		off += int64(n)
		dst = dst[n:]
	}
	if len(dst) > 0 {
		return done, io.EOF
	}
	return done, nil
}

func (v *verifiedReader) Read(dst []byte) (int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	n, e := v.readAt(dst, v.pos)
	v.pos += int64(n)
	return n, e
}

func (v *verifiedReader) Seek(off int64, whence int) (int64, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	base := int64(0)
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		base = v.pos
	case io.SeekEnd:
		base = v.record.Phase1.SizeBytes
	default:
		return 0, errors.New("invalid seek whence")
	}
	if off < -base || off > math.MaxInt64-base {
		return 0, errors.New("invalid seek offset")
	}
	v.pos = base + off
	return v.pos, nil
}

// The caller owns the descriptor. Parquet may close its reader before the final
// whole-file check, which also covers blocks omitted by column drop rules.
func (v *verifiedReader) Close() error { return nil }

func (v *verifiedReader) verify() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if e := v.checkSize(); e != nil {
		return e
	}
	v.block = -1
	h := sha256.New()
	for i := range v.record.BlockHashes {
		if e := v.load(int64(i)); e != nil {
			return e
		}
		n := min(int64(inventory.BlockSize), v.record.Phase1.SizeBytes-int64(i)*inventory.BlockSize)
		h.Write(v.buf[:n])
	}
	if !bytes.Equal(h.Sum(nil), v.record.SHA256[:]) {
		return errSourceChanged
	}
	return v.checkSize()
}
