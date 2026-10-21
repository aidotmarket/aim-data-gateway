package profile

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"os"
	"testing"

	"github.com/aidotmarket/aim-data-gateway/internal/config"
	"github.com/aidotmarket/aim-data-gateway/internal/inventory"
)

type mutatingSource struct {
	*os.File
	afterRead func(int64)
}

func (s *mutatingSource) ReadAt(p []byte, off int64) (int, error) {
	n, e := s.File.ReadAt(p, off)
	if s.afterRead != nil {
		s.afterRead(off)
	}
	return n, e
}

func TestSourceBindingMutationDuringDecode(t *testing.T) {
	csv := append([]byte("a,b\n1,"), bytes.Repeat([]byte("x"), inventory.BlockSize)...)
	csv = append(csv, []byte("\n2,y\n")...)
	fixture, e := os.ReadFile("testdata/f_none.parquet")
	if e != nil {
		t.Fatal(e)
	}
	// Retain original column offsets while moving the footer beyond a block.
	footerStart := len(fixture) - 8 - int(binary.LittleEndian.Uint32(fixture[len(fixture)-8:]))
	pq := append([]byte{}, fixture[:footerStart]...)
	pq = append(pq, bytes.Repeat([]byte{0}, inventory.BlockSize)...)
	pq = append(pq, fixture[footerStart:]...)
	for _, tc := range []struct {
		name            string
		body            []byte
		trigger, change int64
	}{
		{"sequential", csv, 0, inventory.BlockSize},
		{"parquet_random", pq, inventory.BlockSize, 4},
		{"parquet_cached", fixture, 0, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := inventoryBody(t, tc.body)
			// Prove the decoder accepts the unmodified multi-block fixture first.
			if _, e := File(r, config.Columns{}); e != nil {
				t.Fatal(e)
			}
			f, e := os.OpenFile(r.Path, os.O_RDWR, 0600)
			if e != nil {
				t.Fatal(e)
			}
			defer f.Close()
			mutated := false
			source := &mutatingSource{File: f}
			source.afterRead = func(off int64) {
				if !mutated && off == tc.trigger {
					mutated = true
					value := []byte{tc.body[tc.change] ^ 1}
					if _, e := f.WriteAt(value, tc.change); e != nil {
						t.Fatal(e)
					}
				}
			}
			d, e := fileFromReader(context.Background(), r, config.Columns{}, source)
			if !mutated {
				t.Fatal("mutation was not reached")
			}
			if !errors.Is(e, errSourceChanged) || d.SHA256 != "" {
				t.Fatalf("mutation result: %+v %v", d, e)
			}
		})
	}
}

func TestVerifiedReaderRandomAccessAndCancellation(t *testing.T) {
	body := bytes.Repeat([]byte("abcd"), inventory.BlockSize/4+3)
	r := inventoryBody(t, body)
	f, e := r.Open()
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	v, e := newVerifiedReader(ctx, f, r)
	if e != nil {
		t.Fatal(e)
	}
	for _, off := range []int64{inventory.BlockSize - 3, 0, inventory.BlockSize, 0} {
		got := make([]byte, 10)
		n, e := v.ReadAt(got, off)
		if e != nil || n != 10 || !bytes.Equal(got, body[off:off+10]) {
			t.Fatalf("read at %d: %d %v", off, n, e)
		}
	}
	if _, e := v.Seek(-3, io.SeekEnd); e != nil {
		t.Fatal(e)
	}
	got := make([]byte, 4)
	if n, e := v.Read(got); n != 3 || e != io.EOF || !bytes.Equal(got[:n], body[len(body)-3:]) {
		t.Fatalf("short read: %d %v", n, e)
	}
	if _, e := v.Seek(0, io.SeekCurrent); e != nil {
		t.Fatal(e)
	}
	if n, e := v.ReadAt(nil, r.Phase1.SizeBytes); n != 0 || e != nil {
		t.Fatalf("empty read: %d %v", n, e)
	}
	if _, e := v.ReadAt(got, -1); e == nil {
		t.Fatal("negative read accepted")
	}
	if _, e := v.Seek(math.MaxInt64, io.SeekCurrent); e == nil {
		t.Fatal("seek overflow accepted")
	}
	if _, e := v.Seek(-1, io.SeekStart); e == nil {
		t.Fatal("negative seek accepted")
	}
	cancel()
	if _, e := v.ReadAt(got, 0); !errors.Is(e, ErrGatewayTimeout) {
		t.Fatal(e)
	}
	if e := v.verify(); !errors.Is(e, ErrGatewayTimeout) {
		t.Fatal(e)
	}
}

func TestSourceBindingUnverifiableInventory(t *testing.T) {
	for _, change := range []string{"sha", "block", "missing", "extra", "size"} {
		t.Run(change, func(t *testing.T) {
			r := inventoryBody(t, []byte("a,b\n1,2\n"))
			switch change {
			case "sha":
				r.SHA256[0] ^= 1
			case "block":
				r.BlockHashes[0][0] ^= 1
			case "missing":
				r.BlockHashes = nil
			case "extra":
				r.BlockHashes = append(r.BlockHashes, [32]byte{})
			case "size":
				r.Phase1.SizeBytes = -1
			}
			if d, e := File(r, config.Columns{}); e == nil || d.SHA256 != "" {
				t.Fatalf("unverifiable result: %+v %v", d, e)
			}
		})
	}
}

func TestSourceBindingDroppedParquetMutation(t *testing.T) {
	entries, e := os.ReadDir("testdata")
	if e != nil {
		t.Fatal(e)
	}
	body, e := os.ReadFile("testdata/" + entries[0].Name())
	if e != nil {
		t.Fatal(e)
	}
	r := inventoryBody(t, body)
	body[4] ^= 1
	if e := os.WriteFile(r.Path, body, 0600); e != nil {
		t.Fatal(e)
	}
	if d, e := File(r, config.Columns{Drop: []string{"i", "f", "s", "b", "d", "ts"}}); e == nil || d.SHA256 != "" {
		t.Fatalf("dropped bytes bypassed verification: %+v %v", d, e)
	}
}

func TestSourceBindingCancellationDuringRead(t *testing.T) {
	r := inventoryBody(t, []byte("a,b\n1,2\n"))
	f, e := r.Open()
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &mutatingSource{File: f, afterRead: func(int64) { cancel() }}
	if d, e := fileFromReader(ctx, r, config.Columns{}, s); !errors.Is(e, ErrGatewayTimeout) || d.SHA256 != "" {
		t.Fatalf("cancelled result: %+v %v", d, e)
	}
}
