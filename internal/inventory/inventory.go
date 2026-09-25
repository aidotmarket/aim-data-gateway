package inventory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/config"
	"github.com/aidotmarket/aim-data-gateway/internal/ids"
)

const BlockSize = 8 << 20
const MaxFiles = 100000
const BatchSize = 1000

var ErrTooLarge = errors.New("inventory_too_large")

type Phase1 struct {
	FileID            string    `json:"file_id"`
	DisplayName       string    `json:"display_name"`
	SizeBytes         int64     `json:"size_bytes"`
	MediaType         string    `json:"media_type"`
	ContentCommitment string    `json:"content_commitment"`
	FirstSeenAt       time.Time `json:"first_seen_at"`
	ChangedAt         time.Time `json:"changed_at"`
	Present           bool      `json:"present"`
}
type Record struct {
	Phase1                           Phase1
	Source, RelativePath, Path, Root string
	SHA256                           [32]byte
	BlockHashes                      [][32]byte
	Mtime                            time.Time
}

func (r Record) Open() (*os.File, error) {
	root, e := os.OpenRoot(r.Root)
	if e != nil {
		return nil, e
	}
	defer root.Close()
	f, e := root.Open(r.RelativePath)
	if e != nil {
		return nil, e
	}
	st, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, e
	}
	if !st.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("not a regular file")
	}
	return f, nil
}

type Batch struct {
	Generation uint64   `json:"generation"`
	Files      []Phase1 `json:"files"`
}

func Batches(records []Record, generation uint64) []Batch {
	if len(records) == 0 {
		return []Batch{{Generation: generation, Files: []Phase1{}}}
	}
	out := make([]Batch, 0, (len(records)+BatchSize-1)/BatchSize)
	for start := 0; start < len(records); start += BatchSize {
		end := min(start+BatchSize, len(records))
		batch := Batch{Generation: generation, Files: make([]Phase1, 0, end-start)}
		for _, r := range records[start:end] {
			batch.Files = append(batch.Files, r.Phase1)
		}
		out = append(out, batch)
	}
	return out
}

func (r Record) MarshalJSON() ([]byte, error) { return json.Marshal(r.Phase1) }
func Scan(c config.Config, k ids.Keys) ([]Record, error) {
	return scan(context.Background(), c, k, MaxFiles, nil)
}
func ScanWithPrevious(c config.Config, k ids.Keys, previous []Record) ([]Record, error) {
	return scan(context.Background(), c, k, MaxFiles, previous)
}
func ScanWithPreviousContext(ctx context.Context, c config.Config, k ids.Keys, previous []Record) ([]Record, error) {
	return scan(ctx, c, k, MaxFiles, previous)
}
func ScanLimit(c config.Config, k ids.Keys, limit int) ([]Record, error) {
	return scan(context.Background(), c, k, limit, nil)
}
func scan(ctx context.Context, c config.Config, k ids.Keys, limit int, previous []Record) ([]Record, error) {
	var out []Record
	prior := make(map[string]Record, len(previous))
	for _, r := range previous {
		if r.Phase1.Present {
			prior[r.Phase1.FileID] = r
		}
	}
	for _, source := range c.Sources {
		root, e := filepath.EvalSymlinks(source.Path)
		if e != nil {
			return nil, e
		}
		rootHandle, e := os.OpenRoot(root)
		if e != nil {
			return nil, e
		}
		e = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if walkErr != nil {
				return walkErr
			}
			if d.Type()&os.ModeSymlink != 0 {
				return nil
			} // no links are followed, including links into the root
			if d.IsDir() {
				return nil
			}
			info, e := d.Info()
			if e != nil {
				return e
			}
			if !info.Mode().IsRegular() {
				return nil
			}
			if len(out) >= limit {
				return ErrTooLarge
			}
			rel, e := filepath.Rel(root, path)
			if e != nil {
				return e
			}
			rel = filepath.ToSlash(rel)
			id := ids.FileID(k, source.Name, rel)
			old, ok := prior[id]
			same := ok && old.Source == source.Name && old.RelativePath == rel && old.Phase1.SizeBytes == info.Size() && old.Mtime.Equal(info.ModTime().UTC())
			var r Record
			if same {
				r = old
			} else {
				f, e := rootHandle.Open(rel)
				if e != nil {
					return e
				}
				stop := context.AfterFunc(ctx, func() { _ = f.Close() })
				r, e = readFileContext(ctx, f)
				stop()
				f.Close()
				if e != nil {
					return fmt.Errorf("inventory read: %w", e)
				}
			}
			r.Source = source.Name
			r.RelativePath = rel
			r.Path = path
			r.Root = root
			r.Mtime = info.ModTime().UTC()
			name := c.Alias(source.Name, r.RelativePath)
			if name == "" {
				name = ids.DisplayName(id, r.Phase1.MediaType)
			}
			now := time.Now().UTC()
			r.Phase1.FileID = id
			r.Phase1.DisplayName = name
			r.Phase1.ContentCommitment = ids.ContentCommitment(k, r.SHA256)
			if ok {
				r.Phase1.FirstSeenAt = old.Phase1.FirstSeenAt
			} else {
				r.Phase1.FirstSeenAt = now
			}
			if !same {
				r.Phase1.ChangedAt = now
			}
			r.Phase1.Present = true
			out = append(out, r)
			return nil
		})
		rootHandle.Close()
		if e != nil {
			return nil, e
		}
	}
	seen := make(map[string]bool, len(out))
	for _, r := range out {
		seen[r.Phase1.FileID] = true
	}
	var deleted []string
	for id := range prior {
		if !seen[id] {
			deleted = append(deleted, id)
		}
	}
	sort.Strings(deleted)
	for _, id := range deleted {
		r := prior[id]
		r.Phase1.Present = false
		out = append(out, r)
	}
	return out, nil
}
func readFile(f *os.File) (Record, error) { return readFileContext(context.Background(), f) }
func readFileContext(ctx context.Context, f *os.File) (Record, error) {
	var r Record
	st, e := f.Stat()
	if e != nil {
		return r, e
	}
	if !st.Mode().IsRegular() {
		return r, errors.New("not a regular file")
	}
	full := sha256.New()
	block := make([]byte, BlockSize)
	first := make([]byte, 0, 4096)
	for {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		n, e := io.ReadFull(f, block)
		if n > 0 {
			full.Write(block[:n])
			r.BlockHashes = append(r.BlockHashes, sha256.Sum256(block[:n]))
			r.Phase1.SizeBytes += int64(n)
			if len(first) < cap(first) {
				take := min(n, cap(first)-len(first))
				first = append(first, block[:take]...)
			}
		}
		if e == io.EOF || e == io.ErrUnexpectedEOF {
			break
		}
		if e != nil {
			return r, e
		}
	}
	copy(r.SHA256[:], full.Sum(nil))
	r.Phase1.MediaType = detect(first)
	return r, nil
}
func detect(b []byte) string {
	if len(b) >= 4 && bytes.Equal(b[:4], []byte("PAR1")) {
		return "application/vnd.apache.parquet"
	}
	// Text formats are recognized from content, never from names.
	s := strings.TrimPrefix(string(b), "\ufeff")
	line, _, _ := strings.Cut(s, "\n")
	line = strings.TrimSuffix(line, "\r")
	if len(line) == 0 || !utf8Text(b) {
		return "application/octet-stream"
	}
	if json.Valid([]byte(line)) && (strings.HasPrefix(strings.TrimSpace(line), "{") || strings.HasPrefix(strings.TrimSpace(line), "[")) {
		return "application/x-ndjson"
	}
	if strings.Contains(line, "\t") {
		return "text/tab-separated-values"
	}
	if strings.Contains(line, ",") {
		return "text/csv"
	}
	return "application/octet-stream"
}
func utf8Text(b []byte) bool {
	for _, x := range b {
		if x == 0 {
			return false
		}
	}
	return true
}
func SHAHex(r Record) string { return hex.EncodeToString(r.SHA256[:]) }
