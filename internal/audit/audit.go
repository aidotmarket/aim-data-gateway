package audit

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/wire"
)

const RotationBytes = 100_000_000

type Entry struct {
	Seq         uint64          `json:"seq"`
	Time        string          `json:"time"`
	MessageType string          `json:"message_type"`
	Body        json.RawMessage `json:"body"`
	PrevHash    string          `json:"prev_hash"`
	Sig         string          `json:"sig"`
}
type unsigned struct {
	Seq         uint64          `json:"seq"`
	Time        string          `json:"time"`
	MessageType string          `json:"message_type"`
	Body        json.RawMessage `json:"body"`
	PrevHash    string          `json:"prev_hash"`
}
type Log struct {
	mu        sync.Mutex
	dir       string
	private   ed25519.PrivateKey
	seq       uint64
	prev      string
	index     int
	size      int64
	rotations []rotation
	cursor    cursor
	last      Entry
	syncDir   func(string) error
	failed    error
}
type rotation struct {
	first uint64
	path  string
}
type cursor struct {
	seq    uint64
	path   string
	offset int64
}

func Open(dir string, private ed25519.PrivateKey) (*Log, error) {
	if len(private) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid key")
	}
	_, statErr := os.Stat(dir)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	if errors.Is(statErr, os.ErrNotExist) {
		if e := syncDirectory(filepath.Dir(dir)); e != nil {
			return nil, e
		}
	}
	l := &Log{dir: dir, private: private, syncDir: syncDirectory}
	files, e := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if e != nil {
		return nil, e
	}
	sort.Strings(files)
	for _, p := range files {
		f, e := os.Open(p)
		if e != nil {
			return nil, e
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 2<<20)
		first := l.seq + 1
		for sc.Scan() {
			entry, e := ValidateRaw(sc.Bytes(), private.Public().(ed25519.PublicKey))
			if e != nil {
				f.Close()
				return nil, e
			}
			if entry.Seq != l.seq+1 || entry.PrevHash != l.prev {
				f.Close()
				return nil, errors.New("audit chain broken")
			}
			h := sha256.Sum256(sc.Bytes())
			l.prev = hex.EncodeToString(h[:])
			l.seq++
			l.last = entry
		}
		e = sc.Err()
		f.Close()
		if e != nil {
			return nil, e
		}
		if l.seq >= first {
			l.rotations = append(l.rotations, rotation{first, p})
		}
		n, e := strconv.Atoi(strings.TrimSuffix(filepath.Base(p), ".jsonl"))
		if e != nil {
			return nil, e
		}
		l.index = n
	}
	if len(files) > 0 {
		st, e := os.Stat(files[len(files)-1])
		if e != nil {
			return nil, e
		}
		l.size = st.Size()
	}
	return l, nil
}
func (l *Log) Append(messageType string, body any) (Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var entry Entry
	if l.failed != nil {
		return entry, l.failed
	}
	if !allowed(messageType) {
		return entry, errors.New("unknown message type")
	}
	b, e := wire.Canonical(body)
	if e != nil {
		return entry, e
	}
	u := unsigned{l.seq + 1, time.Now().UTC().Format(time.RFC3339Nano), messageType, b, l.prev}
	raw, e := wire.Canonical(u)
	if e != nil {
		return entry, e
	}
	entry = Entry{u.Seq, u.Time, u.MessageType, u.Body, u.PrevHash, hex.EncodeToString(ed25519.Sign(l.private, raw))}
	line, e := wire.Canonical(entry)
	if e != nil {
		return entry, e
	}
	if _, e = ValidateRaw(line, l.private.Public().(ed25519.PublicKey)); e != nil {
		return Entry{}, e
	}
	if l.size+int64(len(line)+1) > RotationBytes && l.size > 0 {
		l.index++
		l.size = 0
	}
	path := filepath.Join(l.dir, fmt.Sprintf("%06d.jsonl", l.index))
	newRotation := l.size == 0
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if e != nil {
		return Entry{}, e
	}
	_, e = f.Write(append(line, '\n'))
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		l.failed = e
		return Entry{}, e
	}
	if ce != nil {
		l.failed = ce
		return Entry{}, ce
	}
	if newRotation {
		if e = l.syncDir(l.dir); e != nil {
			l.failed = e
			return Entry{}, e
		}
	}
	if newRotation {
		l.rotations = append(l.rotations, rotation{l.seq + 1, path})
	}
	l.size += int64(len(line) + 1)
	l.seq++
	h := sha256.Sum256(line)
	l.prev = hex.EncodeToString(h[:])
	l.last = entry
	return entry, nil
}
func (l *Log) Sequence() uint64 { l.mu.Lock(); defer l.mu.Unlock(); return l.seq }
func syncDirectory(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Read starts at the matching rotation, or at the previous read's byte offset.
// History memory is bounded by the number of rotations, not entries.
func (l *Log) Read(seq uint64) (Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if seq == 0 || seq > l.seq {
		return Entry{}, errors.New("audit sequence out of range")
	}
	if seq == l.seq {
		return l.last, nil
	}
	n := sort.Search(len(l.rotations), func(i int) bool { return l.rotations[i].first > seq }) - 1
	if n < 0 {
		return Entry{}, errors.New("audit rotation missing")
	}
	r := l.rotations[n]
	start, offset := r.first, int64(0)
	if l.cursor.seq+1 == seq && l.cursor.path == r.path {
		start, offset = seq, l.cursor.offset
	}
	f, err := os.Open(r.path)
	if err != nil {
		return Entry{}, err
	}
	defer f.Close()
	if _, err = f.Seek(offset, io.SeekStart); err != nil {
		return Entry{}, err
	}
	reader := bufio.NewReader(f)
	for current := start; current <= seq; current++ {
		line, readErr := reader.ReadBytes('\n')
		if readErr != nil {
			return Entry{}, readErr
		}
		offset += int64(len(line))
		if current == seq {
			var entry Entry
			if err = json.Unmarshal(line[:len(line)-1], &entry); err != nil {
				return Entry{}, err
			}
			l.cursor = cursor{seq, r.path, offset}
			return entry, nil
		}
	}
	return Entry{}, errors.New("audit sequence missing")
}
func allowed(s string) bool {
	for _, x := range strings.Fields("inventory description receipt canary_result revocation_ack offer_ack prepare_ack error") {
		if x == s {
			return true
		}
	}
	return false
}

// Entries returns the durable log in sequence order. It never removes entries.
func (l *Log) Entries() ([]Entry, error) {
	var entries []Entry
	err := l.Walk(func(entry Entry) error { entries = append(entries, entry); return nil })
	return entries, err
}

// Walk streams the durable log without materializing its history.
func (l *Log) Walk(visit func(Entry) error) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	files, err := filepath.Glob(filepath.Join(l.dir, "*.jsonl"))
	if err != nil {
		return err
	}
	sort.Strings(files)
	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		s := bufio.NewScanner(f)
		s.Buffer(make([]byte, 64*1024), 2<<20)
		for s.Scan() {
			var entry Entry
			if err = json.Unmarshal(s.Bytes(), &entry); err != nil {
				break
			}
			if err = visit(entry); err != nil {
				break
			}
		}
		if err == nil {
			err = s.Err()
		}
		f.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func Hash(e Entry) (string, error) {
	b, err := wire.Canonical(e)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

// ValidateRaw applies the six-field canonical wire rule before signature checks.
func ValidateRaw(raw []byte, public ed25519.PublicKey) (Entry, error) {
	var entry Entry
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, err := value(d)
	if err != nil {
		return entry, err
	}
	if _, err = d.Token(); err != io.EOF {
		return entry, errors.New("trailing audit JSON")
	}
	fields, ok := v.(map[string]any)
	if !ok || len(fields) != 6 {
		return entry, errors.New("audit entry needs six fields")
	}
	for _, key := range []string{"seq", "time", "message_type", "body", "prev_hash", "sig"} {
		if _, ok := fields[key]; !ok {
			return entry, errors.New("missing audit field")
		}
	}
	canonical, err := wire.Canonical(v)
	if err != nil || !bytes.Equal(canonical, raw) {
		return entry, errors.New("noncanonical audit JSON")
	}
	if err = json.Unmarshal(raw, &entry); err != nil {
		return entry, err
	}
	if entry.Seq == 0 || entry.MessageType == "" {
		return entry, errors.New("invalid audit entry")
	}
	unsignedRaw, err := wire.Canonical(unsigned{entry.Seq, entry.Time, entry.MessageType, entry.Body, entry.PrevHash})
	if err != nil {
		return entry, err
	}
	sig, err := hex.DecodeString(entry.Sig)
	if err != nil || !ed25519.Verify(public, unsignedRaw, sig) {
		return entry, errors.New("invalid audit signature")
	}
	return entry, nil
}

func value(d *json.Decoder) (any, error) {
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := t.(json.Delim); ok {
		switch delim {
		case '{':
			m := map[string]any{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return nil, err
				}
				name, ok := key.(string)
				if !ok {
					return nil, errors.New("non-string key")
				}
				if _, exists := m[name]; exists {
					return nil, errors.New("duplicate key")
				}
				m[name], err = value(d)
				if err != nil {
					return nil, err
				}
			}
			_, err := d.Token()
			return m, err
		case '[':
			a := []any{}
			for d.More() {
				v, err := value(d)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			_, err := d.Token()
			return a, err
		}
		return nil, errors.New("unexpected delimiter")
	}
	if n, ok := t.(json.Number); ok {
		s := string(n)
		if s == "-0" || strings.ContainsAny(s, ".eE+") || (len(s) > 1 && s[0] == '0') || (len(s) > 2 && s[:2] == "-0") {
			return nil, errors.New("noninteger audit number")
		}
		if _, err := strconv.ParseInt(s, 10, 64); err != nil {
			return nil, err
		}
	}
	return t, nil
}
