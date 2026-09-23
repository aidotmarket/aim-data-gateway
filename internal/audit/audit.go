package audit

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	mu      sync.Mutex
	dir     string
	private ed25519.PrivateKey
	seq     uint64
	prev    string
	index   int
	size    int64
}

func Open(dir string, private ed25519.PrivateKey) (*Log, error) {
	if len(private) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid key")
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	l := &Log{dir: dir, private: private}
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
		for sc.Scan() {
			var entry Entry
			if e = json.Unmarshal(sc.Bytes(), &entry); e != nil {
				f.Close()
				return nil, e
			}
			if entry.Seq != l.seq+1 || entry.PrevHash != l.prev {
				f.Close()
				return nil, errors.New("audit chain broken")
			}
			raw, e := wire.Canonical(unsigned{entry.Seq, entry.Time, entry.MessageType, entry.Body, entry.PrevHash})
			sig, e2 := hex.DecodeString(entry.Sig)
			if e != nil || e2 != nil || !ed25519.Verify(private.Public().(ed25519.PublicKey), raw, sig) {
				f.Close()
				return nil, errors.New("audit signature invalid")
			}
			h := sha256.Sum256(sc.Bytes())
			l.prev = hex.EncodeToString(h[:])
			l.seq++
		}
		e = sc.Err()
		f.Close()
		if e != nil {
			return nil, e
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
	if l.size+int64(len(line)+1) > RotationBytes && l.size > 0 {
		l.index++
		l.size = 0
	}
	path := filepath.Join(l.dir, fmt.Sprintf("%06d.jsonl", l.index))
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
		return Entry{}, e
	}
	if ce != nil {
		return Entry{}, ce
	}
	l.size += int64(len(line) + 1)
	l.seq++
	h := sha256.Sum256(line)
	l.prev = hex.EncodeToString(h[:])
	return entry, nil
}
func allowed(s string) bool {
	for _, x := range strings.Fields("hello inventory description receipt canary_result revocation_ack offer_ack prepare_ack error") {
		if x == s {
			return true
		}
	}
	return false
}
