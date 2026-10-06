package cloudflareverification

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/wire"
)

type Audit interface {
	Event(context.Context, string, string) error
}
type Service struct {
	Audit                     Audit
	Release, Version, Binary  string
	BackendClient, BridgeHTTP *http.Client
	busy                      atomic.Bool
	Now                       func() time.Time
}
type Invocation struct {
	Config     Config  `json:"config"`
	Secret     *Secret `json:"secret"`
	Token      string  `json:"token"`
	Snapshot   string  `json:"snapshot"`
	Capability string  `json:"capability"`
	Start      int64   `json:"start"`
	Pickup     int64   `json:"pickup"`
}
type Prepared struct {
	Job      wire.ScanJob `json:"job"`
	Snapshot string       `json:"snapshot"`
	Objects  []Object     `json:"objects"`
}
type memoryStore struct{}

func (memoryStore) Load(context.Context) (*Secret, error) { return nil, ErrRefused }
func (memoryStore) Save(context.Context, *Secret) error   { return nil }
func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == "GET" && r.URL.Path == "/health" {
		w.WriteHeader(200)
		return
	}
	if r.Method != "POST" || r.URL.RawQuery != "" {
		http.Error(w, "verification_refused", 403)
		return
	}
	if !s.busy.CompareAndSwap(false, true) {
		http.Error(w, "verification_refused", 409)
		return
	}
	defer s.busy.Store(false)
	var in Invocation
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 18<<20))
	dec.DisallowUnknownFields()
	if e := dec.Decode(&in); e != nil {
		http.Error(w, "verification_refused", 403)
		return
	}
	var extra any
	if dec.Decode(&extra) != io.EOF || in.Config.Validate() != nil || in.Config.Release != s.Release || in.Config.Version != s.Version || in.Config.Binary != s.Binary {
		http.Error(w, "verification_refused", 403)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 890*time.Second)
	defer cancel()
	result, e := s.invoke(ctx, r.URL.Path, in)
	if e != nil {
		http.Error(w, "verification_refused", 403)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
func (s *Service) invoke(ctx context.Context, path string, in Invocation) (any, error) {
	c := in.Config
	b := HTTPBackend{Config: c, Client: s.BackendClient, Now: s.Now}
	if path == "/create" {
		if !validToken(c.Token) {
			return nil, ErrRefused
		}
		return CreateSecret(c, s.now())
	}
	sec := in.Secret
	if sec == nil || sec.validate(c) != nil {
		return nil, ErrRefused
	}
	if path == "/register" {
		if e := Register(ctx, c, sec, b); e != nil {
			return nil, e
		}
		return sec, nil
	}
	if sec.Runner == "" {
		return nil, ErrRefused
	}
	if path == "/prepare" {
		if Rotate(ctx, memoryStore{}, sec, in.Token, s.now()) == nil {
			return map[string]any{"secret": sec, "rotation": true}, nil
		}
	}
	verifyAt := s.now()
	if path == "/terminal" {
		verifyAt = time.Unix(in.Pickup, 0)
	}
	j, e := VerifyWork(in.Token, sec.keys(s.now()), sec.Runner, sec.Runner, c.Version, verifyAt)
	if e != nil {
		return nil, ErrRefused
	}
	j.ScannerVersion, j.ReceiptKeyID = c.Version, sec.Receipt
	if path == "/terminal" {
		if in.Pickup <= 0 || s.now().Unix() > in.Pickup+CF_VERIFY_TERMINAL_DEADLINE_SECONDS {
			return nil, ErrRefused
		}
		body, e := encodeReport(sec, j, "terminal", terminal(j, "scanner_failure", s.now()), nil)
		return map[string]any{"body": string(body)}, e
	}
	snapshot := in.Snapshot
	if path == "/prepare" {
		snapshot, e = b.Snapshot(ctx, sec, j.Text("manifest_hash"))
		if e != nil {
			return nil, e
		}
	}
	objects, e := Snapshot(snapshot, sec.keys(s.now()), j, c)
	if e != nil {
		return nil, e
	}
	// Fetching a snapshot must not refresh consent or cross expiry.
	if _, e = VerifyWork(in.Token, sec.keys(s.now()), sec.Runner, sec.Runner, c.Version, s.now()); e != nil {
		return nil, e
	}
	if path == "/prepare" {
		return Prepared{Job: j, Snapshot: snapshot, Objects: objects}, nil
	}
	if path != "/execute" || in.Start <= 0 || in.Pickup <= 0 || !validTokenPart(in.Capability) {
		return nil, ErrRefused
	}
	deadline := time.Unix(in.Start, 0).Add(CF_VERIFY_DEADLINE_SECONDS * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Add(-30*time.Second).Before(deadline) {
		deadline = d.Add(-30 * time.Second)
	}
	if !s.now().Before(deadline) || s.now().Unix() > in.Pickup+CF_VERIFY_TERMINAL_DEADLINE_SECONDS {
		return nil, ErrRefused
	}
	scanCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	src, e := NewSource(HTTPBridge{Client: s.BridgeHTTP, Capability: in.Capability}, c.Bucket, objects)
	if e != nil {
		return nil, e
	}
	if s.Audit != nil && s.Audit.Event(ctx, "accepted", j.Envelope.SpecHash) != nil {
		return nil, ErrRefused
	}
	body, e := (Handler{Config: c, Now: s.Now}).scan(scanCtx, sec, j, src)
	return map[string]any{"body": string(body)}, e
}
