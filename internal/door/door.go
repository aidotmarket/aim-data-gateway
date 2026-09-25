package door

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/config"
	"github.com/aidotmarket/aim-data-gateway/internal/inventory"
	"github.com/aidotmarket/aim-data-gateway/internal/ledger"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
)

type Door struct {
	Ledger                *ledger.Ledger
	Config                func() config.Config
	GatewayID             string
	PermissionKeys        map[string]ed25519.PublicKey
	PermissionKeyProvider func() map[string]ed25519.PublicKey
	GatewayKey            ed25519.PrivateKey
	GatewayKID            string
	Limit                 int
	sem                   chan struct{}
}

func (d *Door) Handler() http.Handler {
	n := d.Limit
	if n <= 0 {
		if d.Config != nil {
			n = d.Config().Door.MaxConcurrentDownloads
		}
		if n <= 0 {
			n = 8
		}
	}
	d.sem = make(chan struct{}, n)
	return http.HandlerFunc(d.serve)
}
func (d *Door) Server(addr string) *http.Server {
	return &http.Server{Addr: addr, Handler: d.Handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
}
func HealthServer() *http.Server {
	return &http.Server{Addr: "127.0.0.1:8081", Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		if r.Method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "ok\n")
	}), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
}
func fail(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": code, "message": strings.ReplaceAll(code, "_", " "), "details": map[string]any{}}})
}

var fidRE = regexp.MustCompile(`^[0-9a-f]{32}$`)
var nonceRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

func (d *Door) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "GET" {
		fail(w, 405, "method_not_allowed")
		return
	}
	if r.URL.Path == "/.well-known/aim-gateway" {
		d.statement(w, r)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/v1/files/") {
		fail(w, 404, "not_found")
		return
	}
	fid := strings.TrimPrefix(r.URL.Path, "/v1/files/")
	if !fidRE.MatchString(fid) {
		fail(w, 404, "not_found")
		return
	}
	select {
	case d.sem <- struct{}{}:
		defer func() { <-d.sem }()
	default:
		fail(w, 503, "busy")
		return
	}
	d.download(w, r, fid)
}
func (d *Door) statement(w http.ResponseWriter, r *http.Request) {
	nonce := r.URL.Query().Get("nonce")
	if !nonceRE.MatchString(nonce) {
		fail(w, 400, "invalid_nonce")
		return
	}
	token, e := wire.Sign("aim-door+jwt", d.GatewayKID, struct {
		GatewayID string `json:"gid"`
		Nonce     string `json:"nonce"`
		IssuedAt  int64  `json:"iat"`
	}{d.GatewayID, nonce, time.Now().Unix()}, d.GatewayKey)
	if e != nil {
		fail(w, 500, "internal_error")
		return
	}
	w.Header().Set("Content-Type", "application/jose")
	io.WriteString(w, token)
}
func token(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	hasHeader := h != ""
	if h != "" {
		if !strings.HasPrefix(h, "Bearer ") || strings.TrimPrefix(h, "Bearer ") == "" {
			return "", errors.New("invalid bearer")
		}
		h = strings.TrimPrefix(h, "Bearer ")
	}
	values, hasQuery := r.URL.Query()["t"]
	if hasQuery && len(values) != 1 {
		return "", errors.New("duplicate token")
	}
	q := ""
	if hasQuery {
		q = values[0]
	}
	if hasHeader && hasQuery && h != q {
		return "", errors.New("tokens differ")
	}
	if h != "" {
		return h, nil
	}
	if q != "" {
		return q, nil
	}
	return "", errors.New("missing token")
}
func parseRange(s string, size int64) (int64, int64, bool, error) {
	if size <= 0 {
		return 0, 0, false, errors.New("empty file")
	}
	if s == "" {
		return 0, size - 1, false, nil
	}
	if !strings.HasPrefix(s, "bytes=") || strings.Contains(s, ",") {
		return 0, 0, false, errors.New("invalid range")
	}
	v := strings.TrimPrefix(s, "bytes=")
	a, b, ok := strings.Cut(v, "-")
	if !ok {
		return 0, 0, false, errors.New("invalid range")
	}
	if a == "" {
		n, e := strconv.ParseInt(b, 10, 64)
		if e != nil || n <= 0 {
			return 0, 0, false, errors.New("invalid suffix")
		}
		return max(0, size-n), size - 1, true, nil
	}
	start, e := strconv.ParseInt(a, 10, 64)
	if e != nil || start < 0 || start >= size {
		return 0, 0, false, errors.New("invalid start")
	}
	end := size - 1
	if b != "" {
		end, e = strconv.ParseInt(b, 10, 64)
		if e != nil || end < start {
			return 0, 0, false, errors.New("invalid end")
		}
		end = min(end, size-1)
	}
	return start, end, true, nil
}
func (d *Door) download(w http.ResponseWriter, r *http.Request, fid string) {
	ctx := r.Context()
	raw, e := token(r)
	if e != nil {
		fail(w, 401, "invalid_permission")
		return
	}
	keys := d.PermissionKeys
	if d.PermissionKeyProvider != nil {
		keys = d.PermissionKeyProvider()
	}
	p, e := wire.VerifyPermission(raw, keys)
	if e != nil {
		fail(w, 401, "invalid_permission")
		return
	}
	if p.Audience != d.GatewayID {
		fail(w, 403, "wrong_audience")
		return
	}
	if p.FileID != fid {
		fail(w, 403, "wrong_file")
		return
	}
	o, e := d.Ledger.Offer(ctx, fid, p.SHA256, p.ListingVersionID)
	if e != nil && e != sql.ErrNoRows {
		fail(w, 500, "internal_error")
		return
	}
	// The bound exception is read only to decide whether withdrawal still permits this offer.
	state, stateErr := d.Ledger.Permission(ctx, p.JTI)
	bound := stateErr == nil && state.State == "bound" && state.OrderID == p.OrderID && state.FileID == fid && state.SHA256 == p.SHA256
	if stateErr != nil && stateErr != sql.ErrNoRows {
		fail(w, 500, "internal_error")
		return
	}
	if !bound && (e == sql.ErrNoRows || o.State != "offered" || o.KeyClass != "listing") {
		fail(w, 403, "not_offered")
		return
	}
	f, e := d.Ledger.File(ctx, fid)
	if e != nil {
		fail(w, 404, "file_missing")
		return
	}
	if f.Changed || f.SHA256 != p.SHA256 || !f.ValidBlocks() {
		fail(w, 409, "file_changed")
		return
	}
	c := d.Config()
	if !ledger.WithinCeiling(c, f) {
		fail(w, 403, "outside_ceiling")
		return
	}
	if c.OfferRequiresLocalApproval && !o.ApprovedAt.Valid {
		fail(w, 403, "awaiting_local_approval")
		return
	}
	now := time.Now().Unix()
	if now >= p.TransferDeadline || (!bound && now >= p.StartDeadline) {
		_ = d.Ledger.CloseExpired(ctx, now)
		fail(w, 403, "permission_expired")
		return
	}
	if stateErr == nil && (state.State == "closed" || state.State == "revoked" || state.OrderID != p.OrderID || state.FileID != fid || state.SHA256 != p.SHA256) {
		fail(w, 403, "permission_closed")
		return
	}
	if f.Size == 0 && r.Header.Get("Range") == "" {
		root, e := os.OpenRoot(f.Root)
		if e != nil {
			fail(w, 404, "file_missing")
			return
		}
		defer root.Close()
		file, e := root.Open(f.RelativePath)
		if e != nil {
			fail(w, 404, "file_missing")
			return
		}
		defer file.Close()
		st, e := file.Stat()
		if e != nil || !st.Mode().IsRegular() || st.Size() != 0 {
			fail(w, 409, "file_changed")
			return
		}
		if e = d.Ledger.FinishEmpty(ctx, p); e != nil {
			fail(w, 403, "permission_closed")
			return
		}
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", safeName(f.DisplayName)))
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(200)
		return
	}
	start, end, partial, e := parseRange(r.Header.Get("Range"), f.Size)
	if e != nil {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", f.Size))
		fail(w, 416, "invalid_range")
		return
	}
	// First bind and reservation commit together before the first response byte.
	req, e := d.Ledger.Reserve(ctx, p, start, end)
	if e != nil {
		code := "internal_error"
		status := 500
		switch e {
		case ledger.ErrFragmented:
			code = "coverage_fragmented"
			status = 409
		case ledger.ErrExhausted:
			code = "coverage_exhausted"
			status = 409
		case ledger.ErrClosed:
			code = "permission_closed"
			status = 403
		case ledger.ErrDeadline:
			code = "permission_expired"
			status = 403
		}
		fail(w, status, code)
		return
	}
	outcome := ""
	settle := true
	defer func() {
		if settle {
			_ = d.Ledger.SettleOutcome(context.Background(), req.ID, outcome)
		} else {
			// A failed terminal checkpoint must not strand an open request until
			// restart. Retry conservative crash settlement after transient DB errors.
			go func() {
				for {
					if d.Ledger.RecoverRequest(context.Background(), req.ID) == nil {
						return
					}
					time.Sleep(time.Second)
				}
			}()
		}
	}()
	end = req.End
	partial = partial || start != 0 || end != f.Size-1
	root, e := os.OpenRoot(f.Root)
	if e != nil {
		fail(w, 404, "file_missing")
		return
	}
	defer root.Close()
	file, e := root.Open(f.RelativePath)
	if e != nil {
		fail(w, 404, "file_missing")
		return
	}
	defer file.Close()
	st, e := file.Stat()
	if e != nil || !st.Mode().IsRegular() {
		fail(w, 404, "file_missing")
		return
	}
	buf := make([]byte, inventory.BlockSize)
	readBlock := func(pos int64) (int64, int, bool) {
		index := int(pos / inventory.BlockSize)
		blockStart := int64(index) * inventory.BlockSize
		blockLen := int(min(int64(inventory.BlockSize), f.Size-blockStart))
		n, readErr := file.ReadAt(buf[:blockLen], blockStart)
		return blockStart, blockLen, (readErr == nil || readErr == io.EOF) && n == blockLen && index < len(f.BlockHashes) && sha256.Sum256(buf[:blockLen]) == f.BlockHashes[index]
	}
	blockStart, blockLen, ok := readBlock(start)
	if !ok {
		_ = d.Ledger.MarkChanged(context.Background(), fid)
		outcome = "aborted_block_mismatch"
		fail(w, 409, "file_changed")
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Unix(p.TransferDeadline, 0))
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", safeName(f.DisplayName)))
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
	if partial {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, f.Size))
	}
	committed := false
	for pos := start; pos <= end; {
		if pos >= blockStart+int64(blockLen) {
			blockStart, blockLen, ok = readBlock(pos)
			if !ok {
				_ = d.Ledger.MarkChanged(context.Background(), fid)
				outcome = "aborted_block_mismatch"
				return
			}
		}
		lo := int(pos - blockStart)
		hi := int(min(int64(blockLen), end-blockStart+1))
		for lo < hi {
			n, e := d.Ledger.WriteChunk(ctx, req.ID, buf[lo:hi], func(b []byte) (int, error) {
				if !committed {
					if partial {
						w.WriteHeader(206)
					}
					committed = true
				}
				return w.Write(b)
			})
			if n > 0 {
				lo += n
				pos += int64(n)
			}
			if errors.Is(e, ledger.ErrDeadline) {
				outcome = "aborted_deadline"
			}
			if errors.Is(e, ledger.ErrProgress) {
				settle = false
			}
			if e != nil || n == 0 {
				if !committed && (errors.Is(e, ledger.ErrClosed) || errors.Is(e, ledger.ErrDeadline)) {
					w.Header().Del("Content-Length")
					w.Header().Del("Content-Range")
					if errors.Is(e, ledger.ErrDeadline) {
						fail(w, 403, "permission_expired")
					} else {
						fail(w, 403, "permission_closed")
					}
				}
				return
			}
		}
	}
}
func safeName(s string) string {
	s = filepath.Base(s)
	s = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '"' || r == '\\' || r < 32 {
			return -1
		}
		return r
	}, s)
	if s == "" || s == "." {
		return "download"
	}
	return s
}
