package door

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/config"
	"github.com/aidotmarket/aim-data-gateway/internal/inventory"
	"github.com/aidotmarket/aim-data-gateway/internal/ledger"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
)

type brokenWriter struct {
	header    http.Header
	remaining int
	status    int
}

func (w *brokenWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}
func (w *brokenWriter) WriteHeader(s int) { w.status = s }
func (w *brokenWriter) Write(b []byte) (int, error) {
	if w.remaining == 0 {
		return 0, errors.New("disconnected")
	}
	n := min(w.remaining, len(b))
	w.remaining -= n
	return n, errors.New("disconnected")
}

const fileID = "0123456789abcdef0123456789abcdef"
const orderID = "22222222-2222-4222-8222-222222222222"
const listingID = "33333333-3333-4333-8333-333333333333"
const gatewayID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

func setup(t *testing.T) (*Door, wire.Permission, ed25519.PrivateKey, string) {
	t.Helper()
	root := t.TempDir()
	data := []byte("abcdefghij")
	if e := os.WriteFile(filepath.Join(root, "data.bin"), data, 0600); e != nil {
		t.Fatal(e)
	}
	hash := sha256.Sum256(data)
	db := filepath.Join(t.TempDir(), "gateway.db")
	gatewayKey := ed25519.NewKeyFromSeed([]byte(strings.Repeat("B", 32)))
	l, e := ledger.Open(db, gatewayKey, "gateway")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	r := inventory.Record{Phase1: inventory.Phase1{FileID: fileID, DisplayName: "data.bin", SizeBytes: int64(len(data))}, Source: "source", RelativePath: "data.bin", Root: root, SHA256: hash, BlockHashes: [][32]byte{hash}, Mtime: time.Now()}
	if e = l.PutFile(t.Context(), r); e != nil {
		t.Fatal(e)
	}
	if e = l.PutOffer(t.Context(), ledger.Offer{FileID: fileID, SHA256: hex.EncodeToString(hash[:]), ListingVersionID: listingID, IID: orderID, State: "offered", KeyClass: "listing"}); e != nil {
		t.Fatal(e)
	}
	permissionKey := ed25519.NewKeyFromSeed([]byte(strings.Repeat("P", 32)))
	p := wire.Permission{Audience: gatewayID, OrderID: orderID, ListingVersionID: listingID, FileID: fileID, SHA256: hex.EncodeToString(hash[:]), JTI: "44444444-4444-4444-8444-444444444444", IssuedAt: time.Now().Unix() - 1, StartDeadline: time.Now().Unix() + 60, TransferDeadline: time.Now().Unix() + 3600}
	d := &Door{Ledger: l, Config: func() config.Config { return config.Config{} }, GatewayID: gatewayID, PermissionKeys: map[string]ed25519.PublicKey{"permission": permissionKey.Public().(ed25519.PublicKey)}, GatewayKey: gatewayKey, GatewayKID: "gateway"}
	return d, p, permissionKey, root
}
func call(t *testing.T, h http.Handler, p wire.Permission, key ed25519.PrivateKey, method, rangeValue, kind string) *httptest.ResponseRecorder {
	t.Helper()
	token, e := wire.Sign("aim-permission+jwt", "permission", p, key)
	if e != nil {
		t.Fatal(e)
	}
	url := "/v1/files/" + fileID
	if kind == "query" || kind == "both" || kind == "mismatch" {
		url += "?t=" + token
	}
	r := httptest.NewRequest(method, url, nil)
	if kind == "header" || kind == "both" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if kind == "mismatch" {
		r.Header.Set("Authorization", "Bearer other")
	}
	if rangeValue != "" {
		r.Header.Set("Range", rangeValue)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestRangesAndPermissionClosure(t *testing.T) {
	d, p, key, _ := setup(t)
	h := d.Handler()
	w := call(t, h, p, key, "GET", "bytes=0-2", "header")
	if w.Code != 206 || w.Body.String() != "abc" {
		t.Fatalf("first range: %d %q", w.Code, w.Body.String())
	}
	w = call(t, h, p, key, "GET", "bytes=-3", "query")
	if w.Code != 206 || w.Body.String() != "hij" {
		t.Fatalf("suffix: %d %q", w.Code, w.Body.String())
	}
	w = call(t, h, p, key, "GET", "bytes=3-", "both")
	if w.Code != 206 || w.Body.String() != "defghij" {
		t.Fatalf("open-ended: %d %q", w.Code, w.Body.String())
	}
	w = call(t, h, p, key, "GET", "bytes=0-0", "header")
	if w.Code != 403 {
		t.Fatalf("closed permission: %d", w.Code)
	}
	var n int
	if e := d.Ledger.DB.QueryRow(`SELECT count(*) FROM receipts_outbox`).Scan(&n); e != nil || n != 4 {
		t.Fatalf("receipt count %d, %v", n, e)
	}
}
func TestDoorRefusalsAndNoCORS(t *testing.T) {
	d, p, key, root := setup(t)
	h := d.Handler()
	for _, tc := range []struct {
		method, rangeValue, kind string
		want                     int
	}{{"OPTIONS", "", "header", 405}, {"GET", "bytes=0-1,3-4", "header", 416}, {"GET", "", "mismatch", 401}, {"GET", "bytes=0-0", "query", 206}} {
		w := call(t, h, p, key, tc.method, tc.rangeValue, tc.kind)
		if w.Code != tc.want {
			t.Fatalf("%+v: %d %s", tc, w.Code, w.Body.String())
		}
		for k := range w.Header() {
			if strings.HasPrefix(strings.ToLower(k), "access-control-") {
				t.Fatal("CORS header", k)
			}
		}
	}
	p.JTI = "55555555-5555-4555-8555-555555555555"
	p.Audience = orderID
	if w := call(t, h, p, key, "GET", "", "header"); w.Code != 403 {
		t.Fatalf("audience: %d", w.Code)
	}
	p.Audience = gatewayID
	p.IssuedAt = time.Now().Unix() - 100
	p.StartDeadline = time.Now().Unix() - 1
	if w := call(t, h, p, key, "GET", "", "header"); w.Code != 403 {
		t.Fatalf("sd: %d", w.Code)
	}
	p.StartDeadline = time.Now().Unix() - 2
	p.TransferDeadline = time.Now().Unix() - 1
	if w := call(t, h, p, key, "GET", "", "header"); w.Code != 403 {
		t.Fatalf("td claims: %d", w.Code)
	}
	p.TransferDeadline = time.Now().Unix() + 3600
	p.StartDeadline = time.Now().Unix() + 60
	d.Config = func() config.Config { return config.Config{OfferCeiling: []string{"other/*"}} }
	if w := call(t, h, p, key, "GET", "", "header"); w.Code != 403 {
		t.Fatalf("ceiling: %d", w.Code)
	}
	d.Config = func() config.Config { return config.Config{} }
	st, e := os.Stat(filepath.Join(root, "data.bin"))
	if e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(root, "data.bin"), []byte("abcdEfghij"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Chtimes(filepath.Join(root, "data.bin"), st.ModTime(), st.ModTime()); e != nil {
		t.Fatal(e)
	}
	if w := call(t, h, p, key, "GET", "bytes=5-7", "header"); w.Code != 409 || !strings.Contains(w.Body.String(), "file_changed") {
		t.Fatalf("mismatch response: %d %q", w.Code, w.Body.String())
	}
}

func TestUnofferAfterBindAndWrongKey(t *testing.T) {
	d, p, key, _ := setup(t)
	h := d.Handler()
	wrong := ed25519.NewKeyFromSeed([]byte(strings.Repeat("X", 32)))
	if w := call(t, h, p, wrong, "GET", "bytes=0-0", "header"); w.Code != 401 {
		t.Fatalf("wrong key %d", w.Code)
	}
	if w := call(t, h, p, key, "GET", "bytes=0-0", "header"); w.Code != 206 {
		t.Fatalf("first bind %d", w.Code)
	}
	if e := d.Ledger.PutOffer(t.Context(), ledger.Offer{FileID: fileID, SHA256: p.SHA256, ListingVersionID: listingID, IID: orderID, State: "withdrawn", KeyClass: "listing"}); e != nil {
		t.Fatal(e)
	}
	if w := call(t, h, p, key, "GET", "bytes=1-1", "header"); w.Code != 206 {
		t.Fatalf("bound after unoffer %d", w.Code)
	}
	p.JTI = "66666666-6666-4666-8666-666666666666"
	if w := call(t, h, p, key, "GET", "bytes=2-2", "header"); w.Code != 403 {
		t.Fatalf("new bind after unoffer %d", w.Code)
	}
}

func TestUnofferedAndWrongOfferKeyClass(t *testing.T) {
	d, p, key, _ := setup(t)
	h := d.Handler()
	_, e := d.Ledger.DB.Exec(`DELETE FROM offers`)
	if e != nil {
		t.Fatal(e)
	}
	if w := call(t, h, p, key, "GET", "bytes=0-0", "header"); w.Code != 403 {
		t.Fatalf("unoffered: %d", w.Code)
	}
	if e = d.Ledger.PutOffer(t.Context(), ledger.Offer{FileID: fileID, SHA256: p.SHA256, ListingVersionID: listingID, IID: orderID, State: "offered", KeyClass: "permission"}); e != nil {
		t.Fatal(e)
	}
	if w := call(t, h, p, key, "GET", "bytes=0-0", "header"); w.Code != 403 {
		t.Fatalf("wrong offer key class: %d", w.Code)
	}
}

func TestDisconnectedResponsesDoNotComplete(t *testing.T) {
	d, p, key, _ := setup(t)
	h := d.Handler()
	tok, e := wire.Sign("aim-permission+jwt", "permission", p, key)
	if e != nil {
		t.Fatal(e)
	}
	for index, limit := range []int{0, 5} {
		r := httptest.NewRequest("GET", "/v1/files/"+fileID, nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		w := &brokenWriter{remaining: limit}
		h.ServeHTTP(w, r)
		var n int
		if e = d.Ledger.DB.QueryRow(`SELECT count(*) FROM receipts_outbox`).Scan(&n); e != nil {
			t.Fatal(e)
		}
		if n != index*2 {
			t.Fatalf("unexpected early receipt count %d", n)
		}
	}
	w := call(t, h, p, key, "GET", "bytes=5-", "header")
	if w.Code != 206 || w.Body.String() != "fghij" {
		t.Fatalf("resume %d %q", w.Code, w.Body.String())
	}
	var n int
	if e = d.Ledger.DB.QueryRow(`SELECT count(*) FROM receipts_outbox`).Scan(&n); e != nil {
		t.Fatal(e)
	}
	if n != 4 {
		t.Fatalf("outbox rows %d", n)
	}
}

func TestStatementAndHealthSeparation(t *testing.T) {
	d, _, _, _ := setup(t)
	h := d.Handler()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/.well-known/aim-gateway?nonce=0123456789abcdef0123456789abcdef", nil))
	if w.Code != 200 || strings.Count(w.Body.String(), ".") != 2 {
		t.Fatalf("statement %d %q", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/healthz", nil))
	if w.Code != 404 {
		t.Fatalf("public health %d", w.Code)
	}
	w = httptest.NewRecorder()
	HealthServer().Handler.ServeHTTP(w, httptest.NewRequest("GET", "/healthz", nil))
	if w.Code != 200 {
		t.Fatalf("private health %d", w.Code)
	}
}

func TestGLM6DeepSeek2OfferPrecedesJTIAndFileCode(t *testing.T) {
	d, p, key, _ := setup(t)
	h := d.Handler()
	p.FileID = "ffffffffffffffffffffffffffffffff"
	w := call(t, h, p, key, "GET", "", "header")
	if w.Code != 403 || !strings.Contains(w.Body.String(), "wrong_file") {
		t.Fatalf("fid: %d %s", w.Code, w.Body.String())
	}
	p.FileID = fileID
	_, e := d.Ledger.DB.Exec(`INSERT INTO permissions(jti,oid,fid,sha256,sd,td,ro,state) VALUES(?,?,?,?,?,?,?,'closed')`, p.JTI, p.OrderID, p.FileID, p.SHA256, p.StartDeadline, p.TransferDeadline, 0)
	if e != nil {
		t.Fatal(e)
	}
	_, e = d.Ledger.DB.Exec(`DELETE FROM offers`)
	if e != nil {
		t.Fatal(e)
	}
	w = call(t, h, p, key, "GET", "", "header")
	if w.Code != 403 || !strings.Contains(w.Body.String(), "not_offered") {
		t.Fatalf("offer precedence: %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "message") || !strings.Contains(w.Body.String(), "details") {
		t.Fatalf("error shape: %s", w.Body.String())
	}
}

func TestGLM7Gemini3DeepSeek1FirstBlockMismatchIs409(t *testing.T) {
	for _, rng := range []string{"", "bytes=5-7"} {
		t.Run(rng, func(t *testing.T) {
			d, p, key, root := setup(t)
			if e := os.WriteFile(filepath.Join(root, "data.bin"), []byte("abcdEfghij"), 0600); e != nil {
				t.Fatal(e)
			}
			w := call(t, d.Handler(), p, key, "GET", rng, "header")
			if w.Code != 409 || !strings.Contains(w.Body.String(), "file_changed") {
				t.Fatalf("response: %d %s", w.Code, w.Body.String())
			}
			if w.Header().Get("Content-Range") != "" || w.Header().Get("Content-Length") == "10" {
				t.Fatalf("success headers: %v", w.Header())
			}
			f, e := d.Ledger.File(t.Context(), fileID)
			if e != nil || !f.Changed {
				t.Fatalf("changed: %+v %v", f, e)
			}
			var body string
			if e = d.Ledger.DB.QueryRow(`SELECT body FROM receipts_outbox ORDER BY seq DESC LIMIT 1`).Scan(&body); e != nil || !strings.Contains(body, ".") {
				t.Fatalf("receipt: %v %s", e, body)
			}
		})
	}
}

func TestDeepSeek7ReofferRequiresFreshLocalApproval(t *testing.T) {
	d, p, key, _ := setup(t)
	d.Config = func() config.Config { return config.Config{OfferRequiresLocalApproval: true} }
	if e := d.Ledger.Approve(t.Context(), fileID, p.SHA256, listingID); e != nil {
		t.Fatal(e)
	}
	if e := d.Ledger.PutOffer(t.Context(), ledger.Offer{FileID: fileID, SHA256: p.SHA256, ListingVersionID: listingID, State: "withdrawn", KeyClass: "listing"}); e != nil {
		t.Fatal(e)
	}
	if e := d.Ledger.PutOffer(t.Context(), ledger.Offer{FileID: fileID, SHA256: p.SHA256, ListingVersionID: listingID, State: "offered", KeyClass: "listing"}); e != nil {
		t.Fatal(e)
	}
	w := call(t, d.Handler(), p, key, "GET", "bytes=0-0", "header")
	if w.Code != 403 || !strings.Contains(w.Body.String(), "awaiting_local_approval") {
		t.Fatalf("approval: %d %s", w.Code, w.Body.String())
	}
}

func TestGLM1Gemini1DeepSeek4ConcurrentResponsesOneJTI(t *testing.T) {
	d, p, key, _ := setup(t)
	h := d.Handler()
	start := make(chan struct{})
	results := make(chan *httptest.ResponseRecorder, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- call(t, h, p, key, "GET", "", "header")
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	complete, refused := 0, 0
	for w := range results {
		if w.Code == 200 && w.Body.String() == "abcdefghij" {
			complete++
		}
		if w.Code == 403 && strings.Contains(w.Body.String(), "permission_closed") {
			refused++
		}
	}
	if complete != 1 || refused != 1 {
		t.Fatalf("complete=%d refused=%d", complete, refused)
	}
}
