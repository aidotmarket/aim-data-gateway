package channel

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/audit"
	"github.com/aidotmarket/aim-data-gateway/internal/pairing"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	"github.com/coder/websocket"
)

func fixture(t *testing.T) (*Client, []audit.Entry) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	l, err := audit.Open(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{1, 2} {
		if _, err := l.Append("inventory", map[string]any{"generation": n, "files": []any{}}); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := l.Entries()
	if err != nil {
		t.Fatal(err)
	}
	return &Client{State: &pairing.State{Private: key, Pins: pairing.Pins{GatewayID: "11111111-1111-4111-8111-111111111111"}}, Log: l, Version: "1.0.0"}, entries
}

func TestSignedInstructionThroughChannel(t *testing.T) {
	c, _ := fixture(t)
	key := ed25519.NewKeyFromSeed(bytesRepeat(0x42, 32))
	c.State.Pins.ListingKeys = []wire.Key{{KID: "listing", Alg: "EdDSA", Key: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}}
	called := 0
	c.Handle = func(_ context.Context, i wire.Instruction, class, signer string) (string, any, error) {
		called++
		if i.Op != "offer" || class != "listing" || signer != "listing" {
			t.Errorf("wrong instruction: %+v %s %s", i, class, signer)
		}
		return "offer_ack", wire.OfferAck{IID: i.IID, FileID: i.FileID, Ready: true}, nil
	}
	i := wire.Instruction{Op: "offer", Audience: c.State.Pins.GatewayID, IID: "44444444-4444-4444-8444-444444444444", IssuedAt: 1767225600, FileID: "0123456789abcdef0123456789abcdef", SHA256: strings.Repeat("a", 64), ListingVersionID: "33333333-3333-4333-8333-333333333333"}
	token, err := wire.Sign("aim-offer+jwt", "listing", i, key)
	if err != nil {
		t.Fatal(err)
	}
	s := server(t, func(ctx context.Context, ws *websocket.Conn) {
		_ = ws.Write(ctx, websocket.MessageText, []byte(`{"resume":{"seq":0,"entry_hash":""}}`))
		for range 2 {
			_, _, _ = ws.Read(ctx)
		}
		_ = ws.Write(ctx, websocket.MessageText, []byte(token))
		_, raw, e := ws.Read(ctx)
		if e != nil {
			t.Error(e)
			return
		}
		var entry audit.Entry
		if json.Unmarshal(raw, &entry) != nil || entry.Seq != 3 || entry.MessageType != "offer_ack" {
			t.Errorf("bad answer: %s", raw)
		}
		_ = ws.Close(websocket.StatusNormalClosure, "done")
	})
	defer s.Close()
	c.URL = "ws" + strings.TrimPrefix(s.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	_ = c.Connect(ctx)
	if called != 1 {
		t.Fatalf("handler called %d times", called)
	}
}
func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestBlockedScanDoesNotBlockReceiptDelivery(t *testing.T) {
	c, entries := fixture(t)
	c.heartbeatEvery = 20 * time.Millisecond
	started := make(chan struct{})
	c.Scan = func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}
	var once sync.Once
	c.Poll = func(context.Context) error {
		var err error
		once.Do(func() { _, err = c.Log.Append("receipt", map[string]any{"seq": 1}) })
		return err
	}
	h, _ := audit.Hash(entries[1])
	s := server(t, func(ctx context.Context, ws *websocket.Conn) {
		_ = ws.Write(ctx, websocket.MessageText, []byte(`{"resume":{"seq":2,"entry_hash":"`+h+`"}}`))
		<-started
		_, raw, err := ws.Read(ctx)
		if err != nil {
			t.Error(err)
			return
		}
		var entry audit.Entry
		if json.Unmarshal(raw, &entry) != nil || entry.Seq != 3 || entry.MessageType != "receipt" {
			t.Errorf("receipt stalled by scan: %s", raw)
		}
		_ = ws.Close(websocket.StatusNormalClosure, "done")
	})
	defer s.Close()
	c.URL = "ws" + strings.TrimPrefix(s.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	_ = c.Connect(ctx)
}

func TestDuplicateControlKeysRejected(t *testing.T) {
	for _, raw := range []string{`{"ack":1,"ack":2}`, `{"nonce":"` + strings.Repeat("a", 64) + `","nonce":"` + strings.Repeat("b", 64) + `"}`, `{"resume":{"seq":0,"seq":1,"entry_hash":""}}`} {
		if kind, _, _ := parseControl([]byte(raw)); kind != "" {
			t.Fatalf("accepted %s", raw)
		}
	}
}
func TestDescribeFailureCodeInAudit(t *testing.T) {
	c, _ := fixture(t)
	key := ed25519.NewKeyFromSeed(bytesRepeat(0x42, 32))
	c.State.Pins.ListingKeys = []wire.Key{{KID: "listing", Alg: "EdDSA", Key: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}}
	c.Handle = func(context.Context, wire.Instruction, string, string) (string, any, error) {
		return "", nil, errors.New("unsupported_format")
	}
	c.Complete = func(context.Context, string) error { t.Error("failed description was marked seen"); return nil }
	now := time.Now().Unix()
	i := wire.Instruction{Op: "describe", Audience: c.State.Pins.GatewayID, IID: "44444444-4444-4444-8444-444444444444", IssuedAt: now, ExpiresAt: now + 900, FileID: "0123456789abcdef0123456789abcdef", ConfirmationID: "33333333-3333-4333-8333-333333333333"}
	token, err := wire.Sign("aim-describe+jwt", "listing", i, key)
	if err != nil {
		t.Fatal(err)
	}
	s := server(t, func(ctx context.Context, ws *websocket.Conn) {
		_ = ws.Write(ctx, websocket.MessageText, []byte(`{"resume":{"seq":0,"entry_hash":""}}`))
		for range 2 {
			_, _, _ = ws.Read(ctx)
		}
		_ = ws.Write(ctx, websocket.MessageText, []byte(token))
		_, raw, err := ws.Read(ctx)
		if err != nil {
			t.Error(err)
			return
		}
		var entry audit.Entry
		if json.Unmarshal(raw, &entry) != nil || entry.MessageType != "error" || !strings.Contains(string(entry.Body), "unsupported_format") {
			t.Errorf("wrong failure code: %s", raw)
		}
		_ = ws.Close(websocket.StatusNormalClosure, "done")
	})
	defer s.Close()
	c.URL = "ws" + strings.TrimPrefix(s.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	_ = c.Connect(ctx)
}

func TestRotatedKeyExpires(t *testing.T) {
	c, _ := fixture(t)
	key := ed25519.NewKeyFromSeed(bytesRepeat(0x42, 32))
	c.State.Pins.ListingKeys = []wire.Key{{KID: "old", Alg: "EdDSA", Key: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}}
	c.State.Pins.KeyExpires = map[string]string{"old": time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)}
	keys, err := c.keys("listing")
	if err != nil || len(keys) != 0 {
		t.Fatalf("expired key remained: %v %v", keys, err)
	}
	c.State.Pins.KeyExpires["old"] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	keys, err = c.keys("listing")
	if err != nil || len(keys) != 1 {
		t.Fatalf("grace key missing: %v %v", keys, err)
	}
}

func server(t *testing.T, fn func(context.Context, *websocket.Conn)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer ws.CloseNow()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := ws.Write(ctx, websocket.MessageText, []byte(`{"nonce":"`+strings.Repeat("a", 64)+`"}`)); err != nil {
			return
		}
		_, hello, err := ws.Read(ctx)
		if err != nil || len(strings.Split(string(hello), ".")) != 3 {
			t.Errorf("missing signed hello: %v", err)
			return
		}
		fn(ctx, ws)
	}))
}

func TestReplayBeforeNewAndAck(t *testing.T) {
	c, entries := fixture(t)
	h, _ := audit.Hash(entries[0])
	var mu sync.Mutex
	var received []uint64
	var delivered []uint64
	c.Delivered = func(_ context.Context, e audit.Entry) error {
		mu.Lock()
		delivered = append(delivered, e.Seq)
		mu.Unlock()
		return nil
	}
	c.Scan = func(context.Context) error {
		_, err := c.Log.Append("inventory", map[string]any{"generation": 3, "files": []any{}})
		return err
	}
	s := server(t, func(ctx context.Context, ws *websocket.Conn) {
		_ = ws.Write(ctx, websocket.MessageText, []byte(`{"resume":{"seq":1,"entry_hash":"`+h+`"}}`))
		for range 2 {
			_, raw, err := ws.Read(ctx)
			if err != nil {
				t.Error(err)
				return
			}
			var e audit.Entry
			if json.Unmarshal(raw, &e) != nil {
				t.Errorf("bad entry: %s", raw)
				return
			}
			mu.Lock()
			received = append(received, e.Seq)
			mu.Unlock()
			_ = ws.Write(ctx, websocket.MessageText, []byte(`{"ack":`+string(rune('0'+e.Seq))+`}`))
		}
		_ = ws.Close(websocket.StatusNormalClosure, "done")
	})
	defer s.Close()
	c.URL = "ws" + strings.TrimPrefix(s.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	_ = c.Connect(ctx)
	mu.Lock()
	defer mu.Unlock()
	if len(received) != 2 || received[0] != 2 || received[1] != 3 {
		t.Fatalf("replay order: %v", received)
	}
	// A close can race the final ack; at least the committed first ack was observed.
	if len(delivered) == 0 || delivered[0] != 2 {
		t.Fatalf("ack delivery: %v", delivered)
	}
}

func TestLostAckAndCrashBeforeAckResume(t *testing.T) {
	for _, label := range []string{"lost_after_commit", "crash_before_recording"} {
		t.Run(label, func(t *testing.T) {
			c, entries := fixture(t)
			var stored []uint64
			first := server(t, func(ctx context.Context, ws *websocket.Conn) {
				_ = ws.Write(ctx, websocket.MessageText, []byte(`{"resume":{"seq":0,"entry_hash":""}}`))
				for range 2 {
					_, raw, err := ws.Read(ctx)
					if err != nil {
						t.Error(err)
						return
					}
					var e audit.Entry
					_ = json.Unmarshal(raw, &e)
					stored = append(stored, e.Seq)
				}
				_ = ws.Close(websocket.StatusNormalClosure, "commit_without_ack")
			})
			c.URL = "ws" + strings.TrimPrefix(first.URL, "http")
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			_ = c.Connect(ctx)
			first.Close()
			if len(stored) != 2 {
				t.Fatalf("first delivery: %v", stored)
			}
			h, _ := audit.Hash(entries[1])
			second := server(t, func(ctx context.Context, ws *websocket.Conn) {
				_ = ws.Write(ctx, websocket.MessageText, []byte(`{"resume":{"seq":2,"entry_hash":"`+h+`"}}`))
				readCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
				if _, raw, err := ws.Read(readCtx); err == nil {
					t.Errorf("duplicate after resume: %s", raw)
				}
				_ = ws.Close(websocket.StatusNormalClosure, "done")
			})
			defer second.Close()
			c.URL = "ws" + strings.TrimPrefix(second.URL, "http")
			_ = c.Connect(ctx)
		})
	}
}

func TestDivergenceSendsNothingAndKeepsLog(t *testing.T) {
	for _, frame := range []string{`{"resume":{"seq":3,"entry_hash":"` + strings.Repeat("a", 64) + `"}}`, `{"resume":{"seq":1,"entry_hash":"` + strings.Repeat("b", 64) + `"}}`} {
		c, before := fixture(t)
		closeCode := make(chan websocket.StatusCode, 1)
		s := server(t, func(ctx context.Context, ws *websocket.Conn) {
			_ = ws.Write(ctx, websocket.MessageText, []byte(frame))
			_, _, err := ws.Read(ctx)
			closeCode <- websocket.CloseStatus(err)
		})
		c.URL = "ws" + strings.TrimPrefix(s.URL, "http")
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		err := c.Connect(ctx)
		cancel()
		s.Close()
		if !errors.Is(err, context.Canceled) && (err == nil || !strings.Contains(err.Error(), "audit_divergence")) {
			t.Fatalf("divergence: %v", err)
		}
		if <-closeCode != 4409 {
			t.Fatal("wrong divergence close")
		}
		after, _ := c.Log.Entries()
		if len(after) != len(before) {
			t.Fatal("log changed")
		}
	}
}

func TestForgedAckCorrectedByNextResume(t *testing.T) {
	c, _ := fixture(t)
	var mu sync.Mutex
	marked := map[uint64]bool{}
	c.Delivered = func(_ context.Context, e audit.Entry) error { mu.Lock(); marked[e.Seq] = true; mu.Unlock(); return nil }
	c.Reconcile = func(_ context.Context, seq uint64, _ []audit.Entry) error {
		mu.Lock()
		defer mu.Unlock()
		for k := range marked {
			if k > seq {
				delete(marked, k)
			}
		}
		return nil
	}
	first := server(t, func(ctx context.Context, ws *websocket.Conn) {
		_ = ws.Write(ctx, websocket.MessageText, []byte(`{"resume":{"seq":0,"entry_hash":""}}`))
		for range 2 {
			_, _, _ = ws.Read(ctx)
		}
		_ = ws.Write(ctx, websocket.MessageText, []byte(`{"ack":2}`))
		time.Sleep(50 * time.Millisecond)
		_ = ws.Close(websocket.StatusNormalClosure, "done")
	})
	c.URL = "ws" + strings.TrimPrefix(first.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	_ = c.Connect(ctx)
	first.Close()
	mu.Lock()
	got := marked[2]
	mu.Unlock()
	if !got {
		t.Fatal("ack did not mark delivery")
	}
	second := server(t, func(ctx context.Context, ws *websocket.Conn) {
		_ = ws.Write(ctx, websocket.MessageText, []byte(`{"resume":{"seq":0,"entry_hash":""}}`))
		for range 2 {
			_, _, _ = ws.Read(ctx)
		}
		_ = ws.Close(websocket.StatusNormalClosure, "done")
	})
	defer second.Close()
	c.URL = "ws" + strings.TrimPrefix(second.URL, "http")
	_ = c.Connect(ctx)
	mu.Lock()
	got = marked[2]
	mu.Unlock()
	if got {
		t.Fatal("forged ack remained delivered")
	}
	entries, _ := c.Log.Entries()
	if len(entries) != 2 {
		t.Fatal("ack pruned log")
	}
}
