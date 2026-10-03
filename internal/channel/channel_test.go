package channel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/audit"
	"github.com/aidotmarket/aim-data-gateway/internal/ledger"
	"github.com/aidotmarket/aim-data-gateway/internal/pairing"
	"github.com/aidotmarket/aim-data-gateway/internal/profile"
	verifier "github.com/aidotmarket/aim-data-gateway/internal/verification"
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

func TestCanaryRunsAndAcksWhileScanBlocked(t *testing.T) {
	c, entries := fixture(t)
	c.canaryEvery = 25 * time.Millisecond
	started := make(chan struct{})
	c.Scan = func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}
	c.Canary = func(context.Context) error {
		_, err := c.Log.Append("canary_result", map[string]any{"state": "closed"})
		return err
	}
	acked := make(chan uint64, 2)
	c.Delivered = func(_ context.Context, entry audit.Entry) error {
		acked <- entry.Seq
		return nil
	}
	h, _ := audit.Hash(entries[1])
	s := server(t, func(ctx context.Context, ws *websocket.Conn) {
		_ = ws.Write(ctx, websocket.MessageText, []byte(`{"resume":{"seq":2,"entry_hash":"`+h+`"}}`))
		<-started
		for seq := uint64(3); seq <= 4; seq++ {
			_, raw, err := ws.Read(ctx)
			if err != nil {
				t.Errorf("canary %d stalled: %v", seq, err)
				return
			}
			var entry audit.Entry
			if json.Unmarshal(raw, &entry) != nil || entry.Seq != seq || entry.MessageType != "canary_result" {
				t.Errorf("wrong canary: %s", raw)
				return
			}
			_ = ws.Write(ctx, websocket.MessageText, []byte(`{"ack":`+strconv.FormatUint(seq, 10)+`}`))
			select {
			case got := <-acked:
				if got != seq {
					t.Errorf("ack %d delivered as %d", seq, got)
				}
			case <-ctx.Done():
				t.Errorf("ack %d stalled", seq)
				return
			}
		}
		_ = ws.Close(websocket.StatusNormalClosure, "done")
	})
	defer s.Close()
	c.URL = "ws" + strings.TrimPrefix(s.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	_ = c.Connect(ctx)
	if c.Log.Sequence() < 4 {
		t.Fatalf("only %d canary results", c.Log.Sequence()-2)
	}
}

func TestControlPassesBlockedDescription(t *testing.T) {
	c, _ := fixture(t)
	key := ed25519.NewKeyFromSeed(bytesRepeat(0x42, 32))
	c.State.Pins.ListingKeys = []wire.Key{{KID: "listing", Alg: "EdDSA", Key: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}}
	started := make(chan struct{})
	c.Handle = func(ctx context.Context, i wire.Instruction, _, _ string) (string, any, error) {
		if i.Op == "describe" {
			close(started)
			<-ctx.Done()
			return "", nil, ctx.Err()
		}
		return "offer_ack", wire.OfferAck{IID: i.IID, FileID: i.FileID, Ready: true}, nil
	}
	now := time.Now().Unix()
	base := wire.Instruction{Audience: c.State.Pins.GatewayID, IID: "44444444-4444-4444-8444-444444444444", IssuedAt: now, FileID: "0123456789abcdef0123456789abcdef"}
	d := base
	d.Op, d.ExpiresAt, d.ConfirmationID = "describe", now+900, "33333333-3333-4333-8333-333333333333"
	o := base
	o.Op, o.IID, o.SHA256, o.ListingVersionID = "offer", "55555555-5555-4555-8555-555555555555", strings.Repeat("a", 64), "33333333-3333-4333-8333-333333333333"
	dToken, err := wire.Sign("aim-describe+jwt", "listing", d, key)
	if err != nil {
		t.Fatal(err)
	}
	oToken, err := wire.Sign("aim-offer+jwt", "listing", o, key)
	if err != nil {
		t.Fatal(err)
	}
	s := server(t, func(ctx context.Context, ws *websocket.Conn) {
		_ = ws.Write(ctx, websocket.MessageText, []byte(`{"resume":{"seq":0,"entry_hash":""}}`))
		for range 2 {
			_, _, _ = ws.Read(ctx)
		}
		_ = ws.Write(ctx, websocket.MessageText, []byte(dToken))
		<-started
		_ = ws.Write(ctx, websocket.MessageText, []byte(oToken))
		_, raw, e := ws.Read(ctx)
		if e != nil {
			t.Error(e)
			return
		}
		var entry audit.Entry
		if json.Unmarshal(raw, &entry) != nil || entry.MessageType != "offer_ack" {
			t.Errorf("control blocked: %s", raw)
		}
		_ = ws.Close(websocket.StatusNormalClosure, "done")
	})
	defer s.Close()
	c.URL = "ws" + strings.TrimPrefix(s.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	_ = c.Connect(ctx)
}

func TestSuccessorUsesRotatedPin(t *testing.T) {
	c, _ := fixture(t)
	oldKey := ed25519.NewKeyFromSeed(bytesRepeat(0x41, 32))
	newKey := ed25519.NewKeyFromSeed(bytesRepeat(0x42, 32))
	oldPin := wire.Key{KID: "old", Alg: "EdDSA", Key: base64.RawURLEncoding.EncodeToString(oldKey.Public().(ed25519.PublicKey))}
	newPin := wire.Key{KID: "new", Alg: "EdDSA", Key: base64.RawURLEncoding.EncodeToString(newKey.Public().(ed25519.PublicKey))}
	var mu sync.RWMutex
	c.State.Pins.ListingKeys = []wire.Key{oldPin}
	c.PinsSnapshot = func() pairing.Pins {
		mu.RLock()
		defer mu.RUnlock()
		p := c.State.Pins
		p.ListingKeys = append([]wire.Key(nil), p.ListingKeys...)
		return p
	}
	c.Handle = func(_ context.Context, i wire.Instruction, _, _ string) (string, any, error) {
		if i.Op == "key_rotation" {
			mu.Lock()
			c.State.Pins.ListingKeys = append(c.State.Pins.ListingKeys, newPin)
			mu.Unlock()
			return "", nil, nil
		}
		return "offer_ack", wire.OfferAck{IID: i.IID, FileID: i.FileID, Ready: true}, nil
	}
	now := time.Now().Unix()
	rotation := wire.Instruction{Op: "key_rotation", Audience: c.State.Pins.GatewayID, IID: "44444444-4444-4444-8444-444444444444", IssuedAt: now, Keys: []wire.Key{newPin}}
	offer := wire.Instruction{Op: "offer", Audience: c.State.Pins.GatewayID, IID: "55555555-5555-4555-8555-555555555555", IssuedAt: now, FileID: "0123456789abcdef0123456789abcdef", SHA256: strings.Repeat("a", 64), ListingVersionID: "33333333-3333-4333-8333-333333333333"}
	rToken, err := wire.Sign("aim-keys+jwt", "old", rotation, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	oToken, err := wire.Sign("aim-offer+jwt", "new", offer, newKey)
	if err != nil {
		t.Fatal(err)
	}
	s := server(t, func(ctx context.Context, ws *websocket.Conn) {
		_ = ws.Write(ctx, websocket.MessageText, []byte(`{"resume":{"seq":0,"entry_hash":""}}`))
		for range 2 {
			_, _, _ = ws.Read(ctx)
		}
		_ = ws.Write(ctx, websocket.MessageText, []byte(rToken))
		_ = ws.Write(ctx, websocket.MessageText, []byte(oToken))
		_, raw, e := ws.Read(ctx)
		if e != nil {
			t.Error(e)
			return
		}
		var entry audit.Entry
		if json.Unmarshal(raw, &entry) != nil || entry.MessageType != "offer_ack" {
			t.Errorf("successor rejected: %s", raw)
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
		return "", nil, profile.ErrUnsupportedFormat
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
	c.Reconcile = func(_ context.Context, seq uint64) error {
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

func TestVerificationLaneDoesNotBlockControlOrHeartbeat(t *testing.T) {
	c, _ := fixture(t)
	key := ed25519.NewKeyFromSeed(bytesRepeat(0x42, 32))
	c.State.Pins.ListingKeys = []wire.Key{{KID: "listing", Alg: "EdDSA", Key: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}}
	started := make(chan struct{})
	stopped := make(chan struct{})
	c.Verification = func(ctx context.Context, token string) error {
		close(started)
		<-ctx.Done()
		close(stopped)
		return ctx.Err()
	}
	c.heartbeatEvery = 20 * time.Millisecond
	c.Handle = func(ctx context.Context, i wire.Instruction, _, _ string) (string, any, error) {
		return "offer_ack", wire.OfferAck{IID: i.IID, FileID: i.FileID, Ready: true}, nil
	}
	i := wire.Instruction{Op: "offer", Audience: c.State.Pins.GatewayID, IID: "44444444-4444-4444-8444-444444444444", IssuedAt: time.Now().Unix(), FileID: "0123456789abcdef0123456789abcdef", SHA256: strings.Repeat("a", 64), ListingVersionID: "33333333-3333-4333-8333-333333333333"}
	offer, _ := wire.Sign("aim-offer+jwt", "listing", i, key)
	scan, _ := wire.Sign("aim-scan-spec+jwt", "scan", map[string]any{"variant": "scan"}, key)
	s := server(t, func(ctx context.Context, ws *websocket.Conn) {
		ws.Write(ctx, websocket.MessageText, []byte(`{"resume":{"seq":0,"entry_hash":""}}`))
		for range 2 {
			ws.Read(ctx)
		}
		ws.Write(ctx, websocket.MessageText, []byte(scan))
		<-started
		ws.Write(ctx, websocket.MessageText, []byte(offer))
		_, raw, e := ws.Read(ctx)
		if e != nil {
			t.Error(e)
			return
		}
		var a audit.Entry
		if json.Unmarshal(raw, &a) != nil || a.MessageType != "offer_ack" {
			t.Error("verification blocked control", string(raw))
		}
		ws.Close(websocket.StatusNormalClosure, "done")
	})
	defer s.Close()
	c.URL = "ws" + strings.TrimPrefix(s.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	c.Connect(ctx)
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("disconnect did not cancel verification")
	}
}
func TestScanRotationUsesOutgoingScanClass(t *testing.T) {
	c, _ := fixture(t)
	key := ed25519.NewKeyFromSeed(bytesRepeat(0x42, 32))
	c.State.Pins.ScanSpecKeys = []wire.Key{{KID: "scan", Alg: "EdDSA", Key: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}}
	i := wire.Instruction{Op: "key_rotation", Audience: c.State.Pins.GatewayID, IID: "44444444-4444-4444-8444-444444444444", IssuedAt: time.Now().Unix(), Keys: c.State.Pins.ScanSpecKeys}
	token, _ := wire.Sign("aim-keys+jwt", "scan", i, key)
	_, class, _, e := c.verify(token)
	if e != nil || class != "scan" {
		t.Fatal(class, e)
	}
}

func TestVerificationControlOverflowRecordsEveryToken(t *testing.T) {
	c, _ := fixture(t)
	dir := t.TempDir()
	l, e := ledger.Open(filepath.Join(dir, "gateway.db"), c.State.Private, "gateway")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	local, e := verifier.OpenLocalAudit(dir, c.State.Private)
	if e != nil {
		t.Fatal(e)
	}
	r := &verifier.Runner{Ledger: l, Audit: local, Log: c.Log, OpenFile: func(ledger.File) (*os.File, error) { t.Error("overflow opened source"); return nil, os.ErrPermission }}
	received := make(chan struct{}, 12)
	record := func(ctx context.Context, token string) error {
		e := r.RefuseControl(ctx, token)
		if e == nil {
			received <- struct{}{}
		}
		return e
	}
	if e = r.Start(context.Background(), dir); e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	c.VerificationRefused = r.QueueRefusal
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	c.Verification = func(ctx context.Context, token string) error {
		if e := record(ctx, wire.Digest([]byte(token))); e != nil {
			return e
		}
		once.Do(func() {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
			}
		})
		return nil
	}
	key := ed25519.NewKeyFromSeed(bytesRepeat(0x42, 32))
	token, _ := wire.Sign("aim-scan-spec+jwt", "scan", map[string]any{"sample": "PRIVATE_CELL", "path": "PRIVATE_PATH", "schema": "PRIVATE_SCHEMA"}, key)
	// A recognizable verification header with a malformed body/signature is also
	// routed to hash-only refusal instead of silently escaping the bounded lane.
	malformed := strings.Split(token, ".")[0] + ".malformed"
	tokens := []string{token, token, malformed, token, malformed, token, token, token, token, token, token, token}
	c.heartbeatEvery = time.Second
	polled := make(chan struct{}, 1)
	c.Poll = func(ctx context.Context) error {
		select {
		case polled <- struct{}{}:
		default:
		}
		return nil
	}
	s := server(t, func(ctx context.Context, ws *websocket.Conn) {
		ws.Write(ctx, websocket.MessageText, []byte(`{"resume":{"seq":0,"entry_hash":""}}`))
		for range 2 {
			ws.Read(ctx)
		}
		// Keep reading so websocket ping/pong remains active while controls overflow.
		go func() {
			for {
				if _, _, e := ws.Read(ctx); e != nil {
					return
				}
			}
		}()
		ws.Write(ctx, websocket.MessageText, []byte(tokens[0]))
		select {
		case <-entered:
		case <-ctx.Done():
			return
		}
		for _, token := range tokens[1:] {
			ws.Write(ctx, websocket.MessageText, []byte(token))
		}
		// First control is blocked and one is queued; all ten excess controls must
		// already have durable refusal records without releasing the worker.
		waitRefusalEvents(t, ctx, l, 11)
		select {
		case <-polled:
		case <-ctx.Done():
			t.Error("overflow blocked channel polling")
			return
		}
		if e := ws.Ping(ctx); e != nil {
			t.Error("overflow blocked heartbeat", e)
		}
		close(release)
		waitRefusalEvents(t, ctx, l, 12)
		ws.Close(websocket.StatusNormalClosure, "done")
	})
	defer s.Close()
	c.URL = "ws" + strings.TrimPrefix(s.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	c.Connect(ctx)
	r.Close()
	events, e := l.VerificationEvents(context.Background(), 0)
	if e != nil || len(events) != len(tokens) {
		t.Fatal("lost verification control", len(events), e)
	}
	for _, event := range events {
		if event.Result != "refused" || event.RefusalCode != "queue_full" || event.SpecID != "" || len(event.SpecHash) != 64 {
			t.Fatal(event)
		}
	}
	raw, e := os.ReadFile(filepath.Join(dir, "verification-audit.jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	for _, marker := range []string{"PRIVATE_CELL", "PRIVATE_PATH", "PRIVATE_SCHEMA", "malformed"} {
		if bytes.Contains(raw, []byte(marker)) {
			t.Fatal("overflow leaked content")
		}
	}
	var n int
	l.DB.QueryRow("SELECT count(*) FROM verification_admissions").Scan(&n)
	if n != 0 {
		t.Fatal("overflow admitted", n)
	}
}

func TestOverflowAuditSyncDoesNotBlockChannel(t *testing.T) {
	c, entries := fixture(t)
	dir := t.TempDir()
	l, e := ledger.Open(filepath.Join(dir, "gateway.db"), c.State.Private, "gateway")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	local, e := verifier.OpenLocalAudit(dir, c.State.Private)
	if e != nil {
		t.Fatal(e)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	r := &verifier.Runner{Ledger: l, Audit: local, Log: c.Log, OpenFile: func(ledger.File) (*os.File, error) { t.Error("source opened"); return nil, os.ErrPermission }}
	if e = r.Start(context.Background(), dir); e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	local.Sync = func(f *os.File) error { once.Do(func() { close(entered); <-release }); return f.Sync() }
	c.VerificationRefused = r.QueueRefusal
	var onceAdmission sync.Once
	admissionEntered := make(chan struct{})
	c.Verification = func(ctx context.Context, token string) error {
		onceAdmission.Do(func() { close(admissionEntered) })
		<-ctx.Done()
		return ctx.Err()
	}
	c.heartbeatEvery = 20 * time.Millisecond
	polled, acked, revoked := make(chan struct{}, 1), make(chan struct{}, 1), make(chan struct{}, 1)
	c.Poll = func(context.Context) error {
		select {
		case polled <- struct{}{}:
		default:
		}
		return nil
	}
	c.Delivered = func(context.Context, audit.Entry) error {
		select {
		case acked <- struct{}{}:
		default:
		}
		return nil
	}
	c.Handle = func(_ context.Context, i wire.Instruction, _, _ string) (string, any, error) {
		if i.Op == "revoke" {
			revoked <- struct{}{}
		}
		return "", nil, nil
	}
	key := ed25519.NewKeyFromSeed(bytesRepeat(0x42, 32))
	c.State.Pins.PermissionKeys = []wire.Key{{KID: "permission", Alg: "EdDSA", Key: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}}
	token, _ := wire.Sign("aim-scan-spec+jwt", "scan", map[string]any{"secret": "PRIVATE_CELL"}, key)
	revoke, e := wire.Sign("aim-revoke+jwt", "permission", wire.Instruction{Op: "revoke", Audience: c.State.Pins.GatewayID, IID: "44444444-4444-4444-8444-444444444444", IssuedAt: time.Now().Unix(), JTI: "22222222-2222-4222-8222-222222222222"}, key)
	if e != nil {
		t.Fatal(e)
	}
	var connections atomic.Int64
	s := server(t, func(ctx context.Context, ws *websocket.Conn) {
		ws.Write(ctx, websocket.MessageText, []byte(`{"resume":{"seq":0,"entry_hash":""}}`))
		for range len(entries) {
			ws.Read(ctx)
		}
		go func() {
			for {
				if _, _, e := ws.Read(ctx); e != nil {
					return
				}
			}
		}()
		if connections.Add(1) == 2 {
			select {
			case <-polled:
			case <-ctx.Done():
				t.Error("reconnect polling stalled")
				return
			}
			if e := ws.Ping(ctx); e != nil {
				t.Error("reconnect heartbeat blocked", e)
			}
			close(release)
			waitRefusalEvents(t, ctx, l, 100)
			return
		}
		ws.Write(ctx, websocket.MessageText, []byte(token))
		select {
		case <-admissionEntered:
		case <-ctx.Done():
			t.Error("admission not blocked")
			return
		}
		// One queued control and 100 overflow refusals.
		for range 101 {
			ws.Write(ctx, websocket.MessageText, []byte(token))
		}
		select {
		case <-entered:
		case <-ctx.Done():
			t.Error("audit did not block")
			return
		}
		ws.Write(ctx, websocket.MessageText, []byte(`{"ack":2}`))
		ws.Write(ctx, websocket.MessageText, []byte(revoke))
		for _, ch := range []chan struct{}{acked, revoked, polled} {
			select {
			case <-ch:
			case <-ctx.Done():
				t.Error("channel stalled on audit")
				close(release)
				return
			}
		}
		// Poll fires after one second, beyond the old refusal deadline. Storage is
		// still blocked, but ping/pong and ordinary controls remain responsive.
		if e := ws.Ping(ctx); e != nil {
			t.Error("heartbeat blocked", e)
		}
		ws.CloseNow() // Replace the connection while refusal storage is blocked.
	})
	defer s.Close()
	c.URL = "ws" + strings.TrimPrefix(s.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	c.Connect(ctx)
	c.Connect(ctx)
	r.Close()
	events, e := l.VerificationEvents(context.Background(), 0)
	if e != nil || len(events) != 100 {
		t.Fatal(len(events), e)
	}
	counted := 0
	for _, v := range events {
		if v.SpecHash == "" {
			counted++
		} else if v.SpecHash != wire.Digest([]byte(token)) {
			t.Fatal(v)
		}
		if v.Result != "refused" || v.RefusalCode != "queue_full" || v.SpecID != "" {
			t.Fatal(v)
		}
	}
	if counted == 0 {
		t.Fatal("bounded counter was not exercised")
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "verification-audit.jsonl"))
	if bytes.Contains(raw, []byte("PRIVATE_CELL")) {
		t.Fatal("raw control leaked")
	}
}

func waitRefusalEvents(t *testing.T, ctx context.Context, l *ledger.Ledger, want int) {
	t.Helper()
	for {
		var n int
		if e := l.DB.QueryRowContext(ctx, "SELECT count(*) FROM verification_local_events").Scan(&n); e != nil {
			t.Error(e)
			return
		}
		if n == want {
			return
		}
		if n > want {
			t.Errorf("duplicate events: %d > %d", n, want)
			return
		}
		select {
		case <-ctx.Done():
			t.Error("missing refusal evidence", n, want)
			return
		case <-time.After(10 * time.Millisecond):
		}
	}
}
