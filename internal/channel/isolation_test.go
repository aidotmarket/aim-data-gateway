package channel_test

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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/audit"
	"github.com/aidotmarket/aim-data-gateway/internal/channel"
	"github.com/aidotmarket/aim-data-gateway/internal/config"
	"github.com/aidotmarket/aim-data-gateway/internal/gateway"
	"github.com/aidotmarket/aim-data-gateway/internal/ledger"
	"github.com/aidotmarket/aim-data-gateway/internal/pairing"
	verifier "github.com/aidotmarket/aim-data-gateway/internal/verification"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	"github.com/coder/websocket"
)

func TestVerificationAuditFailureKeepsOrdinaryGatewayChannel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dir := t.TempDir()
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	state := pairing.State{Private: key, Secret: make([]byte, 32), Pins: pairing.Pins{GatewayID: "11111111-1111-4111-8111-111111111111"}}
	g, e := gateway.Open(dir, config.Config{}, state)
	if e != nil {
		t.Fatal(e)
	}
	defer g.Ledger.Close()
	local, e := verifier.OpenLocalAudit(dir, key)
	if e != nil {
		t.Fatal(e)
	}
	var opens atomic.Int64
	r := &verifier.Runner{Ledger: g.Ledger, Audit: local, Log: g.Log, OpenFile: func(ledger.File) (*os.File, error) { opens.Add(1); return nil, os.ErrPermission }}
	g.Verifier = r
	// Seed a completed but unlinked durable result, then fail the local-only
	// event sync. No scanner/source fixture is needed for this recovery boundary.
	at := time.Now()
	a := ledger.Admission{SpecID: "retained", RunnerID: "runner", ListingID: "listing", VersionID: "version", ManifestHash: "manifest", SpecHash: "hash", Nonce: "nonce", AuthorizationID: "auth", Variant: "scan", IID: "44444444-4444-4444-8444-444444444444", Spec: []byte("retained signed spec"), Snapshot: []byte("snapshot"), Accepted: at.Unix() - 60, Issued: at.Unix() - 30, Expires: at.Unix() + 3600}
	if _, e = g.Ledger.Admit(ctx, a, at); e != nil {
		t.Fatal(e)
	}
	body, e := wire.Canonical(map[string]any{"op": "scan_report", "variant": "terminal", "runner_id": "33333333-3333-4333-8333-333333333333", "iid": a.IID, "document_b64": base64.RawURLEncoding.EncodeToString([]byte(`{"error_code":"scanner_failure"}`))})
	if e != nil {
		t.Fatal(e)
	}
	if e = g.Ledger.SaveVerification(ctx, a.SpecID, "reported", body); e != nil {
		t.Fatal(e)
	}
	local.Sync = func(*os.File) error { return errors.New("injected verification-only sync failure") }
	if e = r.Flush(ctx); e == nil {
		t.Fatal("expected sticky audit failure")
	}
	if e = r.Submit(ctx, "new work"); e == nil {
		t.Fatal("failed runner accepted work")
	}
	receipt := wire.Receipt{Op: "receipt", OrderID: "22222222-2222-4222-8222-222222222222", FileID: strings.Repeat("a", 32), SHA256: strings.Repeat("a", 64), JTIs: []string{}, Transmitted: []wire.Interval{}, Outcome: "in_progress", BlocksVerified: true, Seq: 1}
	token, e := wire.Sign("aim-receipt+jwt", "gateway", receipt, key)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = g.Ledger.DB.ExecContext(ctx, `INSERT INTO receipts_outbox(seq,body) VALUES(1,?)`, token); e != nil {
		t.Fatal(e)
	}
	var connections, pings, canaries atomic.Int64
	delivered := make(chan struct{}, 1)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		connections.Add(1)
		ws, e := websocket.Accept(w, req, &websocket.AcceptOptions{OnPingReceived: func(context.Context, []byte) bool { pings.Add(1); return true }})
		if e != nil {
			return
		}
		defer ws.CloseNow()
		ws.Write(ctx, websocket.MessageText, []byte(`{"nonce":"`+strings.Repeat("a", 64)+`"}`))
		ws.Read(ctx)
		ws.Write(ctx, websocket.MessageText, []byte(`{"resume":{"seq":0,"entry_hash":""}}`))
		for {
			_, raw, e := ws.Read(ctx)
			if e != nil {
				return
			}
			var entry audit.Entry
			if e = json.Unmarshal(raw, &entry); e != nil {
				t.Error(e)
				return
			}
			if entry.MessageType == "scan_report" {
				t.Error("unsynced verification report transmitted")
			}
			if entry.MessageType == "receipt" {
				delivered <- struct{}{}
			}
		}
	}))
	defer s.Close()
	c := &channel.Client{URL: "ws" + strings.TrimPrefix(s.URL, "http"), State: &state, Log: g.Log, Poll: g.Poll, Delivered: g.Delivered, Canary: func(context.Context) error { canaries.Add(1); return nil }}
	channel.SetTestHeartbeat(c, 73*time.Millisecond)
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	select {
	case <-delivered:
	case <-ctx.Done():
		t.Fatal("ordinary receipt not transmitted")
	}
	// Stay connected beyond two poll ticks: the old implementation disconnects
	// on its first tick and never appends the newly pending ordinary receipt.
	time.Sleep(1200 * time.Millisecond)
	if connections.Load() != 1 || pings.Load() < 2 || canaries.Load() == 0 {
		t.Fatal("ordinary channel degraded", connections.Load(), pings.Load(), canaries.Load())
	}
	cancel()
	<-done
	if opens.Load() != 0 {
		t.Fatal("failed verifier opened source")
	}
	saved, e := g.Ledger.Verification(context.Background(), a.SpecID)
	if e != nil || saved.AuditSeq.Valid || !bytes.Equal(saved.Result, body) {
		t.Fatal("verification outbox lost or reported", saved, e)
	}
	entries, e := g.Log.Entries()
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range entries {
		if entry.MessageType == "scan_report" {
			t.Fatal("unsynced report appended")
		}
	}
	recovered, e := verifier.OpenLocalAudit(dir, key)
	if e != nil {
		t.Fatal(e)
	}
	restarted := &verifier.Runner{Ledger: g.Ledger, Audit: recovered, Log: g.Log}
	if e = restarted.Recover(context.Background()); e != nil {
		t.Fatal(e)
	}
	saved, e = g.Ledger.Verification(context.Background(), a.SpecID)
	if e != nil || !saved.AuditSeq.Valid || !bytes.Equal(saved.Result, body) {
		t.Fatal("restart did not reconcile", saved, e)
	}
	if _, e = os.Stat(filepath.Join(dir, "verification-audit.jsonl")); e != nil {
		t.Fatal(e)
	}
}
