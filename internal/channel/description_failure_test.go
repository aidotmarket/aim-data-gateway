package channel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/audit"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	"github.com/coder/websocket"
)

func TestDisconnectedDescriptionFailureDeliveredAfterResume(t *testing.T) {
	c, entries := fixture(t)
	// No connection exists when this failure is appended. Resume must deliver it.
	body := wire.DescriptionFailure{FileID: "0123456789abcdef0123456789abcdef", FailureCode: "read_error"}
	failure, err := c.Log.Append("description", body)
	if err != nil {
		t.Fatal(err)
	}
	previousHash, _ := audit.Hash(entries[1])
	failureHash, _ := audit.Hash(failure)
	acked := make(chan struct{}, 1)
	c.Delivered = func(_ context.Context, entry audit.Entry) error {
		if entry.Seq != failure.Seq {
			t.Errorf("unexpected ack: %d", entry.Seq)
		}
		acked <- struct{}{}
		return nil
	}
	first := server(t, func(ctx context.Context, ws *websocket.Conn) {
		_ = ws.Write(ctx, websocket.MessageText, []byte(`{"resume":{"seq":2,"entry_hash":"`+previousHash+`"}}`))
		_, raw, err := ws.Read(ctx)
		if err != nil {
			t.Error(err)
			return
		}
		entry, err := audit.ValidateRaw(raw, c.State.Private.Public().(ed25519.PublicKey))
		want, _ := wire.Canonical(body)
		if err != nil || entry.Seq != failure.Seq || entry.MessageType != "description" || !bytes.Equal(entry.Body, want) {
			t.Errorf("resumed failure: %s, %v", raw, err)
		}
		_ = ws.Write(ctx, websocket.MessageText, []byte(`{"ack":3}`))
		select {
		case <-acked:
		case <-ctx.Done():
			t.Error("failure delivery was not acknowledged")
		}
		_ = ws.Close(websocket.StatusNormalClosure, "done")
	})
	defer first.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c.URL = "ws" + strings.TrimPrefix(first.URL, "http")
	_ = c.Connect(ctx)
	second := server(t, func(ctx context.Context, ws *websocket.Conn) {
		_ = ws.Write(ctx, websocket.MessageText, []byte(`{"resume":{"seq":3,"entry_hash":"`+failureHash+`"}}`))
		readCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()
		if _, raw, err := ws.Read(readCtx); err == nil {
			var entry audit.Entry
			_ = json.Unmarshal(raw, &entry)
			t.Errorf("entry delivered twice after acknowledged resume: %s", raw)
		}
	})
	defer second.Close()
	c.URL = "ws" + strings.TrimPrefix(second.URL, "http")
	_ = c.Connect(ctx)
}
