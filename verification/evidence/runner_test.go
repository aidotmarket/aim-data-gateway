//go:build evidence

package evidence

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/audit"
	"github.com/aidotmarket/aim-data-gateway/internal/channel"
	"github.com/aidotmarket/aim-data-gateway/internal/pairing"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	"github.com/coder/websocket"
)

func TestRunnerHostRefusal(t *testing.T) {
	for _, raw := range []string{"https://api.ai.market", "http://api.ai.market", "https://localhost:18000", "http://example.com", "http://localhost.example.com", "http://127.0.0.2", "http://[::1]", "http://backend.evil", "http://localhost@api.ai.market", "http://user@localhost", "http://localhost:18000/prefix", "http://localhost?x=1", "http://localhost#x", "http://localhost:", "http://localhost:abc", "http://localhost./", "//localhost:18000"} {
		t.Run(raw, func(t *testing.T) {
			if _, err := testBase(raw); err == nil {
				t.Fatal("accepted unsafe origin")
			}
		})
	}
	for _, raw := range []string{"http://localhost:18000", "http://127.0.0.1:18000/", "http://backend:8000"} {
		if _, err := testBase(raw); err != nil {
			t.Fatal(raw, err)
		}
	}
}

func TestRunnerTransportPreservesSignedBytes(t *testing.T) {
	base, err := testBase("http://localhost:18000")
	must(t, err)
	body := []byte(`{"document_b64":"signed-exact-bytes"}`)
	called := 0
	tr := testTransport{base: base, next: trip(func(req *http.Request) (*http.Response, error) {
		called++
		if req.URL.Scheme != "http" || req.URL.Host != base.Host || req.Host != base.Host || req.Header.Get("Authorization") != "Bearer unchanged.signature.bytes" {
			t.Fatal("unexpected transport mapping")
		}
		raw, e := io.ReadAll(req.Body)
		must(t, e)
		if !bytes.Equal(raw, body) {
			t.Fatal("body changed")
		}
		return response(req, "backend-signed-snapshot"), nil
	})}
	req, err := http.NewRequest("GET", "https://api.ai.market/api/v1/verification-runners/test/snapshot/hash", bytes.NewReader(body))
	must(t, err)
	req.Header.Set("Authorization", "Bearer unchanged.signature.bytes")
	resp, err := tr.RoundTrip(req)
	must(t, err)
	defer resp.Body.Close()
	if resp.Request != req || req.URL.Host != "api.ai.market" {
		t.Fatal("logical origin metadata changed")
	}
	for _, raw := range []string{"https://api.ai.market/api/v1/other", "http://api.ai.market/api/v1/verification-runners/test/snapshot/hash", "http://example.com/", "http://127.0.0.1:18000/"} {
		r, e := http.NewRequest("GET", raw, nil)
		must(t, e)
		if _, e = tr.RoundTrip(r); e == nil {
			t.Fatal("outbound origin accepted", raw)
		}
	}
	if called != 1 {
		t.Fatal("unsafe request reached underlying transport")
	}
}

// Gen2's newHarness.scan invokes the actual gateway scanner/report/receipt
// implementation. Send those durable entries through the native channel and
// compare every received byte, including signed audit envelopes, to gen2.
func TestRunnerFramesIdenticalToGen2Capture(t *testing.T) {
	h := newHarness(t, "aim_gateway")
	_, err := h.gateway.Log.Append("scan_report", json.RawMessage(h.registration))
	must(t, err)
	frames := map[string][]byte{}
	for _, variant := range []string{"probe", "scan"} {
		frames[variant] = h.scan(t, []file{{Key: "data.csv", Format: "csv", Data: []byte(SyntheticFixture)}}, variant)
	}
	var expected [][]byte
	for seq := uint64(1); seq <= h.gateway.Log.Sequence(); seq++ {
		e, err := h.gateway.Log.Read(seq)
		must(t, err)
		raw, err := wire.Canonical(e)
		must(t, err)
		expected = append(expected, raw)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, e := websocket.Accept(w, r, nil)
		if e != nil {
			result <- e
			return
		}
		defer ws.CloseNow()
		if e = ws.Write(ctx, websocket.MessageText, []byte(`{"nonce":"`+strings.Repeat("a", 64)+`"}`)); e != nil {
			result <- e
			return
		}
		if _, _, e = ws.Read(ctx); e != nil {
			result <- e
			return
		}
		if e = ws.Write(ctx, websocket.MessageText, []byte(`{"resume":{"seq":0,"entry_hash":""}}`)); e != nil {
			result <- e
			return
		}
		for _, want := range expected {
			_, got, e := ws.Read(ctx)
			if e != nil {
				result <- e
				return
			}
			if !bytes.Equal(got, want) {
				result <- fmt.Errorf("native channel frame differs from gen2")
				return
			}
			var entry audit.Entry
			if e = json.Unmarshal(got, &entry); e != nil {
				result <- e
				return
			}
			var body struct {
				Variant string `json:"variant"`
			}
			if e = json.Unmarshal(entry.Body, &body); e != nil {
				result <- e
				return
			}
			if wantBody := frames[body.Variant]; wantBody != nil && !bytes.Equal(entry.Body, wantBody) {
				result <- fmt.Errorf("signed report/receipt changed")
				return
			}
		}
		ack, _ := json.Marshal(map[string]uint64{"ack": h.gateway.Log.Sequence()})
		if e = ws.Write(ctx, websocket.MessageText, ack); e != nil {
			result <- e
			return
		}
		result <- nil
		<-ctx.Done()
	}))
	defer srv.Close()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	base, err := testBase(srv.URL)
	must(t, err)
	c := channel.Client{URL: "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/v1/gateway-channel", HTTPClient: testClient(base), Log: h.gateway.Log, Version: "1.2.3",
		State:     &pairing.State{Private: key, Pins: pairing.Pins{GatewayID: h.gateway.GatewayID}},
		Delivered: func(context.Context, audit.Entry) error { cancel(); return nil }}
	_ = c.Connect(ctx) // Expected context cancellation after the final real ack.
	if err = <-result; err != nil {
		t.Fatal(err)
	}
	t.Logf("%d native channel frames byte-identical to gen2; probe and scan receipts included", len(expected))
}
