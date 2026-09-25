package channel

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/audit"
	"github.com/aidotmarket/aim-data-gateway/internal/pairing"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	"github.com/coder/websocket"
)

const URL = "wss://api.ai.market/api/v1/gateway-channel"
const maxMessage = 1 << 20

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Client struct {
	URL        string
	HTTPClient *http.Client
	State      *pairing.State
	Log        *audit.Log
	Version    string
	// Handle processes a verified, unseen instruction and returns an audit answer.
	Handle func(context.Context, wire.Instruction, string, string) (string, any, error)
	// Scan appends an inventory generation after each successful resume.
	Scan func(context.Context) error
	// Poll appends any newly queued receipts, returning their local audit sequences.
	Poll func(context.Context) error
	// Delivered marks an outbox receipt after ack or a later resume.
	Delivered func(context.Context, audit.Entry) error
	Reconcile func(context.Context, uint64, []audit.Entry) error
	sent      uint64
}

func (c *Client) keys(class string) (map[string]ed25519.PublicKey, error) {
	var pins []wire.Key
	if class == "permission" {
		pins = c.State.Pins.PermissionKeys
	} else {
		pins = c.State.Pins.ListingKeys
	}
	out := make(map[string]ed25519.PublicKey, len(pins))
	for _, p := range pins {
		if at := c.State.Pins.KeyExpires[p.KID]; at != "" {
			deadline, err := time.Parse(time.RFC3339Nano, at)
			if err != nil || !time.Now().Before(deadline) {
				continue
			}
		}
		b, err := base64.RawURLEncoding.DecodeString(p.Key)
		if err != nil || p.Alg != "EdDSA" || len(b) != ed25519.PublicKeySize {
			return nil, errors.New("invalid pinned key")
		}
		out[p.KID] = b
	}
	return out, nil
}

func (c *Client) verify(token string) (wire.Instruction, string, string, error) {
	var i wire.Instruction
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return i, "", "", errors.New("invalid instruction")
	}
	h, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return i, "", "", err
	}
	var header wire.Header
	if err = json.Unmarshal(h, &header); err != nil {
		return i, "", "", err
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return i, "", "", err
	}
	if err = json.Unmarshal(b, &i); err != nil {
		return i, "", "", err
	}
	_, class, err := i.Kind()
	if err != nil {
		return i, "", "", err
	}
	if class == "outgoing" {
		// A rotation may be signed by either outgoing key class.
		for _, kind := range []string{"listing", "permission"} {
			keys, e := c.keys(kind)
			if e == nil {
				if i, e = wire.VerifyInstruction(token, keys); e == nil {
					class = kind
					err = nil
					break
				} else {
					err = e
				}
			}
		}
	} else {
		keys, e := c.keys(class)
		if e != nil {
			return i, "", "", e
		}
		i, err = wire.VerifyInstruction(token, keys)
	}
	if err != nil {
		return i, "", "", err
	}
	if i.Audience != c.State.Pins.GatewayID {
		return i, "", "", errors.New("wrong instruction audience")
	}
	return i, class, header.KID, nil
}

func parseControl(raw []byte) (kind string, seq uint64, hash string) {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil || len(obj) != 1 {
		return "", 0, ""
	}
	if value, ok := obj["nonce"]; ok {
		var nonce string
		if json.Unmarshal(value, &nonce) == nil && hex64.MatchString(nonce) {
			return "nonce", 0, nonce
		}
	}
	if value, ok := obj["resume"]; ok {
		var fields map[string]json.RawMessage
		if json.Unmarshal(value, &fields) != nil || len(fields) != 2 {
			return "", 0, ""
		}
		if json.Unmarshal(fields["seq"], &seq) != nil || json.Unmarshal(fields["entry_hash"], &hash) != nil {
			return "", 0, ""
		}
		if (seq == 0 && hash == "") || (seq > 0 && hex64.MatchString(hash)) {
			return "resume", seq, hash
		}
	}
	if value, ok := obj["ack"]; ok {
		if json.Unmarshal(value, &seq) == nil && seq > 0 {
			return "ack", seq, ""
		}
	}
	return "", 0, ""
}

func (c *Client) appendAndSend(ctx context.Context, ws *websocket.Conn, typ string, body any) error {
	if _, err := c.Log.Append(typ, body); err != nil {
		return err
	}
	return c.sendNew(ctx, ws)
}

// sendNew sends each local sequence at most once on this connection.
func (c *Client) sendNew(ctx context.Context, ws *websocket.Conn) error {
	entries, err := c.Log.Entries()
	if err != nil {
		return err
	}
	for c.sent < uint64(len(entries)) {
		b, err := wire.Canonical(entries[c.sent])
		if err != nil {
			return err
		}
		if len(b) > maxMessage {
			return errors.New("audit entry exceeds 1 MiB")
		}
		if err = ws.Write(ctx, websocket.MessageText, b); err != nil {
			return err
		}
		c.sent++
	}
	return nil
}

func (c *Client) Connect(ctx context.Context) error {
	url := c.URL
	if url == "" {
		url = URL
	}
	ws, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPClient: c.HTTPClient})
	if err != nil {
		return err
	}
	defer ws.CloseNow()
	ws.SetReadLimit(maxMessage)
	handshake, cancelHandshake := context.WithTimeout(ctx, 10*time.Second)
	defer cancelHandshake()
	for {
		_, raw, err := ws.Read(handshake)
		if err != nil {
			return err
		}
		kind, _, nonce := parseControl(raw)
		if kind != "nonce" {
			continue
		}
		hello, err := wire.Sign("aim-hello+jwt", "gateway", wire.Hello{GatewayID: c.State.Pins.GatewayID, Nonce: nonce, Version: c.Version, Time: time.Now().UTC().Format(time.RFC3339Nano)}, c.State.Private)
		if err != nil {
			return err
		}
		if err = ws.Write(handshake, websocket.MessageText, []byte(hello)); err != nil {
			return err
		}
		break
	}
	var entries []audit.Entry
	var resume uint64
	for {
		_, raw, err := ws.Read(handshake)
		if err != nil {
			return err
		}
		kind, seq, hash := parseControl(raw)
		if kind != "resume" {
			continue
		}
		entries, err = c.Log.Entries()
		if err != nil {
			return err
		}
		localHash := ""
		if seq > 0 && seq <= uint64(len(entries)) {
			localHash, err = audit.Hash(entries[seq-1])
			if err != nil {
				return err
			}
		}
		if seq > uint64(len(entries)) || localHash != hash {
			log.Printf("audit_divergence: server seq=%d local seq=%d", seq, len(entries))
			_ = ws.Close(websocket.StatusCode(4409), "audit_divergence")
			return errors.New("audit_divergence")
		}
		resume = seq
		break
	}
	// Reconcile delivery from the authoritative resume, then replay before new work.
	if c.Reconcile != nil {
		if err = c.Reconcile(ctx, resume, entries); err != nil {
			return err
		}
	}
	c.sent = resume
	if err = c.sendNew(ctx, ws); err != nil {
		return err
	}
	if c.Scan != nil {
		if err = c.Scan(ctx); err != nil {
			return err
		}
		if err = c.sendNew(ctx, ws); err != nil {
			return err
		}
	}
	if c.Poll != nil {
		if err = c.Poll(ctx); err != nil {
			return err
		}
		if err = c.sendNew(ctx, ws); err != nil {
			return err
		}
	}
	reads := make(chan []byte)
	errorsCh := make(chan error, 1)
	go func() {
		for {
			_, b, e := ws.Read(ctx)
			if e != nil {
				errorsCh <- e
				return
			}
			select {
			case reads <- b:
			case <-ctx.Done():
				return
			}
		}
	}()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	scan := time.NewTicker(15 * time.Minute)
	defer scan.Stop()
	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err = <-errorsCh:
			return err
		case <-heartbeat.C:
			pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err = ws.Ping(pingCtx)
			cancel()
			if err != nil {
				return err
			}
		case <-tick.C:
			if c.Poll != nil {
				if err = c.Poll(ctx); err != nil {
					return err
				}
			}
			if err = c.sendNew(ctx, ws); err != nil {
				return err
			}
		case <-scan.C:
			if c.Scan != nil {
				if err = c.Scan(ctx); err != nil {
					return err
				}
			}
			if err = c.sendNew(ctx, ws); err != nil {
				return err
			}
		case raw := <-reads:
			kind, seq, _ := parseControl(raw)
			if kind == "ack" {
				if seq <= c.sent && c.Delivered != nil {
					entries, err = c.Log.Entries()
					if err != nil {
						return err
					}
					if err = c.Delivered(ctx, entries[seq-1]); err != nil {
						return err
					}
				}
				continue
			}
			if len(raw) == 0 || raw[0] == '{' {
				continue
			}
			i, class, signer, e := c.verify(string(raw))
			if e != nil {
				log.Printf("invalid gateway instruction: %v", e)
				continue
			}
			if c.Handle == nil {
				continue
			}
			typ, body, e := c.Handle(ctx, i, class, signer)
			if e != nil {
				log.Printf("gateway instruction failed: %v", e)
				typ, body = "error", wire.GatewayError{Code: "instruction_failed", Message: "instruction failed"}
			}
			if typ != "" {
				if err = c.appendAndSend(ctx, ws, typ, body); err != nil {
					return err
				}
			}
		}
	}
}

func (c *Client) Run(ctx context.Context) error {
	backoff := time.Second
	for ctx.Err() == nil {
		err := c.Connect(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		log.Printf("gateway channel disconnected: %v", err)
		delay := min(backoff/2+time.Duration(rand.Int64N(int64(backoff))), 60*time.Second)
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
		backoff = min(backoff*2, 60*time.Second)
	}
	return fmt.Errorf("channel stopped: %w", ctx.Err())
}
