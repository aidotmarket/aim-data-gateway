package channel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/audit"
	"github.com/aidotmarket/aim-data-gateway/internal/pairing"
	"github.com/aidotmarket/aim-data-gateway/internal/profile"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	"github.com/coder/websocket"
)

const URL = "wss://api.ai.market/api/v1/gateway-channel"
const maxMessage = 1 << 20

func ProxyClient(address string) *http.Client {
	proxy := &url.URL{Scheme: "http", Host: address}
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy), DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext}}
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Client struct {
	URL          string
	HTTPClient   *http.Client
	State        *pairing.State
	PinsSnapshot func() pairing.Pins
	Log          *audit.Log
	Version      string
	// Handle processes a verified, unseen instruction and returns an audit answer.
	Handle   func(context.Context, wire.Instruction, string, string) (string, any, error)
	Complete func(context.Context, string) error
	// Scan appends an inventory generation after each successful resume.
	Scan   func(context.Context) error
	Canary func(context.Context) error
	// Poll appends any newly queued receipts, returning their local audit sequences.
	Poll func(context.Context) error
	// Delivered marks an outbox receipt after ack or a later resume.
	Delivered      func(context.Context, audit.Entry) error
	Reconcile      func(context.Context, uint64) error
	canaryMu       sync.Mutex
	sent           uint64
	heartbeatEvery time.Duration
}

func (c *Client) pinned() pairing.Pins {
	if c.PinsSnapshot != nil {
		return c.PinsSnapshot()
	}
	return c.State.Pins
}

func (c *Client) keys(class string) (map[string]ed25519.PublicKey, error) {
	return keys(c.pinned(), class)
}
func keys(pinned pairing.Pins, class string) (map[string]ed25519.PublicKey, error) {
	var pins []wire.Key
	if class == "permission" {
		pins = pinned.PermissionKeys
	} else {
		pins = pinned.ListingKeys
	}
	out := make(map[string]ed25519.PublicKey, len(pins))
	for _, p := range pins {
		if at := pinned.KeyExpires[p.KID]; at != "" {
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
	pinned := c.pinned()
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
			keys, e := keys(pinned, kind)
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
		keys, e := keys(pinned, class)
		if e != nil {
			return i, "", "", e
		}
		i, err = wire.VerifyInstruction(token, keys)
	}
	if err != nil {
		return i, "", "", err
	}
	if i.Audience != pinned.GatewayID {
		return i, "", "", errors.New("wrong instruction audience")
	}
	return i, class, header.KID, nil
}

func parseControl(raw []byte) (kind string, seq uint64, hash string) {
	obj, err := uniqueObject(raw)
	if err != nil || len(obj) != 1 {
		return "", 0, ""
	}
	if value, ok := obj["nonce"]; ok {
		var nonce string
		if json.Unmarshal(value, &nonce) == nil && hex64.MatchString(nonce) {
			return "nonce", 0, nonce
		}
	}
	if value, ok := obj["resume"]; ok {
		fields, err := uniqueObject(value)
		if err != nil || len(fields) != 2 {
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
func uniqueObject(raw []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return nil, errors.New("invalid control object")
	}
	out := make(map[string]json.RawMessage)
	for d.More() {
		t, err = d.Token()
		if err != nil {
			return nil, err
		}
		key, ok := t.(string)
		if !ok || out[key] != nil {
			return nil, errors.New("duplicate control key")
		}
		var value json.RawMessage
		if err = d.Decode(&value); err != nil {
			return nil, err
		}
		out[key] = value
	}
	if _, err = d.Token(); err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errors.New("trailing control data")
	}
	return out, nil
}

// sendNew sends each local sequence at most once on this connection.
func (c *Client) sendNew(ctx context.Context, ws *websocket.Conn) error {
	for c.sent < c.Log.Sequence() {
		entry, err := c.Log.Read(c.sent + 1)
		if err != nil {
			return err
		}
		b, err := wire.Canonical(entry)
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
		hello, err := wire.Sign("aim-hello+jwt", "gateway", wire.Hello{GatewayID: c.pinned().GatewayID, Nonce: nonce, Version: c.Version, Time: time.Now().UTC().Format(time.RFC3339Nano)}, c.State.Private)
		if err != nil {
			return err
		}
		if err = ws.Write(handshake, websocket.MessageText, []byte(hello)); err != nil {
			return err
		}
		break
	}
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
		localHash := ""
		if seq > 0 && seq <= c.Log.Sequence() {
			entry, readErr := c.Log.Read(seq)
			if readErr != nil {
				return readErr
			}
			localHash, err = audit.Hash(entry)
			if err != nil {
				return err
			}
		}
		if seq > c.Log.Sequence() || localHash != hash {
			log.Printf("audit_divergence: server seq=%d local seq=%d", seq, c.Log.Sequence())
			_ = ws.Close(websocket.StatusCode(4409), "audit_divergence")
			return errors.New("audit_divergence")
		}
		resume = seq
		break
	}
	// Reconcile delivery from the authoritative resume, then replay before new work.
	if c.Reconcile != nil {
		if err = c.Reconcile(ctx, resume); err != nil {
			return err
		}
	}
	c.sent = resume
	if err = c.sendNew(ctx, ws); err != nil {
		return err
	}
	workCtx, stopWork := context.WithCancel(ctx)
	defer stopWork()
	jobs := make(chan func() error, 64)
	descriptions := make(chan func() error, 64)
	wake := make(chan struct{}, 1)
	workErr := make(chan error, 1)
	worker := func(lane <-chan func() error) {
		for {
			select {
			case <-workCtx.Done():
				return
			case job := <-lane:
				if e := job(); e != nil {
					select {
					case workErr <- e:
					default:
					}
					return
				}
				select {
				case wake <- struct{}{}:
				default:
				}
			}
		}
	}
	go worker(jobs)
	go worker(descriptions)
	queue := func(lane chan<- func() error, job func() error) error {
		select {
		case lane <- job:
			return nil
		default:
			return errors.New("channel work queue full")
		}
	}
	if c.Canary != nil {
		if err = queue(jobs, func() error { c.canaryMu.Lock(); defer c.canaryMu.Unlock(); return c.Canary(workCtx) }); err != nil {
			return err
		}
	}
	if c.Scan != nil {
		if err = queue(jobs, func() error { return c.Scan(workCtx) }); err != nil {
			return err
		}
	}
	process := func(i wire.Instruction, class, signer string) error {
		if c.Handle == nil {
			return nil
		}
		typ, body, e := c.Handle(workCtx, i, class, signer)
		if workCtx.Err() != nil {
			return workCtx.Err()
		}
		failed := e != nil
		if e != nil {
			log.Printf("gateway instruction failed: %v", e)
			code := "instruction_failed"
			if i.Op == "describe" {
				code = "read_error"
				if errors.Is(e, profile.ErrUnsupportedFormat) {
					code = "unsupported_format"
				}
				if errors.Is(e, profile.ErrGatewayTimeout) || errors.Is(e, context.DeadlineExceeded) {
					code = "gateway_timeout"
				}
			}
			typ, body = "error", wire.GatewayError{Code: code, Message: code}
		}
		if typ != "" {
			if _, e = c.Log.Append(typ, body); e != nil {
				return e
			}
		}
		if failed {
			return nil
		}
		if c.Complete != nil {
			return c.Complete(workCtx, i.IID)
		}
		return nil
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
	canaryTick := time.NewTicker(time.Hour)
	defer canaryTick.Stop()
	interval := c.heartbeatEvery
	if interval == 0 {
		interval = 30 * time.Second
	}
	heartbeat := time.NewTicker(interval)
	defer heartbeat.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err = <-errorsCh:
			return err
		case err = <-workErr:
			return err
		case <-wake:
			if err = c.sendNew(ctx, ws); err != nil {
				return err
			}
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
				if err = queue(jobs, func() error { return c.Scan(workCtx) }); err != nil {
					return err
				}
			}
		case <-canaryTick.C:
			if c.Canary != nil {
				if err = queue(jobs, func() error { c.canaryMu.Lock(); defer c.canaryMu.Unlock(); return c.Canary(workCtx) }); err != nil {
					return err
				}
			}
		case raw := <-reads:
			kind, seq, _ := parseControl(raw)
			if kind == "ack" {
				if seq <= c.sent && c.Delivered != nil {
					entry, readErr := c.Log.Read(seq)
					if readErr != nil {
						return readErr
					}
					if err = c.Delivered(ctx, entry); err != nil {
						return err
					}
				}
				continue
			}
			if len(raw) == 0 || raw[0] == '{' {
				continue
			}
			token := string(raw)
			if err = queue(jobs, func() error {
				i, class, signer, e := c.verify(token)
				if e != nil {
					log.Printf("invalid gateway instruction: %v", e)
					return nil
				}
				if i.Op == "describe" {
					return queue(descriptions, func() error { return process(i, class, signer) })
				}
				return process(i, class, signer)
			}); err != nil {
				return err
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
		delay := max(time.Second, min(backoff/2+time.Duration(rand.Int64N(int64(backoff))), 60*time.Second))
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
