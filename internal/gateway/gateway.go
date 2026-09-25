package gateway

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/audit"
	"github.com/aidotmarket/aim-data-gateway/internal/channel"
	"github.com/aidotmarket/aim-data-gateway/internal/config"
	"github.com/aidotmarket/aim-data-gateway/internal/door"
	"github.com/aidotmarket/aim-data-gateway/internal/ids"
	"github.com/aidotmarket/aim-data-gateway/internal/inventory"
	"github.com/aidotmarket/aim-data-gateway/internal/ledger"
	"github.com/aidotmarket/aim-data-gateway/internal/pairing"
	"github.com/aidotmarket/aim-data-gateway/internal/profile"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
)

type Gateway struct {
	Config          config.Config
	State           pairing.State
	Dir             string
	Ledger          *ledger.Ledger
	Log             *audit.Log
	previous        []inventory.Record
	generation      uint64
	inventoryMu     sync.RWMutex
	keyMu           sync.RWMutex
	permissionKeys  map[string]ed25519.PublicKey
	unmarkedReceipt uint64
	unmarkedAudit   uint64
}

func Open(dir string, cfg config.Config, state pairing.State) (*Gateway, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	l, err := ledger.Open(filepath.Join(dir, "gateway.db"), state.Private, "gateway")
	if err != nil {
		return nil, err
	}
	a, err := audit.Open(filepath.Join(dir, "audit"), state.Private)
	if err != nil {
		l.Close()
		return nil, err
	}
	g := &Gateway{Config: cfg, State: state, Dir: dir, Ledger: l, Log: a}
	active := map[string]inventory.Record{}
	err = a.Walk(func(entry audit.Entry) error {
		if entry.MessageType == "receipt" {
			var receipt wire.Receipt
			if err = json.Unmarshal(entry.Body, &receipt); err != nil {
				return err
			}
			if err = l.MarkReceiptAudited(context.Background(), receipt.Seq, entry.Seq); err != nil {
				return err
			}
		}
		if entry.MessageType != "inventory" {
			return nil
		}
		var batch inventory.Batch
		if err = json.Unmarshal(entry.Body, &batch); err != nil {
			return err
		}
		if batch.Generation > g.generation {
			g.generation = batch.Generation
		}
		for _, f := range batch.Files {
			if f.Present {
				active[f.FileID] = inventory.Record{Phase1: f}
			} else {
				delete(active, f.FileID)
			}
		}
		return nil
	})
	if err != nil {
		l.Close()
		return nil, err
	}
	for _, r := range active {
		g.previous = append(g.previous, r)
	}
	return g, nil
}

func (g *Gateway) Scan(ctx context.Context) error {
	keys, err := ids.Derive(g.State.Secret)
	if err != nil {
		return err
	}
	records, err := inventory.ScanWithPreviousContext(ctx, g.Config, keys, g.previous)
	if err != nil {
		return err
	}
	for _, r := range records {
		if r.Phase1.Present {
			if err = g.Ledger.PutFile(ctx, r); err != nil {
				return err
			}
		} else if err = g.Ledger.MarkMissing(ctx, r.Phase1.FileID); err != nil {
			return err
		}
	}
	g.inventoryMu.Lock()
	g.generation++
	generation := g.generation
	g.inventoryMu.Unlock()
	for _, batch := range inventory.Batches(records, generation) {
		if _, err = g.Log.Append("inventory", batch); err != nil {
			return err
		}
	}
	g.inventoryMu.Lock()
	g.previous = g.previous[:0]
	for _, r := range records {
		if r.Phase1.Present {
			g.previous = append(g.previous, r)
		}
	}
	g.inventoryMu.Unlock()
	return nil
}

func (g *Gateway) outbox(ctx context.Context) ([]ledger.QueuedReceipt, error) {
	return g.Ledger.PendingReceipts(ctx)
}
func (g *Gateway) Poll(ctx context.Context) error {
	queued, err := g.outbox(ctx)
	if err != nil {
		return err
	}
	for _, r := range queued {
		if g.unmarkedReceipt == r.Seq {
			if err = g.Ledger.MarkReceiptAudited(ctx, r.Seq, g.unmarkedAudit); err != nil {
				return err
			}
			g.unmarkedReceipt = 0
			continue
		}
		var receipt wire.Receipt
		keys := map[string]ed25519.PublicKey{g.Ledger.KID: g.State.Private.Public().(ed25519.PublicKey)}
		if err = wire.VerifyGatewayAnswer(r.Body, "receipt", keys, &receipt); err != nil {
			return err
		}
		if receipt.Seq != r.Seq {
			return errors.New("receipt outbox sequence mismatch")
		}
		entry, appendErr := g.Log.Append("receipt", receipt)
		if appendErr != nil {
			return appendErr
		}
		g.unmarkedReceipt, g.unmarkedAudit = r.Seq, entry.Seq
		if err = g.Ledger.MarkReceiptAudited(ctx, r.Seq, entry.Seq); err != nil {
			return err
		}
		g.unmarkedReceipt = 0
	}
	return nil
}
func (g *Gateway) Delivered(ctx context.Context, entry audit.Entry) error {
	if entry.MessageType != "receipt" {
		return nil
	}
	var receipt wire.Receipt
	if err := json.Unmarshal(entry.Body, &receipt); err != nil {
		return err
	}
	return g.Ledger.MarkReceiptDelivered(ctx, receipt.Seq)
}
func (g *Gateway) Reconcile(ctx context.Context, seq uint64) error {
	return g.Ledger.ReconcileReceipts(ctx, seq)
}

func (g *Gateway) Handle(ctx context.Context, i wire.Instruction, class, signer string) (string, any, error) {
	seen, err := g.Ledger.WasSeen(ctx, i.IID)
	if err != nil || seen {
		return "", nil, err
	}
	switch i.Op {
	case "offer", "unoffer":
		ack := wire.OfferAck{IID: i.IID, FileID: i.FileID}
		state := "withdrawn"
		if i.Op == "offer" {
			state = "offered"
			f, e := g.Ledger.File(ctx, i.FileID)
			refusal := ""
			if e != nil || !f.Present {
				refusal = "file_missing"
			} else if f.SHA256 != i.SHA256 || f.Changed || !f.ValidBlocks() {
				refusal = "file_changed"
			} else if !ledger.WithinCeiling(g.Config, f) {
				refusal = "outside_ceiling"
			}
			if refusal != "" {
				ack.Refusal = &refusal
				return "offer_ack", ack, nil
			}
		}
		if err = g.Ledger.PutOffer(ctx, ledger.Offer{FileID: i.FileID, SHA256: i.SHA256, ListingVersionID: i.ListingVersionID, IID: i.IID, State: state, KeyClass: "listing"}); err != nil {
			return "", nil, err
		}
		ack.Ready = true
		return "offer_ack", ack, nil
	case "describe":
		g.inventoryMu.RLock()
		previous := append([]inventory.Record(nil), g.previous...)
		g.inventoryMu.RUnlock()
		for _, r := range previous {
			if r.Phase1.FileID != i.FileID {
				continue
			}
			profileCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
			d, e := profile.FileContext(profileCtx, r, g.Config.ColumnRule(r.Source, r.RelativePath))
			if profileCtx.Err() != nil {
				e = profile.ErrGatewayTimeout
			}
			cancel()
			if e != nil {
				return "", nil, e
			}
			body := wire.Description{FileID: i.FileID, SHA256: d.SHA256, RowCount: d.RowCount, Columns: make([]wire.Column, 0, len(d.Columns))}
			for _, col := range d.Columns {
				body.Columns = append(body.Columns, wire.Column{Name: col.Name, Type: col.Type, NullRatePct: col.NullRatePct, DistinctBucket: col.DistinctBucket})
			}
			return "description", body, nil
		}
		return "", nil, errors.New("file_missing")
	case "revoke":
		a, e := g.Ledger.RevokeInstruction(ctx, i.IID, i.JTI)
		return "revocation_ack", a, e
	case "prepare":
		a, e := g.Ledger.Prepare(ctx, i, g.Config)
		return "prepare_ack", a, e
	case "key_rotation":
		// The channel verifies the outgoing key before this update.
		g.keyMu.Lock()
		pins := copyPins(g.State.Pins)
		if pins.KeyExpires == nil {
			pins.KeyExpires = map[string]string{}
		}
		if pins.KeyExpires[signer] == "" {
			pins.KeyExpires[signer] = time.Now().Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
		}
		var permissionKeys map[string]ed25519.PublicKey
		if class == "permission" {
			pins.PermissionKeys = appendUniqueKeys(pins.PermissionKeys, i.Keys)
			permissionKeys, err = keyMap(pins.PermissionKeys)
		} else {
			pins.ListingKeys = appendUniqueKeys(pins.ListingKeys, i.Keys)
		}
		if err == nil {
			err = g.savePins(pins)
		}
		if err == nil {
			g.State.Pins = pins
			if class == "permission" {
				g.permissionKeys = permissionKeys
			}
		}
		g.keyMu.Unlock()
		return "", nil, err
	case "minimum_version":
		g.keyMu.Lock()
		pins := copyPins(g.State.Pins)
		pins.MinimumVersion = i.Version
		err = g.savePins(pins)
		if err == nil {
			g.State.Pins = pins
		}
		g.keyMu.Unlock()
		return "", nil, err
	default:
		return "", nil, errors.New("unknown instruction")
	}
}
func appendUniqueKeys(existing, added []wire.Key) []wire.Key {
	for _, key := range added {
		found := false
		for _, old := range existing {
			if old.KID == key.KID {
				found = true
				break
			}
		}
		if !found {
			existing = append(existing, key)
		}
	}
	return existing
}
func copyPins(p pairing.Pins) pairing.Pins {
	p.PermissionKeys = append([]wire.Key(nil), p.PermissionKeys...)
	p.ListingKeys = append([]wire.Key(nil), p.ListingKeys...)
	if p.KeyExpires != nil {
		copyMap := make(map[string]string, len(p.KeyExpires))
		for kid, at := range p.KeyExpires {
			copyMap[kid] = at
		}
		p.KeyExpires = copyMap
	}
	return p
}
func (g *Gateway) savePins(pins pairing.Pins) error {
	b, err := json.Marshal(pins)
	if err != nil {
		return err
	}
	path := filepath.Join(g.Dir, "pins.json")
	f, err := os.OpenFile(path+".tmp", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(path+".tmp", path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func keyMap(keys []wire.Key) (map[string]ed25519.PublicKey, error) {
	out := make(map[string]ed25519.PublicKey)
	for _, k := range keys {
		b, err := base64.RawURLEncoding.DecodeString(k.Key)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, errors.New("invalid key")
		}
		out[k.KID] = b
	}
	return out, nil
}

func (g *Gateway) Run(ctx context.Context, version string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	permissionKeys, err := keyMap(g.State.Pins.PermissionKeys)
	if err != nil {
		return err
	}
	g.permissionKeys = permissionKeys
	d := &door.Door{Ledger: g.Ledger, Config: func() config.Config { return g.Config }, GatewayID: g.State.Pins.GatewayID, PermissionKeyProvider: func() map[string]ed25519.PublicKey {
		g.keyMu.RLock()
		defer g.keyMu.RUnlock()
		keys := make(map[string]ed25519.PublicKey, len(g.permissionKeys))
		for kid, key := range g.permissionKeys {
			at := g.State.Pins.KeyExpires[kid]
			if at != "" {
				deadline, err := time.Parse(time.RFC3339Nano, at)
				if err != nil || !time.Now().Before(deadline) {
					continue
				}
			}
			keys[kid] = key
		}
		return keys
	}, GatewayKey: g.State.Private, GatewayKID: "gateway", RecoveryContext: ctx}
	server := d.Server(g.Config.Door.Listen)
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.ListenAndServe() }()
	defer server.Shutdown(context.Background())
	client := &channel.Client{State: &g.State, Log: g.Log, Version: version, Handle: g.Handle, Complete: func(ctx context.Context, iid string) error { _, err := g.Ledger.Seen(ctx, iid); return err }, Scan: g.Scan, Poll: g.Poll, Delivered: g.Delivered, Reconcile: g.Reconcile}
	client.PinsSnapshot = func() pairing.Pins {
		g.keyMu.RLock()
		defer g.keyMu.RUnlock()
		return copyPins(g.State.Pins)
	}
	if g.Config.Egress.ConnectProxy != "" {
		proxyURL := &url.URL{Scheme: "http", Host: g.Config.Egress.ConnectProxy}
		client.HTTPClient = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext}}
	}
	go func() { serverErr <- client.Run(ctx) }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err = <-serverErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func StateDir() string {
	if s := os.Getenv("AIM_GATEWAY_STATE"); s != "" {
		return s
	}
	return "/state"
}

func LoadOrPair(ctx context.Context, dir, code, version string, client *http.Client) (pairing.State, error) {
	if code != "" {
		if client == nil {
			client = http.DefaultClient
		}
		return pairing.Pair(ctx, dir, code, version, pairing.PairURL, client)
	}
	return pairing.Load(dir)
}
