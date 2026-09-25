package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"github.com/aidotmarket/aim-data-gateway/internal/config"
	"github.com/aidotmarket/aim-data-gateway/internal/pairing"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
)

func TestReceiptOutboxAckAndResume(t *testing.T) {
	dir := t.TempDir()
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	source := t.TempDir()
	c := config.Config{Sources: []config.Source{{Name: "one", Path: source}}}
	state := pairing.State{Private: key, Secret: make([]byte, 32)}
	g, err := Open(dir, c, state)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	receipt := wire.Receipt{Op: "receipt", OrderID: "22222222-2222-4222-8222-222222222222", FileID: "0123456789abcdef0123456789abcdef", SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", JTIs: []string{}, Transmitted: []wire.Interval{}, Outcome: "in_progress", BlocksVerified: true, Seq: 1}
	token, err := wire.Sign("aim-receipt+jwt", "gateway", receipt, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = g.Ledger.DB.Exec(`INSERT INTO receipts_outbox(seq,body) VALUES(1,?)`, token); err != nil {
		t.Fatal(err)
	}
	if err = g.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if err = g.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	entries, err := g.Log.Entries()
	if err != nil || len(entries) != 1 {
		t.Fatalf("receipt appended more than once: %d %v", len(entries), err)
	}
	if bytes.Contains(entries[0].Body, []byte(token)) || !bytes.Contains(entries[0].Body, []byte(`"op":"receipt"`)) {
		t.Fatal("receipt audit body contains signature or lacks claims")
	}
	var sent any
	if err = g.Ledger.DB.QueryRow(`SELECT sent_at FROM receipts_outbox WHERE seq=1`).Scan(&sent); err != nil || sent != nil {
		t.Fatalf("delivered before ack: %v %v", sent, err)
	}
	if err = g.Delivered(ctx, entries[0]); err != nil {
		t.Fatal(err)
	}
	if err = g.Ledger.DB.QueryRow(`SELECT sent_at FROM receipts_outbox WHERE seq=1`).Scan(&sent); err != nil || sent == nil {
		t.Fatalf("ack did not deliver: %v %v", sent, err)
	}
	if err = g.Reconcile(ctx, 0, entries); err != nil {
		t.Fatal(err)
	}
	if err = g.Ledger.DB.QueryRow(`SELECT sent_at FROM receipts_outbox WHERE seq=1`).Scan(&sent); err != nil || sent != nil {
		t.Fatalf("forged ack not corrected: %v %v", sent, err)
	}
	if err = g.Reconcile(ctx, 1, entries); err != nil {
		t.Fatal(err)
	}
	if err = g.Ledger.DB.QueryRow(`SELECT sent_at FROM receipts_outbox WHERE seq=1`).Scan(&sent); err != nil || sent == nil {
		t.Fatalf("later resume did not deliver: %v %v", sent, err)
	}
	if err = g.Ledger.Close(); err != nil {
		t.Fatal(err)
	}
	// A crash after the audit append but before recording an ack cannot drop the receipt.
	g, err = Open(dir, c, state)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Ledger.Close()
	if err = g.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	entries, err = g.Log.Entries()
	if err != nil || len(entries) != 1 {
		t.Fatalf("crash duplicated receipt: %d %v", len(entries), err)
	}
	if _, err = os.Stat(filepath.Join(dir, "audit", "000000.jsonl")); err != nil {
		t.Fatal(err)
	}
}
