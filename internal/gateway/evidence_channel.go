//go:build evidence

package gateway

import (
	"context"

	"github.com/aidotmarket/aim-data-gateway/internal/channel"
	"github.com/aidotmarket/aim-data-gateway/internal/pairing"
)

// EvidenceChannel wires the same product callbacks as Run without starting a
// delivery door or a public DNS canary. The caller supplies only test transport.
func (g *Gateway) EvidenceChannel(version string) *channel.Client {
	c := &channel.Client{State: &g.State, Log: g.Log, Version: version,
		Handle: g.Handle, Complete: func(ctx context.Context, iid string) error {
			_, err := g.Ledger.Seen(ctx, iid)
			return err
		}, Scan: g.Scan, Poll: g.Poll, Delivered: g.Delivered, Reconcile: g.Reconcile,
		Verification: g.VerificationControl, VerificationRefused: g.Verifier.QueueRefusal}
	c.PinsSnapshot = func() pairing.Pins {
		g.keyMu.RLock()
		defer g.keyMu.RUnlock()
		return copyPins(g.State.Pins)
	}
	return c
}
