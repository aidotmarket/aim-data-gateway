package awsverification

import (
	"context"
	"encoding/json"
	"io"
)

// Logs writes bounded audit records to Lambda stdout. The runtime forwards
// these to CloudWatch; the verifier has no Logs API client or extra egress.
// A successful local write is required before reads. It cannot acknowledge
// downstream CloudWatch delivery, which is managed by the Lambda runtime.
type Logs struct {
	Output io.Writer
}

func (l Logs) Event(ctx context.Context, event, hash string) error {
	switch event {
	case "received", "accepted", "refused", "committed", "reported", "interrupted", "expired", "key_rotation", "tls_pin_mismatch":
	default:
		return ErrRefused
	}
	if ctx.Err() != nil || l.Output == nil || !hex64.MatchString(hash) {
		return ErrRefused
	}
	msg, err := json.Marshal(map[string]string{"event": event, "hash": hash})
	if err != nil {
		return ErrRefused
	}
	msg = append(msg, '\n')
	n, err := l.Output.Write(msg)
	if err != nil || n != len(msg) {
		return ErrRefused
	}
	return nil
}
