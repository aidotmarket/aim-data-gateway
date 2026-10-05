package awsverification

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"io"
	"net/http"
	"time"
)

// The Logs JSON API uses SDK core SigV4, avoiding an additional service module.
// PutLogEvents success is the audit acknowledgment required before S3 access.
type Logs struct {
	Client                *http.Client
	Credentials           aws.CredentialsProvider
	Region, Group, Stream string
	Now                   func() time.Time
}

func (l Logs) call(ctx context.Context, op string, body any) error {
	b, e := json.Marshal(body)
	if e != nil {
		return ErrRefused
	}
	r, e := http.NewRequestWithContext(ctx, "POST", "https://logs."+l.Region+".amazonaws.com/", bytes.NewReader(b))
	if e != nil {
		return ErrRefused
	}
	r.Header.Set("Content-Type", "application/x-amz-json-1.1")
	r.Header.Set("X-Amz-Target", "Logs_20140328."+op)
	c, e := l.Credentials.Retrieve(ctx)
	if e != nil {
		return ErrRefused
	}
	at := time.Now()
	if l.Now != nil {
		at = l.Now()
	}
	if e = v4.NewSigner().SignHTTP(ctx, c, r, wire.Digest(b), "logs", l.Region, at); e != nil {
		return ErrRefused
	}
	resp, e := l.Client.Do(r)
	if e != nil {
		return ErrRefused
	}
	defer resp.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(resp.Body, 8193))
	if e != nil || len(raw) > 8192 {
		return ErrRefused
	}
	if resp.StatusCode == 200 {
		if op == "PutLogEvents" {
			var result map[string]json.RawMessage
			if json.Unmarshal(raw, &result) != nil || result["rejectedLogEventsInfo"] != nil || result["rejectedEntityInfo"] != nil {
				return ErrRefused
			}
		}
		return nil
	}
	var x struct {
		Type string `json:"__type"`
	}
	if op == "CreateLogStream" && json.Unmarshal(raw, &x) == nil && x.Type == "ResourceAlreadyExistsException" {
		return nil
	}
	return ErrRefused
}
func (l Logs) Event(ctx context.Context, event, hash string) error {
	switch event {
	case "received", "accepted", "refused", "committed", "reported", "interrupted", "expired", "key_rotation", "tls_pin_mismatch":
	default:
		return ErrRefused
	}
	if !hex64.MatchString(hash) {
		return ErrRefused
	}
	if e := l.call(ctx, "CreateLogStream", map[string]any{"logGroupName": l.Group, "logStreamName": l.Stream}); e != nil {
		return e
	}
	at := time.Now()
	if l.Now != nil {
		at = l.Now()
	}
	msg, _ := json.Marshal(map[string]string{"event": event, "hash": hash})
	return l.call(ctx, "PutLogEvents", map[string]any{"logGroupName": l.Group, "logStreamName": l.Stream, "logEvents": []any{map[string]any{"timestamp": at.UnixMilli(), "message": string(msg)}}})
}
