package awsverification

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func TestProductionS3HTTPClientBounds(t *testing.T) {
	c := S3HTTPClient()
	defer c.CloseIdleConnections()
	tr, ok := c.Transport.(*http.Transport)
	if !ok || c.Timeout != 0 || tr.Proxy != nil || tr.DialContext == nil || s3Dialer.Timeout != 10*time.Second || tr.TLSHandshakeTimeout != 10*time.Second || tr.ResponseHeaderTimeout != 30*time.Second || tr.IdleConnTimeout != 90*time.Second {
		t.Fatal("S3 must bound setup and headers without a whole-request timeout")
	}
	if c.CheckRedirect == nil || !errors.Is(c.CheckRedirect(nil, nil), ErrRefused) {
		t.Fatal("S3 redirects must remain refused")
	}
}

func streamingSDK(t *testing.T, serve http.HandlerFunc) S3Client {
	t.Helper()
	server := httptest.NewServer(serve)
	t.Cleanup(server.Close)
	c := S3HTTPClient()
	t.Cleanup(c.CloseIdleConnections)
	tr := c.Transport.(*http.Transport)
	tr.ResponseHeaderTimeout = 50 * time.Millisecond
	tr.TLSHandshakeTimeout = 50 * time.Millisecond
	return S3Client{Client: s3.New(s3.Options{
		Region: "eu-north-1", Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""),
		BaseEndpoint: aws.String(server.URL), UsePathStyle: true, HTTPClient: c,
		RetryMaxAttempts: 1,
	})}
}

func TestS3BodyStreamsBeyondMetadataTimeout(t *testing.T) {
	c := streamingSDK(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "4")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		for _, b := range []byte("data") {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(75 * time.Millisecond):
			}
			w.Write([]byte{b})
			w.(http.Flusher).Flush()
		}
	})
	streamCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	started := time.Now()
	body, err := c.Get(streamCtx, Request{Bucket: "bucket", Key: "key", VersionID: "version", End: -1})
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	raw, err := io.ReadAll(body)
	if err != nil || string(raw) != "data" || time.Since(started) <= 50*time.Millisecond || streamCtx.Err() != nil {
		t.Fatal("body did not outlive metadata timeout under its scan context", string(raw), err)
	}
}

func stalledS3(t *testing.T, data []byte) S3Client {
	t.Helper()
	return streamingSDK(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.Header().Set("ETag", `"RAW_ETAG_MARKER"`)
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodHead {
			return
		}
		w.Write(data[:1])
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	})
}

func TestS3StalledBodyStopsAtContextDeadline(t *testing.T) {
	c := stalledS3(t, []byte("data"))
	streamCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	deadline, _ := streamCtx.Deadline()
	body, err := c.Get(streamCtx, Request{Bucket: "bucket", Key: "key", VersionID: "version", End: -1})
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	raw, err := io.ReadAll(body)
	stopped := time.Now()
	if string(raw) != "d" || !errors.Is(err, context.DeadlineExceeded) || !errors.Is(streamCtx.Err(), context.DeadlineExceeded) || stopped.Before(deadline) || stopped.Sub(deadline) > time.Second {
		t.Fatal("stalled read must stop on context deadline", string(raw), err, stopped.Sub(deadline))
	}
}

func TestS3StalledScanReportsOnlyTerminalTimeout(t *testing.T) {
	f := newFixture(t)
	f.job(t, 1, "scan")
	f.h.S3 = stalledS3(t, f.s3.objects["RAW_KEY_MARKER/data.csv"])
	// Invoke reserves 30 seconds after the scan deadline for the failure outbox.
	invokeCtx, cancel := context.WithTimeout(ctx, 30*time.Second+250*time.Millisecond)
	defer cancel()
	if err := f.h.Invoke(invokeCtx); err != nil {
		t.Fatal(err)
	}
	if len(f.backend.reports) != 1 {
		t.Fatal("expected exactly the spec failure report", len(f.backend.reports))
	}
	var envelope map[string]any
	if err := json.Unmarshal(f.backend.reports[0], &envelope); err != nil {
		t.Fatal(err)
	}
	raw, err := wire.DecodeDocument(envelope["document_b64"].(string), wire.MaxScanDocument)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err = json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if envelope["variant"] != "terminal" || document["terminal_error_code"] != "timeout" || envelope["member_sha256s"] != nil || document["objects"] != nil || document["coverage"] != nil || document["content_sha256"] != nil {
		t.Fatal("stalled scan emitted findings instead of only terminal timeout", envelope, document)
	}
}
