package cloudflareverification

import (
	"context"
	core "github.com/aidotmarket/aim-data-gateway/verification"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

const BridgeHost = "r2-bridge.internal"

// Capability is signed by the DO and names one durably admitted invocation.
// Only a member index goes onto the wire; raw object names never select data.
type HTTPBridge struct {
	Client     *http.Client
	Capability string
}

func BridgeClient() *http.Client {
	d := net.Dialer{Timeout: 10 * time.Second}
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return ErrRefused }, Transport: &http.Transport{Proxy: nil, ResponseHeaderTimeout: 15 * time.Second, MaxResponseHeaderBytes: 16 << 10, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != BridgeHost+":80" {
			return nil, ErrRefused
		}
		return d.DialContext(ctx, network, address)
	}}}
}
func (b HTTPBridge) request(ctx context.Context, method string, q Request) (*http.Response, error) {
	if q.MemberIndex < 0 || !validTokenPart(b.Capability) {
		return nil, ErrRefused
	}
	r, e := http.NewRequestWithContext(ctx, method, "http://"+BridgeHost+"/member/"+strconv.Itoa(q.MemberIndex), nil)
	if e != nil {
		return nil, e
	}
	r.Header.Set("Authorization", "Bearer "+b.Capability)
	if q.Range != nil {
		if method != "GET" || q.Range.Offset < 0 || q.Range.Length <= 0 {
			return nil, ErrRefused
		}
		r.Header.Set("Range", "bytes="+strconv.FormatInt(q.Range.Offset, 10)+"-"+strconv.FormatInt(q.Range.Offset+q.Range.Length-1, 10))
	}
	return b.Client.Do(r)
}
func validTokenPart(s string) bool { return len(s) > 0 && len(s) < 4096 }
func metadata(r *http.Response) (*Head, error) {
	size, e := strconv.ParseInt(r.Header.Get("X-Object-Size"), 10, 64)
	etag := r.Header.Get("X-Object-Etag")
	if e != nil || size < 0 || etag == "" || (r.StatusCode != 200 && r.StatusCode != 206) {
		return nil, core.ErrArtifactChanged
	}
	return &Head{Size: size, ETag: etag}, nil
}
func (b HTTPBridge) Head(ctx context.Context, q Request) (*Head, error) {
	r, e := b.request(ctx, "HEAD", q)
	if e != nil {
		return nil, e
	}
	defer r.Body.Close()
	return metadata(r)
}
func (b HTTPBridge) Get(ctx context.Context, q Request) (GetResult, error) {
	r, e := b.request(ctx, "GET", q)
	if e != nil {
		return GetResult{}, e
	}
	m, e := metadata(r)
	if e != nil {
		r.Body.Close()
		return GetResult{}, e
	}
	var got *Range
	if q.Range != nil {
		off, e1 := strconv.ParseInt(r.Header.Get("X-Range-Offset"), 10, 64)
		length, e2 := strconv.ParseInt(r.Header.Get("X-Range-Length"), 10, 64)
		if e1 != nil || e2 != nil || r.StatusCode != 206 {
			r.Body.Close()
			return GetResult{}, core.ErrArtifactChanged
		}
		got = &Range{Offset: off, Length: length}
	} else if r.StatusCode != 200 {
		r.Body.Close()
		return GetResult{}, core.ErrArtifactChanged
	}
	return GetResult{Metadata: m, Range: got, Body: r.Body}, nil
}

var _ io.ReadCloser = (*fullReader)(nil)
