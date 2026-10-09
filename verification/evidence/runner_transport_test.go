//go:build evidence

package evidence

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// testBase accepts only the host-exposed backend or the S1656 backend service.
// No arbitrary caller-provided service allowlist, proxy, userinfo or path prefix.
func testBase(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Scheme != "http" || u.User != nil || u.Opaque != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" ||
		(u.Path != "" && u.Path != "/") {
		return nil, errors.New("evidence backend must be an HTTP test origin")
	}
	switch u.Hostname() {
	case "localhost", "127.0.0.1", "backend":
	default:
		return nil, errors.New("evidence backend host refused")
	}
	if strings.HasSuffix(u.Host, ":") {
		return nil, errors.New("empty backend port")
	}
	u.Path = ""
	return u, nil
}

type testTransport struct {
	base *url.URL
	next http.RoundTripper
}

func (t testTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Only product snapshot calls use the logical production origin. Nothing
	// is ever dialed there: clone and map before the sole network RoundTrip.
	logicalSnapshot := req.URL.Scheme == "https" && req.URL.Host == "api.ai.market" &&
		req.Method == http.MethodGet && strings.HasPrefix(req.URL.Path, "/api/v1/verification-runners/") &&
		strings.Contains(req.URL.Path, "/snapshot/") && req.URL.RawQuery == ""
	local := req.URL.Scheme == t.base.Scheme && req.URL.Host == t.base.Host
	if !logicalSnapshot && !local {
		return nil, errors.New("evidence outbound origin refused")
	}
	clone := req.Clone(req.Context())
	u := *req.URL
	u.Scheme, u.Host = t.base.Scheme, t.base.Host
	clone.URL, clone.Host = &u, t.base.Host
	resp, err := t.next.RoundTrip(clone)
	if err == nil && logicalSnapshot {
		// The product fetcher checks its logical response origin. Preserve that
		// metadata only; status, headers, body and signed bytes remain untouched.
		resp.Request = req
	}
	return resp, err
}

func testClient(base *url.URL) *http.Client {
	return &http.Client{Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     testTransport{base: base, next: &http.Transport{Proxy: nil}}}
}
