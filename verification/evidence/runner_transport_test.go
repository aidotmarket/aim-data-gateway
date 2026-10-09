//go:build evidence

package evidence

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
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

// Compose access requires both a narrow RFC1918 subnet and the exact backend
// address recorded from the designated S1656 network. Hostnames alone confer no trust.
func constrainedClient(base *url.URL, cidr, backend string) (*http.Client, error) {
	d, err := newTestDialer(cidr, backend)
	if err != nil {
		return nil, err
	}
	if base.Hostname() == "backend" && !d.backend.IsValid() {
		return nil, errors.New("backend requires explicit Compose subnet and backend IP")
	}
	return &http.Client{Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     testTransport{base: base, next: &http.Transport{Proxy: nil, DialContext: d.DialContext}}}, nil
}
func testClient(base *url.URL) *http.Client {
	c, err := constrainedClient(base, "", "")
	if err != nil {
		panic(err)
	}
	return c
}

type testDialer struct {
	subnet  netip.Prefix
	backend netip.Addr
	resolve func(context.Context, string) ([]netip.Addr, error)
	dial    func(context.Context, string, string) (net.Conn, error)
}

func newTestDialer(cidr, backend string) (*testDialer, error) {
	d := &testDialer{resolve: func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}, dial: (&net.Dialer{Timeout: 10 * time.Second}).DialContext}
	if cidr == "" && backend == "" {
		return d, nil
	}
	subnet, err := netip.ParsePrefix(cidr)
	if err != nil || !subnet.Addr().Is4() || subnet.Bits() < 24 || subnet != subnet.Masked() {
		return nil, errors.New("Compose subnet must be canonical IPv4 /24 or narrower")
	}
	ip, err := netip.ParseAddr(backend)
	if err != nil || !ip.Is4() || !ip.IsPrivate() || !subnet.Contains(ip) {
		return nil, errors.New("Compose backend must be an exact private address in subnet")
	}
	// Both endpoints must be RFC1918, so the entire prefix is private.
	last := subnet.Addr().As4()
	for bit := subnet.Bits(); bit < 32; bit++ {
		last[bit/8] |= 1 << (7 - bit%8)
	}
	if !subnet.Addr().IsPrivate() || !netip.AddrFrom4(last).IsPrivate() {
		return nil, errors.New("Compose subnet must be private")
	}
	d.subnet, d.backend = subnet, ip
	return d, nil
}
func (d *testDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if host != "localhost" && host != "127.0.0.1" && host != "backend" {
		return nil, errors.New("dial host refused")
	}
	ips, err := d.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errors.New("empty backend resolution")
	}
	// Validate the complete answer before making any connection; mixed answers
	// fail closed. Dial an IP literal, never re-resolve after validation.
	for _, ip := range ips {
		ip = ip.Unmap()
		allowed := ip.IsLoopback()
		if host == "backend" {
			allowed = d.backend.IsValid() && ip == d.backend && d.subnet.Contains(ip)
		}
		if !allowed {
			return nil, errors.New("resolved backend destination refused")
		}
	}
	var last error
	for _, ip := range ips {
		conn, err := d.dial(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
		if err == nil {
			return conn, nil
		}
		last = err
	}
	return nil, last
}
