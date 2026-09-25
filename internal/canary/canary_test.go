package canary

import (
	"context"
	"errors"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"crypto/ed25519"
	"github.com/aidotmarket/aim-data-gateway/internal/audit"
)

type resolverFunc func(context.Context, string) ([]net.IPAddr, error)

func (f resolverFunc) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return f(ctx, host)
}

type dialerFunc func(context.Context, string, string) (net.Conn, error)

func (f dialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

func TestProbeClassification(t *testing.T) {
	for _, tc := range []struct {
		name             string
		ips              []net.IPAddr
		dnsErr           error
		tcp, proxy, want string
	}{
		{"A", []net.IPAddr{{IP: net.IPv4(192, 0, 2, 1)}}, nil, "closed", "not_configured", "open"},
		{"AAAA", []net.IPAddr{{IP: net.ParseIP("2001:db8::1")}}, nil, "closed", "not_configured", "open"},
		{"NXDOMAIN", nil, &net.DNSError{IsNotFound: true}, "closed", "not_configured", "closed"},
		{"SERVFAIL", nil, &net.DNSError{Err: "server misbehaving"}, "closed", "not_configured", "closed"},
		{"timeout", nil, context.DeadlineExceeded, "closed", "not_configured", "closed"},
		{"TCP established", nil, errors.New("dns"), "open", "not_configured", "open"},
		{"TCP refused", nil, errors.New("dns"), "closed", "not_configured", "closed"},
		{"TCP timeout", nil, errors.New("dns"), "closed", "not_configured", "closed"},
		{"proxy 200", nil, errors.New("dns"), "closed", "open", "open"},
		{"proxy 403", nil, errors.New("dns"), "closed", "closed", "closed"},
		{"proxy 407", nil, errors.New("dns"), "closed", "closed", "closed"},
		{"proxy refused", nil, errors.New("dns"), "closed", "closed", "closed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proxy := ""
			if strings.HasPrefix(tc.name, "proxy") {
				proxy = "proxy:80"
			}
			p := Probe{Resolver: resolverFunc(func(_ context.Context, host string) ([]net.IPAddr, error) {
				if !regexp.MustCompile(`^[0-9a-f]{16}\.zone$`).MatchString(host) {
					t.Errorf("host %q", host)
				}
				return tc.ips, tc.dnsErr
			}), Dialer: dialerFunc(func(_ context.Context, _, addr string) (net.Conn, error) {
				if addr == "canary:443" && tc.tcp == "open" {
					client, server := net.Pipe()
					server.Close()
					return client, nil
				}
				if addr != "proxy:80" || tc.proxy != "open" && tc.name == "proxy refused" {
					return nil, errors.New("refused")
				}
				client, server := net.Pipe()
				go func() {
					defer server.Close()
					b := make([]byte, 256)
					server.Read(b)
					status := "200"
					if tc.name == "proxy 403" {
						status = "403"
					}
					if tc.name == "proxy 407" {
						status = "407"
					}
					server.Write([]byte("HTTP/1.1 " + status + " result\r\n"))
				}()
				return client, nil
			}), Clock: func() time.Time { return time.Date(2026, 9, 25, 1, 2, 3, 0, time.FixedZone("X", 3600)) }}
			got, err := p.Run(context.Background(), "canary", "zone", proxy)
			if err != nil || got.State != tc.want || got.DNS != map[bool]string{true: "open", false: "closed"}[len(tc.ips) > 0] || got.TCP != tc.tcp || got.Proxy != tc.proxy || got.At != "2026-09-25T00:02:03Z" {
				t.Fatalf("%+v %v", got, err)
			}
			if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(got.Label) {
				t.Fatal(got.Label)
			}
		})
	}
}

func TestAuditResultFields(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(nil)
	log, err := audit.Open(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	result, err := (Probe{Resolver: resolverFunc(func(context.Context, string) ([]net.IPAddr, error) { return nil, errors.New("closed") }), Dialer: dialerFunc(func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("closed") })}).Run(context.Background(), "canary", "zone", "")
	if err != nil {
		t.Fatal(err)
	}
	entry, err := log.Append("canary_result", result)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"state"`, `"dns"`, `"tcp"`, `"proxy"`, `"label"`, `"at"`} {
		if !strings.Contains(string(entry.Body), field) {
			t.Fatal(field, string(entry.Body))
		}
	}
}

func TestCanceledCanaryIsNotReportedClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := Probe{Resolver: resolverFunc(func(context.Context, string) ([]net.IPAddr, error) { return nil, context.Canceled }), Dialer: dialerFunc(func(context.Context, string, string) (net.Conn, error) { return nil, context.Canceled })}
	if _, err := p.Run(ctx, "canary", "zone", ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled run: %v", err)
	}
}
