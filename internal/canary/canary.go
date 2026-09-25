package canary

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/wire"
)

type Resolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}
type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}
type Probe struct {
	Resolver Resolver
	Dialer   Dialer
	Clock    func() time.Time
}

func (p Probe) Run(ctx context.Context, host, zone, proxy string) (wire.CanaryResult, error) {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return wire.CanaryResult{}, err
	}
	label := hex.EncodeToString(random[:])
	r := p.Resolver
	if r == nil {
		r = net.DefaultResolver
	}
	d := p.Dialer
	if d == nil {
		d = &net.Dialer{Timeout: 5 * time.Second}
	}
	now := p.Clock
	if now == nil {
		now = time.Now
	}
	result := wire.CanaryResult{State: "closed", DNS: "closed", TCP: "closed", Proxy: "not_configured", Label: label, At: now().UTC().Format(time.RFC3339)}
	dnsCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	addresses, err := r.LookupIPAddr(dnsCtx, label+"."+zone)
	cancel()
	if err == nil && len(addresses) > 0 {
		result.DNS = "open"
	}
	connect := func(address string) net.Conn {
		probeCtx, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		conn, err := d.DialContext(probeCtx, "tcp", address)
		if err != nil {
			return nil
		}
		return conn
	}
	if conn := connect(net.JoinHostPort(host, "443")); conn != nil {
		result.TCP = "open"
		conn.Close()
	}
	if proxy != "" {
		result.Proxy = "closed"
		if conn := connect(proxy); conn != nil {
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			_, err := fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", host, host)
			if err == nil {
				line, readErr := bufio.NewReader(io.LimitReader(conn, 4096)).ReadString('\n')
				parts := strings.Fields(line)
				if readErr == nil && len(parts) >= 2 && (parts[0] == "HTTP/1.0" || parts[0] == "HTTP/1.1") {
					status, parseErr := strconv.Atoi(parts[1])
					if parseErr == nil && status >= 200 && status < 300 {
						result.Proxy = "open"
					}
				}
			}
			conn.Close()
		}
	}
	if err := ctx.Err(); err != nil {
		return wire.CanaryResult{}, err
	}
	if result.DNS == "open" || result.TCP == "open" || result.Proxy == "open" {
		result.State = "open"
	}
	return result, nil
}
