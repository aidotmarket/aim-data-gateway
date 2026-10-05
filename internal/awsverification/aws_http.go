package awsverification

import (
	"net"
	"net/http"
	"time"
)

var s3Dialer = net.Dialer{Timeout: 10 * time.Second}

// S3HTTPClient bounds connection setup and headers. The scan context alone
// governs streaming body reads, which may run for the full scan deadline.
func S3HTTPClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return ErrRefused
	}, Transport: &http.Transport{
		Proxy:                 nil,
		DialContext:           s3Dialer.DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       90 * time.Second,
	}}
}
