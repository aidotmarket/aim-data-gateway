package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	cf "github.com/aidotmarket/aim-data-gateway/internal/cloudflareverification"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// The hash is computed from the executable, avoiding self-referential identity.
var releaseID = "cloudflare-verifier-v0.1.0"
var scannerVersion = "0.1.0"

func executableHash() (string, error) {
	path, e := os.Executable()
	if e != nil {
		return "", e
	}
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func main() {
	hash, e := executableHash()
	if e != nil {
		os.Exit(1)
	}
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Printf("%s %s %s\n", releaseID, scannerVersion, hash)
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	audit := cf.Logs{Output: os.Stdout}
	service := &cf.Service{Release: releaseID, Version: scannerVersion, Binary: hash, BackendClient: cf.MarketplaceClient(audit), Audit: audit, BridgeHTTP: cf.BridgeClient()}
	server := &http.Server{Addr: ":8080", Handler: service, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 895 * time.Second, MaxHeaderBytes: 16 << 10, BaseContext: func(_ net.Listener) context.Context { return ctx }}
	go func() {
		<-ctx.Done()
		shutdown, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		server.Shutdown(shutdown)
	}()
	if e = server.ListenAndServe(); e != nil && e != http.ErrServerClosed {
		os.Exit(1)
	}
}
