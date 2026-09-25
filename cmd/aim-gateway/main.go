package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"

	_ "github.com/aidotmarket/aim-data-gateway/internal/builddeps"
	"github.com/aidotmarket/aim-data-gateway/internal/config"
	"github.com/aidotmarket/aim-data-gateway/internal/gateway"
	"github.com/aidotmarket/aim-data-gateway/internal/ids"
	"github.com/aidotmarket/aim-data-gateway/internal/inventory"
	"github.com/aidotmarket/aim-data-gateway/internal/profile"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
)

const version = "0.1.0-dev"

func main() {
	if e := execute(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func execute(args []string) error {
	if len(args) == 0 {
		args = []string{"run"}
	}
	if args[0] == "version" {
		if len(args) != 1 {
			return errors.New("usage: aim-gateway version")
		}
		fmt.Println(version)
		return nil
	}
	cmd := args[0]
	if cmd != "run" && cmd != "preview" {
		return errors.New("usage: aim-gateway [run|preview <file-id>|version]")
	}
	if (cmd == "run" && len(args) != 1) || (cmd == "preview" && len(args) != 2) {
		return errors.New("invalid arguments")
	}
	path := os.Getenv("AIM_GATEWAY_CONFIG")
	if path == "" {
		path = "/config/gateway.toml"
	}
	c, e := config.Load(path)
	if e != nil {
		return e
	}
	if cmd == "run" {
		ctx := context.Background()
		dir := gateway.StateDir()
		var client *http.Client
		if c.Egress.ConnectProxy != "" {
			proxy := &url.URL{Scheme: "http", Host: c.Egress.ConnectProxy}
			client = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}}
		}
		state, err := gateway.LoadOrPair(ctx, dir, os.Getenv("AIM_PAIRING_CODE"), version, client)
		if err != nil {
			return err
		}
		g, err := gateway.Open(dir, c, state)
		if err != nil {
			return err
		}
		defer g.Ledger.Close()
		return g.Run(ctx, version)
	}
	secretPath := os.Getenv("AIM_GATEWAY_SECRET")
	if secretPath == "" {
		secretPath = "/state/secret.bin"
	}
	secret, e := os.ReadFile(secretPath)
	if e != nil {
		return e
	}
	keys, e := ids.Derive(secret)
	if e != nil {
		return e
	}
	records, e := inventory.Scan(c, keys)
	if e != nil {
		return e
	}
	for _, r := range records {
		if r.Phase1.FileID == args[1] {
			d, e := profile.File(r, c.ColumnRule(r.Source, r.RelativePath))
			if e != nil {
				return e
			}
			body := wire.Description{FileID: r.Phase1.FileID, SHA256: d.SHA256, RowCount: d.RowCount, Columns: make([]wire.Column, 0, len(d.Columns))}
			for _, col := range d.Columns {
				body.Columns = append(body.Columns, wire.Column{Name: col.Name, Type: col.Type, NullRatePct: col.NullRatePct, DistinctBucket: col.DistinctBucket})
			}
			out := struct {
				Phase1 inventory.Phase1 `json:"phase_1"`
				Phase2 wire.Description `json:"phase_2"`
			}{r.Phase1, body}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(out)
		}
	}
	return errors.New("file_id not found")
}
