package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	_ "github.com/aidotmarket/aim-data-gateway/internal/builddeps"
	"github.com/aidotmarket/aim-data-gateway/internal/channel"
	"github.com/aidotmarket/aim-data-gateway/internal/config"
	"github.com/aidotmarket/aim-data-gateway/internal/gateway"
	"github.com/aidotmarket/aim-data-gateway/internal/ids"
	"github.com/aidotmarket/aim-data-gateway/internal/inventory"
	"github.com/aidotmarket/aim-data-gateway/internal/ledger"
	"github.com/aidotmarket/aim-data-gateway/internal/pairing"
	"github.com/aidotmarket/aim-data-gateway/internal/profile"
	"github.com/aidotmarket/aim-data-gateway/internal/selfcheck"
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
	if args[0] == "healthcheck" && len(args) == 1 {
		client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{}}
		response, err := client.Get("http://127.0.0.1:8081/healthz")
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("healthcheck: HTTP %d", response.StatusCode)
		}
		return nil
	}
	cmd := args[0]
	if cmd != "run" && cmd != "preview" && cmd != "approve" {
		return errors.New("usage: aim-gateway [run|preview <file-id>|approve <file-id>|healthcheck|version]")
	}
	if (cmd == "run" && len(args) != 1) || (cmd != "run" && len(args) != 2) {
		return errors.New("invalid arguments")
	}
	if cmd == "run" {
		if err := selfcheck.Run(); err != nil {
			return err
		}
	}
	path := os.Getenv("AIM_GATEWAY_CONFIG")
	if path == "" {
		path = "/config/gateway.toml"
	}
	c, e := config.Load(path)
	if e != nil {
		return e
	}
	if cmd == "approve" {
		if !c.OfferRequiresLocalApproval {
			fmt.Println("local approval is not required")
			return nil
		}
		state, err := pairing.Load(gateway.StateDir())
		if err != nil {
			return err
		}
		l, err := ledger.OpenForApproval(filepath.Join(gateway.StateDir(), "gateway.db"), state.Private, "gateway")
		if err != nil {
			return err
		}
		defer l.Close()
		rows, err := l.DB.QueryContext(context.Background(), `SELECT o.sha256,o.lvid,f.relative_path FROM offers o JOIN files f ON f.fid=o.fid WHERE o.fid=? AND o.state='offered' AND o.approved_locally_at IS NULL`, args[1])
		if err != nil {
			return err
		}
		type pending struct{ sha, lvid, path string }
		var offers []pending
		for rows.Next() {
			var offer pending
			if err = rows.Scan(&offer.sha, &offer.lvid, &offer.path); err != nil {
				break
			}
			offers = append(offers, offer)
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return err
		}
		if len(offers) == 0 {
			return errors.New("no pending offers for file-id")
		}
		for _, offer := range offers {
			if err = l.Approve(context.Background(), args[1], offer.sha, offer.lvid); err != nil {
				return err
			}
			fmt.Printf("fid=%s listing_version_id=%s sha256=%s relative_path=%s\n", args[1], offer.lvid, offer.sha, offer.path)
		}
		return nil
	}
	if cmd == "run" {
		ctx := context.Background()
		dir := gateway.StateDir()
		var client *http.Client
		if c.Egress.ConnectProxy != "" {
			client = channel.ProxyClient(c.Egress.ConnectProxy)
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
		secretPath = filepath.Join(gateway.StateDir(), "secret.bin")
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
