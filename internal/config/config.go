package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

type Source struct {
	Name string `toml:"name"`
	Path string `toml:"path"`
}
type Columns struct {
	Rename map[string]string `toml:"rename"`
	Drop   []string          `toml:"drop"`
}
type Config struct {
	Sources      []Source           `toml:"sources"`
	OfferCeiling []string           `toml:"offer_ceiling"`
	Aliases      map[string]string  `toml:"aliases"`
	Columns      map[string]Columns `toml:"columns"`
	Door         struct {
		Listen                 string `toml:"listen"`
		MaxConcurrentDownloads int    `toml:"max_concurrent_downloads"`
	} `toml:"door"`
	Egress struct {
		ConnectProxy string `toml:"connect_proxy"`
	} `toml:"egress"`
	OfferRequiresLocalApproval bool `toml:"offer_requires_local_approval"`
}

func Load(path string) (Config, error) {
	var c Config
	f, e := os.Open(path)
	if e != nil {
		return c, e
	}
	defer f.Close()
	md, e := toml.NewDecoder(f).Decode(&c)
	if e != nil {
		return c, e
	}
	if keys := md.Undecoded(); len(keys) > 0 {
		return c, fmt.Errorf("unknown config keys: %v", keys)
	}
	if c.Door.Listen == "" {
		c.Door.Listen = ":8080"
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	if len(c.Sources) == 0 {
		return errors.New("at least one source is required")
	}
	names := map[string]bool{}
	for _, s := range c.Sources {
		if s.Name == "" || strings.ContainsAny(s.Name, "/\\\x00") || s.Name == "." || s.Name == ".." {
			return fmt.Errorf("invalid source name %q", s.Name)
		}
		if names[s.Name] {
			return fmt.Errorf("duplicate source %q", s.Name)
		}
		names[s.Name] = true
		if !filepath.IsAbs(s.Path) || filepath.Clean(s.Path) != s.Path {
			return fmt.Errorf("invalid source path %q", s.Path)
		}
		st, e := os.Stat(s.Path)
		if e != nil {
			return e
		}
		if !st.IsDir() {
			return fmt.Errorf("source %q is not a directory", s.Name)
		}
	}
	if c.Door.Listen != "" {
		if _, _, e := net.SplitHostPort(c.Door.Listen); e != nil {
			return fmt.Errorf("door.listen: %w", e)
		}
	}
	if c.Door.MaxConcurrentDownloads < 0 {
		return errors.New("door.max_concurrent_downloads must be nonnegative")
	}
	if c.Egress.ConnectProxy != "" {
		if _, _, e := net.SplitHostPort(c.Egress.ConnectProxy); e != nil {
			return fmt.Errorf("egress.connect_proxy: %w", e)
		}
	}
	for _, g := range c.OfferCeiling {
		if g == "" || strings.Contains(g, "..") {
			return fmt.Errorf("invalid ceiling glob %q", g)
		}
		if _, e := filepath.Match(g, "x"); e != nil {
			return e
		}
	}
	for k, v := range c.Aliases {
		if !validRelative(k) || strings.TrimSpace(v) == "" || strings.ContainsAny(v, "\r\n\x00") {
			return fmt.Errorf("invalid alias %q", k)
		}
	}
	for k, r := range c.Columns {
		if !validRelative(k) {
			return fmt.Errorf("invalid column rule %q", k)
		}
		dropped := map[string]bool{}
		for _, d := range r.Drop {
			if d == "" || dropped[d] {
				return fmt.Errorf("invalid dropped column %q", d)
			}
			dropped[d] = true
		}
		for old, newName := range r.Rename {
			if old == "" || newName == "" || dropped[old] {
				return fmt.Errorf("invalid rename for %q", old)
			}
		}
	}
	return nil
}
func validRelative(p string) bool {
	return p != "" && !filepath.IsAbs(p) && filepath.Clean(p) == p && p != ".." && !strings.HasPrefix(p, "../") && !strings.ContainsRune(p, 0)
}
func (c Config) Alias(source, rel string) string {
	if a := c.Aliases[source+"/"+rel]; a != "" {
		return a
	}
	return c.Aliases[rel]
}
func (c Config) ColumnRule(source, rel string) Columns {
	if r, ok := c.Columns[source+"/"+rel]; ok {
		return r
	}
	return c.Columns[rel]
}
