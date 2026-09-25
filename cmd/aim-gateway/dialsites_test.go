package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// dialSites records references, including method values and type expressions.
func dialSites(name string, source any) ([]string, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, source, 0)
	if err != nil {
		return nil, err
	}
	imports := map[string]string{}
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			return nil, err
		}
		alias := filepath.Base(path)
		if imp.Name != nil {
			alias = imp.Name.Name
		}
		imports[alias] = path
	}
	var sites []string
	for _, decl := range file.Decls {
		fn := "<package>"
		if f, ok := decl.(*ast.FuncDecl); ok {
			fn = f.Name.Name
		}
		ast.Inspect(decl, func(node ast.Node) bool {
			sel, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			method := sel.Sel.Name
			matched := false
			if ident, ok := sel.X.(*ast.Ident); ok {
				switch imports[ident.Name] {
				case "net":
					matched = strings.HasPrefix(method, "Dial") || strings.HasPrefix(method, "Lookup") || method == "Resolver" || method == "DefaultResolver"
				case "net/http":
					matched = method == "Client" || method == "Transport" || method == "DefaultClient" || method == "DefaultTransport" || method == "Get" || method == "Post" || method == "PostForm" || method == "Head"
				case "crypto/tls", "github.com/coder/websocket":
					matched = strings.HasPrefix(method, "Dial")
				}
			}
			if !matched && (hasImport(imports, "net") || hasImport(imports, "net/http")) {
				matched = strings.HasPrefix(method, "Dial") || strings.HasPrefix(method, "Lookup") || method == "Do" || method == "RoundTrip" || method == "Get" || method == "Post" || method == "PostForm" || method == "Head"
			}
			if matched {
				var rendered bytes.Buffer
				if err := printer.Fprint(&rendered, fset, sel); err != nil {
					panic(err)
				}
				sites = append(sites, name+":"+fn+":"+rendered.String())
			}
			return true
		})
	}
	sort.Strings(sites)
	return sites, nil
}

func hasImport(imports map[string]string, path string) bool {
	for _, imported := range imports {
		if imported == path {
			return true
		}
	}
	return false
}

func TestDialSites(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() && entry.Name() == ".git" {
			return filepath.SkipDir
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sites, err := dialSites(filepath.ToSlash(rel), source)
		got = append(got, sites...)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(got)
	want := []string{
		// Loopback health request.
		"cmd/aim-gateway/main.go:execute:client.Get",
		// Loopback health client construction.
		"cmd/aim-gateway/main.go:execute:http.Client",
		// Pairing client type only.
		"cmd/aim-gateway/main.go:execute:http.Client",
		// Loopback health transport construction.
		"cmd/aim-gateway/main.go:execute:http.Transport",
		// Canary TCP probe.
		"internal/canary/canary.go:Run:d.DialContext",
		// Canary DNS resolver.
		"internal/canary/canary.go:Run:net.DefaultResolver",
		// Canary TCP dialer.
		"internal/canary/canary.go:Run:net.Dialer",
		// Canary dialer configuration field.
		"internal/canary/canary.go:Run:p.Dialer",
		// Canary DNS probe.
		"internal/canary/canary.go:Run:r.LookupIPAddr",
		// Channel client field type.
		"internal/channel/channel.go:<package>:http.Client",
		// Pinned channel WebSocket connection.
		"internal/channel/channel.go:Connect:websocket.Dial",
		// Pinned channel dial options type.
		"internal/channel/channel.go:Connect:websocket.DialOptions",
		// Channel proxy TCP dial method.
		"internal/channel/channel.go:ProxyClient:(&net.Dialer{Timeout: 10 * time.Second}).DialContext",
		// Channel proxy client construction.
		"internal/channel/channel.go:ProxyClient:http.Client",
		// Channel proxy client return type.
		"internal/channel/channel.go:ProxyClient:http.Client",
		// Channel proxy transport construction.
		"internal/channel/channel.go:ProxyClient:http.Transport",
		// Channel proxy TCP dialer.
		"internal/channel/channel.go:ProxyClient:net.Dialer",
		// Door request header lookup, not outbound traffic.
		"internal/door/door.go:download:r.Header.Get",
		// Door request header lookup, not outbound traffic.
		"internal/door/door.go:download:r.Header.Get",
		// Door query parameter lookup, not outbound traffic.
		"internal/door/door.go:statement:r.URL.Query().Get",
		// Door request header lookup, not outbound traffic.
		"internal/door/door.go:token:r.Header.Get",
		// Pairing client type only.
		"internal/gateway/gateway.go:LoadOrPair:http.Client",
		// Default pairing client, limited to api.ai.market.
		"internal/gateway/gateway.go:LoadOrPair:http.DefaultClient",
		// Pairing POST to api.ai.market.
		"internal/pairing/pairing.go:Pair:client.Do",
		// Pairing client argument type.
		"internal/pairing/pairing.go:Pair:http.Client",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("dial-site inventory changed:\ngot:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestDialSiteMutations(t *testing.T) {
	for _, tc := range []struct{ name, imports, body, want string }{
		{"method value", `"github.com/coder/websocket"`, `dial := websocket.Dial; _ = dial`, "websocket.Dial"},
		{"default client", `"net/http"`, `http.DefaultClient.Get(u)`, "http.DefaultClient.Get"},
		{"default transport", `"net/http"`, `http.DefaultTransport.RoundTrip(r)`, "http.DefaultTransport.RoundTrip"},
		{"default resolver", `"net"`, `net.DefaultResolver.LookupNetIP(c, "ip", h)`, "net.DefaultResolver.LookupNetIP"},
		{"aliased import", `nh "net/http"`, `nh.Get(u)`, "nh.Get"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sites, err := dialSites("test.go", "package test\nimport ("+tc.imports+")\nfunc f() {"+tc.body+"}")
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, site := range sites {
				if strings.HasSuffix(site, ":"+tc.want) {
					found = true
				}
			}
			if !found {
				t.Fatalf("%s missed: %v", tc.want, sites)
			}
		})
	}
	sites, err := dialSites("allowed.go", `package test
import "net/http"
func allowed() { http.Get("a"); http.Get("b") }`)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(sites, []string{"allowed.go:allowed:http.Get", "allowed.go:allowed:http.Get"}) {
		t.Fatalf("second site in allowed function missed: %v", sites)
	}
}
