package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Keep this inventory exact so a new outbound path fails CI for review.
func TestDialSites(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	sites := map[string]bool{}
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() && entry.Name() == ".git" {
			return filepath.SkipDir
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, e := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if e != nil {
			return e
		}
		found := false
		ast.Inspect(file, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.CallExpr:
				s, ok := n.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				name := s.Sel.Name
				if name == "Dial" || name == "DialContext" || name == "LookupHost" || strings.HasPrefix(name, "LookupIP") || name == "Do" {
					found = true
				}
				if x, ok := s.X.(*ast.Ident); ok {
					if x.Name == "http" && (name == "Get" || name == "Post" || name == "Head") || x.Name == "tls" && strings.HasPrefix(name, "Dial") || x.Name == "net" && strings.HasPrefix(name, "Dial") {
						found = true
					}
				}
			case *ast.CompositeLit:
				s, ok := n.Type.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if x, ok := s.X.(*ast.Ident); ok && ((x.Name == "net" && (s.Sel.Name == "Dialer" || s.Sel.Name == "Resolver")) || (x.Name == "http" && (s.Sel.Name == "Client" || s.Sel.Name == "Transport"))) {
					found = true
				}
			}
			return true
		})
		if found {
			rel, _ := filepath.Rel(root, path)
			sites[filepath.ToSlash(rel)] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for path := range sites {
		got = append(got, path)
	}
	sort.Strings(got)
	t.Logf("network dial sites: %v", got)
	want := []string{"cmd/aim-gateway/main.go", "internal/canary/canary.go", "internal/channel/channel.go", "internal/pairing/pairing.go"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("dial-site files changed: got %v, want %v", got, want)
	}
}
