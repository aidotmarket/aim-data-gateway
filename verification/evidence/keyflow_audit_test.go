//go:build evidence

package evidence

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	aws "github.com/aidotmarket/aim-data-gateway/internal/awsverification"
	cf "github.com/aidotmarket/aim-data-gateway/internal/cloudflareverification"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
)

// Pin the complete write surface for the verification HMAC key. Added cloud
// input/seed/selector assignments fail rather than being silently allowlisted.
func TestE3CommitmentWriteSurface(t *testing.T) {
	roots := []string{"../../internal/verification", "../../internal/awsverification", "../../internal/cloudflareverification"}
	var references []map[string]any
	writes := map[string]int{}
	for _, root := range roots {
		must(t, filepath.WalkDir(root, func(path string, d os.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fs := token.NewFileSet()
			f, e := parser.ParseFile(fs, path, nil, 0)
			if e != nil {
				return e
			}
			ast.Inspect(f, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if ok && sel.Sel.Name == "Commitment" {
					references = append(references, map[string]any{"file": path, "line": fs.Position(sel.Pos()).Line})
				}
				switch x := n.(type) {
				case *ast.AssignStmt:
					for _, lhs := range x.Lhs {
						if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "Commitment" {
							t.Errorf("unapproved direct commitment assignment at %s", fs.Position(lhs.Pos()))
						}
					}
				case *ast.KeyValueExpr:
					if id, ok := x.Key.(*ast.Ident); ok && id.Name == "Commitment" {
						t.Errorf("unapproved commitment initializer at %s", fs.Position(x.Pos()))
					}
				case *ast.CallExpr:
					if len(x.Args) == 0 {
						return true
					}
					slice, ok := x.Args[0].(*ast.SliceExpr)
					if !ok {
						return true
					}
					sel, ok := slice.X.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "Commitment" {
						return true
					}
					allowed := false
					if fn, ok := x.Fun.(*ast.Ident); ok && fn.Name == "copy" && strings.HasSuffix(path, "internal/verification/keys.go") {
						allowed = true
						writes["gateway_local_key_load"]++
					}
					if fn, ok := x.Fun.(*ast.SelectorExpr); ok && fn.Sel.Name == "Read" {
						id, ok := fn.X.(*ast.Ident)
						if ok && id.Name == "rand" && (strings.HasSuffix(path, "internal/awsverification/bootstrap.go") || strings.HasSuffix(path, "internal/cloudflareverification/bootstrap.go")) {
							allowed = true
							writes[path]++
						}
					}
					if !allowed {
						t.Errorf("unapproved mutable commitment slice at %s", fs.Position(x.Pos()))
					}
				}
				return true
			})
			return nil
		}))
	}
	if writes["gateway_local_key_load"] != 2 || writes["../../internal/awsverification/bootstrap.go"] != 1 || writes["../../internal/cloudflareverification/bootstrap.go"] != 1 {
		t.Fatalf("unexpected commitment write surface: %v", writes)
	}
	keys := string(read(t, "../../internal/verification/keys.go"))
	for _, literal := range []string{"\"crypto/rand\"", "_, e := rand.Read(b)", "c, e := random32()", "atomicFile(dir, \"verification-commitment.key\", c)"} {
		if !strings.Contains(keys, literal) {
			t.Errorf("local CSPRNG key custody changed: %q", literal)
		}
	}
	for _, typ := range []reflect.Type{reflect.TypeOf(wire.ScanEnvelope{}), reflect.TypeOf(wire.Snapshot{}), reflect.TypeOf(aws.Config{}), reflect.TypeOf(cf.Config{}), reflect.TypeOf(aws.RegistrationAck{}), reflect.TypeOf(cf.RegistrationAck{})} {
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			name := strings.ToLower(field.Name)
			if strings.Contains(name, "commitment") || strings.Contains(name, "seed") || strings.Contains(name, "selector") {
				t.Errorf("cloud input %s accepts key selector %s", typ, field.Name)
			}
		}
	}
	writeJSON(t, filepath.Join(keyflowDir, "source-audit.json"), map[string]any{"authority": cp81Authority, "write_surface": writes, "references": references, "scope": "Go verification runner key write sites and typed cloud inputs; TS customer-local secret transfer is documented separately"})
	for _, kind := range kinds {
		storage := map[string]string{"aim_gateway": "Customer state directory: verification-commitment.key and verification-receipt.key, separate 0600 files; binding and registration contain no HMAC key.", "aws_s3_verifier": "Customer AWS Secrets Manager secret: independent Commitment and Private fields; customer IAM controls load/save. DynamoDB lease/outbox has no secret key.", "r2_verifier": "Customer Go compute creates the keys; customer Durable Object encrypts the Secret with its locally generated wrap key (AES-GCM). Local DO-to-container compute bodies carry the secret; these are customer-side custody frames, never ai.market frames."}[kind]
		generation := map[string]string{"aim_gateway": "OpenKeys: separate crypto/rand.Read calls for receipt seed and 32-byte HMAC key.", "aws_s3_verifier": "Bootstrap: ed25519.GenerateKey(rand.Reader), then independent rand.Read(Commitment[:]); persist before registering.", "r2_verifier": "CreateSecret: ed25519.GenerateKey(rand.Reader), then independent rand.Read(Commitment[:]); DO persists encrypted secret before registering."}[kind]
		text := "# " + kind + " key flow\n\nAuthority: runbooks 5d8267dc §5.1 E3 (:393). Gateway base: 7fcbd770c7ffb7e21284e28767eeafedfe878c23.\n\n```text\ncustomer-local OS CSPRNG -> independent 32-byte commitment/HMAC key\n                        -> independent Ed25519 receipt key\nHMAC key -> customer secret storage -> scanner -> locator/object commitments\nreceipt key -> customer secret storage -> receipt/registration/request signer\nai.market <- public receipt key, signatures, commitments (never HMAC key)\n```\n\n" + generation + "\n\n" + storage + "\n\nThe signed spec deterministic_seed selects traversal behavior; it is not HMAC entropy. Snapshot locators and manifest hashes are HMAC message inputs. Registration responses bind runner/receipt identifiers and public signing pins. Environment/configuration supplies deployment metadata, credentials and registration tokens; no verification commitment key, seed or selector is accepted. Local retained secret stores are trusted custody inputs, not cloud-visible inputs.\n\nTests: E3KeyAbsenceE2Frames searches the real E2 registration, work/snapshot, probe, successful/terminal report, request claims and audit/log frames in raw, decoded, hex, base64 and JSON-array forms. E3LocalEntropyAndInputIndependence holds local entropy fixed while changing cloud configuration and key-shaped environment variables, changes entropy independently, exercises spec/snapshot and hostile registration response paths, and compares reported commitments against receipt-seed/public-key and public-value candidates. Exact local-key HMAC is a positive control. E3CommitmentWriteSurface pins CSPRNG and retained-key write sites and checks typed cloud input fields.\n\nLimits: finite candidate attempts establish independence for exercised derivations, not universal mathematical non-derivability. No live provider or deployed Cloudflare TypeScript execution is claimed. Customer-owned Secrets Manager/DO/container custody must remain inaccessible to ai.market; the tests do not prove IAM or deployment ownership. Secret keys are not saved in these artifacts.\n"
		write(t, filepath.Join(keyflowDir, kind+".md"), []byte(text))
	}
}
