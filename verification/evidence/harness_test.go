//go:build evidence

package evidence

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/audit"
	aws "github.com/aidotmarket/aim-data-gateway/internal/awsverification"
	cf "github.com/aidotmarket/aim-data-gateway/internal/cloudflareverification"
	"github.com/aidotmarket/aim-data-gateway/internal/config"
	"github.com/aidotmarket/aim-data-gateway/internal/inventory"
	"github.com/aidotmarket/aim-data-gateway/internal/ledger"
	gw "github.com/aidotmarket/aim-data-gateway/internal/verification"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	core "github.com/aidotmarket/aim-data-gateway/verification"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

const baseSHA = "25779953b1c27e0dec5f39ba871422a6b81f8cff"
const authoritySHA = "2870b0b6389b491aaa3089d215a9f3af5280d5ee"

var ctx = context.Background()
var at = time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
var kinds = []string{"aim_gateway", "aws_s3_verifier", "r2_verifier"}
var markers = []string{
	"CP81_CELL_73c19b", "CP81_PATH_92e34f", "cp81-bucket-7a92c1",
	"CP81_KEY_c2ab91", "CP81_COLUMN_COMMENT_f723ab",
	"AKIACP81FAKE7B92C1XYZ", "-----BEGIN CP81 TEST DATA-----",
}

func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func read(t *testing.T, path string) []byte {
	t.Helper()
	b, e := os.ReadFile(path)
	must(t, e)
	return b
}
func canonical(t *testing.T, v any) []byte {
	t.Helper()
	b, e := core.Canonical(v)
	must(t, e)
	return b
}
func write(t *testing.T, path string, b []byte) {
	t.Helper()
	must(t, os.MkdirAll(filepath.Dir(path), 0700))
	generation := filepath.Dir(outDir()) + string(filepath.Separator)
	if strings.HasPrefix(filepath.Clean(path), generation) {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		must(t, err)
		_, err = f.Write(b)
		closeErr := f.Close()
		must(t, err)
		must(t, closeErr)
		return
	}
	must(t, os.WriteFile(path, b, 0600))
}
func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, e := json.MarshalIndent(v, "", "  ")
	must(t, e)
	write(t, path, append(b, '\n'))
}
func outDir() string {
	if s := os.Getenv("EVIDENCE_OUT"); s != "" {
		return filepath.Clean(s)
	}
	panic("EVIDENCE_OUT must name a fresh generation captures directory")
}
func vector(t *testing.T, name string) map[string]any {
	t.Helper()
	var v map[string]any
	must(t, json.Unmarshal(read(t, "../../contract/vectors/verification/"+name+".json"), &v))
	return v
}
func job(t *testing.T, kind, variant string) wire.ScanJob {
	t.Helper()
	v := vector(t, "scan_spec")
	pub, e := hex.DecodeString(v["test_only_public_hex"].(string))
	must(t, e)
	in := v["input"].(map[string]any)
	j, e := wire.VerifyScan(v["token"].(string), map[string]ed25519.PublicKey{"test-only-scan-key": pub}, in["aud"].(string), in["runner_id"].(string), "1.2.3", at)
	must(t, e)
	// Retain the committed contract constants; vary local source metadata only.
	j.ScannerVersion, j.ReceiptKeyID = "1.2.3", "77777777-7777-4777-8777-777777777777"
	j.Envelope.Variant = variant
	j.Payload["connector_type"], j.Payload["connector_version"] = kind, kind+"-v1"
	j.Payload["probe_id"] = j.Payload["verification_id"]
	return j
}

type file struct {
	Key, Format string
	Data        []byte
}
type trip func(*http.Request) (*http.Response, error)

func (f trip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(r *http.Request, body string) *http.Response {
	return &http.Response{StatusCode: 200, Header: make(http.Header), Request: r, Body: io.NopCloser(strings.NewReader(body))}
}

// Provider fakes serve only the pinned source bytes. Scanning, commitments,
// report construction, receipt signing and transport serialization remain real.
type s3 struct {
	files  map[string][]byte
	reads  int
	bucket string
}

func (s *s3) Head(_ context.Context, r aws.Request) (aws.Head, error) {
	b, ok := s.files[r.Key]
	if !ok || r.Bucket != s.bucket {
		return aws.Head{}, os.ErrNotExist
	}
	return aws.Head{Size: int64(len(b)), VersionID: "v1", ETag: "e1"}, nil
}
func (s *s3) Get(_ context.Context, r aws.Request) (io.ReadCloser, error) {
	b, ok := s.files[r.Key]
	if !ok || r.Bucket != s.bucket || r.VersionID != "v1" {
		return nil, os.ErrNotExist
	}
	s.reads++
	if r.End >= 0 {
		b = b[r.Start : r.End+1]
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

type bridge struct {
	files  map[string][]byte
	reads  int
	bucket string
}

func (s *bridge) Head(_ context.Context, r cf.Request) (*cf.Head, error) {
	b, ok := s.files[r.Key]
	if !ok || r.Bucket != s.bucket || r.IfMatch != "e1" {
		return nil, os.ErrNotExist
	}
	return &cf.Head{Size: int64(len(b)), ETag: "e1"}, nil
}
func (s *bridge) Get(c context.Context, r cf.Request) (cf.GetResult, error) {
	h, e := s.Head(c, r)
	if e != nil {
		return cf.GetResult{}, e
	}
	s.reads++
	b := s.files[r.Key]
	if r.Range != nil {
		b = b[r.Range.Offset : r.Range.Offset+r.Range.Length]
	}
	return cf.GetResult{Metadata: h, Range: r.Range, Body: io.NopCloser(bytes.NewReader(b))}, nil
}

type secretStore struct{ secret *aws.Secret }

func (s *secretStore) Load(context.Context) (*aws.Secret, error)   { return s.secret, nil }
func (s *secretStore) Save(_ context.Context, v *aws.Secret) error { s.secret = v; return nil }

// Bootstrap alone needs a single initializing lease; no transaction is used here.
type bootstrapDB struct{ aws.Dynamo }

func (bootstrapDB) PutItem(context.Context, *dynamodb.PutItemInput, ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	return &dynamodb.PutItemOutput{}, nil
}

type stopRegistration struct{ aws.Backend }

func (stopRegistration) Register(context.Context, []byte) (aws.RegistrationAck, error) {
	return aws.RegistrationAck{}, fmt.Errorf("intentional local registration stop after persistence")
}

type harness struct {
	seed         string
	kind         string
	key          [32]byte
	private      ed25519.PrivateKey
	registration []byte
	awsConfig    aws.Config
	cfConfig     cf.Config
	awsSecret    *aws.Secret
	cfSecret     *cf.Secret
	gateway      *gw.Runner
	reads        int
}

func newHarness(t *testing.T, kind string) *harness {
	t.Helper()
	h := &harness{kind: kind}
	defer func() {
		if keyObserver != nil {
			keyObserver(h)
		}
	}()
	if kind == "aim_gateway" {
		dir, e := filepath.EvalSymlinks(t.TempDir())
		must(t, e)
		k, e := gw.OpenKeys(dir, "1.2.3", "sha256:"+strings.Repeat("a", 64))
		must(t, e)
		j := job(t, kind, "scan")
		k.Binding.RunnerID, k.Binding.ReceiptKeyID = j.Envelope.RunnerID, j.ReceiptKeyID
		h.key, h.private = k.Commitment, k.Private
		m, e := k.Registration(j.Envelope.Audience, at)
		must(t, e)
		h.registration, e = wire.Canonical(m)
		must(t, e)
		_, identity, e := ed25519.GenerateKey(rand.Reader)
		must(t, e)
		l, e := ledger.Open(filepath.Join(dir, "gateway.db"), identity, "gateway")
		must(t, e)
		t.Cleanup(func() { must(t, l.Close()) })
		log, e := audit.Open(filepath.Join(dir, "audit"), identity)
		must(t, e)
		a, e := gw.OpenLocalAudit(dir, identity)
		must(t, e)
		cfg := config.Config{Sources: []config.Source{{Name: "data", Path: dir}}, VerificationEnabled: true}
		h.gateway = &gw.Runner{Ledger: l, Log: log, Audit: a, Keys: k, GatewayID: j.Envelope.Audience, Version: "1.2.3", Config: func() config.Config { return cfg }, Now: func() time.Time { return at }}
		h.gateway.OpenFile = func(f ledger.File) (*os.File, error) {
			h.reads++
			return (inventory.Record{Root: f.Root, RelativePath: f.RelativePath}).Open()
		}
		return h
	}
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	if kind == "aws_s3_verifier" {
		h.awsConfig = aws.Config{Connection: "11111111-1111-4111-8111-111111111111", Bucket: markers[2], Version: "1.2.3", Digest: "sha256:" + strings.Repeat("a", 64), Token: token}
		store := &secretStore{}
		_, e := aws.Bootstrap(ctx, h.awsConfig, aws.Ledger{Client: bootstrapDB{}, Table: "evidence"}, store, stopRegistration{}, at)
		if e == nil || store.secret == nil || len(store.secret.Registration) == 0 {
			t.Fatal("bootstrap did not persist real registration")
		}
		h.awsSecret = store.secret
		h.awsSecret.Runner = job(t, kind, "scan").Envelope.RunnerID
		h.awsSecret.Receipt = job(t, kind, "scan").ReceiptKeyID
		h.key, h.private, h.registration = h.awsSecret.Commitment, h.awsSecret.Private, h.awsSecret.Registration
	} else {
		h.cfConfig = cf.Config{ConfigHash: strings.Repeat("d", 64), Connection: "11111111-1111-4111-8111-111111111111", Bucket: markers[2], Prefix: "", Jurisdiction: "default", Keys: []string{markers[3] + "/data.csv"}, Token: token, Version: "1.2.3", Release: "cloudflare-verifier-v1", Binary: strings.Repeat("b", 64), Worker: cf.WorkerIdentity{Mode: "bundle", SHA256: strings.Repeat("c", 64)}}
		s, e := cf.CreateSecret(h.cfConfig, at)
		must(t, e)
		h.cfSecret = s
		s.Runner = job(t, kind, "scan").Envelope.RunnerID
		s.Receipt = job(t, kind, "scan").ReceiptKeyID
		h.key, h.private, h.registration = s.Commitment, s.Private, s.Registration
	}
	return h
}

func (h *harness) scan(t *testing.T, files []file, variant string) []byte {
	t.Helper()
	j := job(t, h.kind, variant)
	if h.seed != "" {
		j.Payload["deterministic_seed"] = h.seed
	}
	files = append([]file(nil), files...)
	sort.Slice(files, func(i, j int) bool { return files[i].Key < files[j].Key })
	// Different snapshots yield different locator commitments across reports.
	j.Payload["manifest_hash"] = wire.Digest(canonical(t, files))
	if h.kind == "aim_gateway" {
		r := h.gateway
		cfg := r.Config()
		root := cfg.Sources[0].Path
		s := wire.Snapshot{Version: "verification-source-snapshot-v1", Kind: "gateway_listing", GatewayID: r.GatewayID, ListingID: j.Text("listing_id"), ListingVersionID: j.Text("listing_version_id"), SourceID: j.Text("source_handle_id")}
		for _, f := range files {
			id := wire.Digest([]byte(f.Key))[:32]
			sha := sha256.Sum256(f.Data)
			digest := hex.EncodeToString(sha[:])
			write(t, filepath.Join(root, f.Key), f.Data)
			record := inventory.Record{Phase1: inventory.Phase1{FileID: id, SizeBytes: int64(len(f.Data)), Present: true}, Root: root, Source: "data", RelativePath: f.Key, SHA256: sha}
			must(t, r.Ledger.PutFile(ctx, record))
			must(t, r.Ledger.PutOffer(ctx, ledger.Offer{FileID: id, SHA256: digest, ListingVersionID: s.ListingVersionID, IID: "offer", State: "offered", KeyClass: "listing"}))
			s.Members = append(s.Members, wire.SnapshotMember{FileID: id, SHA256: digest, Size: int64(len(f.Data))})
		}
		sort.Slice(s.Members, func(i, j int) bool { return s.Members[i].FileID < s.Members[j].FileID })
		// Unique admission claims let this same customer key scan multiple fixtures.
		seq := r.Log.Sequence() + 1
		j.Payload["spec_id"] = fmt.Sprintf("evidence_%d", seq)
		j.Envelope.IID = fmt.Sprintf("88888888-8888-4888-8888-%012d", seq)
		nonce := sha256.Sum256([]byte(fmt.Sprintf("nonce_%d", seq)))
		j.Payload["nonce"] = base64.RawURLEncoding.EncodeToString(nonce[:])
		j.Payload["owner_authorization_id"] = fmt.Sprintf("auth_%d", seq)
		a := ledger.Admission{SpecID: j.Text("spec_id"), RunnerID: j.Envelope.RunnerID, ListingID: j.Text("listing_id"), VersionID: j.Text("listing_version_id"), ManifestHash: j.Text("manifest_hash"), SpecHash: j.Envelope.SpecHash, Nonce: j.Text("nonce"), AuthorizationID: j.Text("owner_authorization_id"), Variant: variant, IID: j.Envelope.IID, Accepted: j.Accepted.Unix(), Issued: j.Issued.Unix(), Expires: j.Expires.Unix(), Spec: []byte(j.Token), ReceiptKeyID: j.ReceiptKeyID, ScannerVersion: j.ScannerVersion}
		a.Snapshot = canonical(t, s)
		fresh, e := r.Ledger.Admit(ctx, a, at, func() time.Time { return at })
		must(t, e)
		if !fresh {
			t.Fatal("admission not fresh")
		}
		must(t, gatewayRun(r, ctx, j, s))
		saved, e := r.Ledger.Verification(ctx, a.SpecID)
		must(t, e)
		if len(saved.Result) == 0 {
			t.Fatal("gateway produced no report")
		}
		return saved.Result
	}
	data := map[string][]byte{}
	if h.kind == "aws_s3_verifier" {
		var objects []aws.Object
		for _, f := range files {
			data[f.Key] = f.Data
			objects = append(objects, aws.Object{Key: f.Key, VersionID: "v1", ETag: "e1", Format: f.Format, Size: int64(len(f.Data))})
		}
		provider := &s3{files: data, bucket: h.awsConfig.Bucket}
		src, e := aws.NewSource(provider, h.awsConfig.Bucket, objects)
		must(t, e)
		b, e := awsScan(aws.Handler{Config: h.awsConfig, Now: func() time.Time { return at }}, ctx, h.awsSecret, j, src)
		must(t, e)
		h.reads += provider.reads
		return b
	}
	var objects []cf.Object
	for _, f := range files {
		data[f.Key] = f.Data
		objects = append(objects, cf.Object{Key: f.Key, ETag: "e1", Format: f.Format, Size: int64(len(f.Data))})
	}
	provider := &bridge{files: data, bucket: h.cfConfig.Bucket}
	src, e := cf.NewSource(provider, h.cfConfig.Bucket, objects)
	must(t, e)
	b, e := cfScan(cf.Handler{Config: h.cfConfig, Now: func() time.Time { return at }}, ctx, h.cfSecret, j, src)
	must(t, e)
	h.reads += provider.reads
	return b
}

func document(t *testing.T, frame []byte) (map[string]any, map[string]any) {
	t.Helper()
	var body map[string]any
	must(t, json.Unmarshal(frame, &body))
	b, e := wire.DecodeDocument(body["document_b64"].(string), wire.MaxScanDocument)
	must(t, e)
	var doc map[string]any
	must(t, json.Unmarshal(b, &doc))
	return body, doc
}
