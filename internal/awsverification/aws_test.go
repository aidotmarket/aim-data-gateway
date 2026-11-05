package awsverification

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/credentials"
	d "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	sm "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

type fakeSecretsAPI struct {
	mu       sync.Mutex
	value    string
	version  string
	versions map[string]string
	err      error
	puts     []*secretsmanager.PutSecretValueInput
}

func (s *fakeSecretsAPI) GetSecretValue(_ context.Context, i *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	value, version := s.value, s.version
	if i.VersionId != nil {
		var ok bool
		version = *i.VersionId
		value, ok = s.versions[version]
		if !ok {
			return nil, &sm.ResourceNotFoundException{Message: aws.String("version missing")}
		}
	} else if value == "" {
		return nil, &sm.ResourceNotFoundException{Message: aws.String("Can't find secret value for staging label: AWSCURRENT")}
	}
	return &secretsmanager.GetSecretValueOutput{SecretString: aws.String(value), VersionId: aws.String(version)}, nil
}
func (s *fakeSecretsAPI) PutSecretValue(_ context.Context, i *secretsmanager.PutSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.puts = append(s.puts, i)
	if s.err != nil {
		return nil, s.err
	}
	version, value := aws.ToString(i.ClientRequestToken), aws.ToString(i.SecretString)
	if old, ok := s.versions[version]; ok {
		if old != value {
			return nil, ErrRefused
		}
	} else {
		if s.versions == nil {
			s.versions = map[string]string{}
		}
		s.versions[version] = value
		s.value, s.version = value, version
	}
	return &secretsmanager.PutSecretValueOutput{VersionId: aws.String(version)}, nil
}
func TestSecretsAdapterEmptyUnavailableAndRetainedMaterial(t *testing.T) {
	api := &fakeSecretsAPI{err: &sm.ResourceNotFoundException{Message: aws.String("Can't find secret value for staging label: AWSCURRENT")}}
	store := Secrets{Client: api, ID: "secret", Ledger: Ledger{Client: newDynamo(), Table: "table"}}
	if s, e := store.Load(ctx); e != nil || s != nil {
		t.Fatal("empty stack secret", e)
	}
	for _, e := range []error{errors.New("RAW_PROVIDER_MARKER"), &sm.ResourceNotFoundException{Message: aws.String("secret deleted")}, &sm.InvalidRequestException{Message: aws.String("scheduled for deletion")}} {
		api.err = e
		if _, e = store.Load(ctx); e == nil || strings.Contains(e.Error(), "RAW_") {
			t.Fatal("ambiguous/missing secret allowed or leaked", e)
		}
	}
	f := newFixture(t)
	s, e := Bootstrap(ctx, f.h.Config, f.h.Ledger, f.secrets, f.backend, f.at)
	if e != nil {
		t.Fatal(e)
	}
	api.err = nil
	s.StateVersion = 0 // Existing deployments start without a secret fence.
	if e = store.Save(ctx, s); e != nil {
		t.Fatal(e)
	}
	restored, e := store.Load(ctx)
	if e != nil || !bytes.Equal(restored.Private, s.Private) || restored.Commitment != s.Commitment {
		t.Fatal("secret material changed", e)
	}
	if len(api.puts) != 1 || aws.ToString(api.puts[0].SecretId) != "secret" || len(aws.ToString(api.puts[0].ClientRequestToken)) != 43 || strings.Contains(api.value, f.h.Config.Token) {
		t.Fatal("token retained or wrong secret/version")
	}
	// A recreated empty ledger must not recover old identity with fresh consent.
	f.h.Ledger.Client = newDynamo()
	if _, e = Bootstrap(ctx, f.h.Config, f.h.Ledger, f.secrets, f.backend, f.at); e == nil {
		t.Fatal("missing bootstrap state reset replay ledger")
	}
}

func TestSecretsFenceMigratesLegacyAndIgnoresCurrentLabel(t *testing.T) {
	f := newFixture(t)
	legacy, err := Bootstrap(ctx, f.h.Config, f.h.Ledger, f.secrets, f.backend, f.at)
	if err != nil {
		t.Fatal(err)
	}
	legacy.StateVersion = 0
	// A pre-fence deployment has no StateVersion field in its JSON.
	b, _ := json.Marshal(legacy)
	var fields map[string]any
	json.Unmarshal(b, &fields)
	delete(fields, "StateVersion")
	b, _ = json.Marshal(fields)
	api := &fakeSecretsAPI{value: string(b), version: strings.Repeat("a", 43)}
	store := Secrets{Client: api, ID: "secret", Ledger: f.h.Ledger}
	s, err := store.Load(ctx)
	if err != nil || !reflect.DeepEqual(s, legacy) {
		t.Fatal("legacy identity could not load", err)
	}
	stale := copySecret(s)
	if err = Rotate(ctx, store, s, rotationToken(t, f.at, "migrated-key", 0x44), f.at); err != nil {
		t.Fatal("legacy rotation could not establish fence", err)
	}
	if err = store.Save(ctx, stale); !errors.Is(err, ErrRefused) || len(api.puts) != 1 {
		t.Fatal("unfenced legacy writer overwrote migrated state", err)
	}
	// Even a delayed provider request moving AWSCURRENT back cannot select
	// older bytes: the strongly consistent fence names an immutable version.
	api.value, api.version = string(b), strings.Repeat("a", 43)
	reloaded, err := store.Load(ctx)
	if err != nil || !reflect.DeepEqual(reloaded, s) || s.StateVersion != 1 {
		t.Fatal("current label overrode authoritative secret fence", err)
	}
}

func TestSecretsFenceMissingAmbiguousAndFailedWritesRefuse(t *testing.T) {
	for _, failure := range []string{"ledger_unavailable", "missing_fence", "malformed_fence", "empty_fence", "missing_version", "mismatched_version", "put_failed"} {
		t.Run(failure, func(t *testing.T) {
			f := newFixture(t)
			api := &fakeSecretsAPI{}
			store := Secrets{Client: api, ID: "secret", Ledger: f.h.Ledger}
			s, err := Bootstrap(ctx, f.h.Config, f.h.Ledger, store, f.backend, f.at)
			if err != nil {
				t.Fatal(err)
			}
			puts := len(api.puts)
			switch failure {
			case "ledger_unavailable":
				f.db.down = true
				if err = store.Save(ctx, s); !errors.Is(err, ErrRefused) || len(api.puts) != puts {
					t.Fatal("secret put bypassed unavailable ledger", err)
				}
			case "missing_fence":
				delete(f.db.items, "secret")
				if err = store.Save(ctx, s); !errors.Is(err, ErrRefused) || len(api.puts) != puts {
					t.Fatal("missing fence reset version history", err)
				}
			case "malformed_fence":
				f.db.items["secret"]["data"] = &d.AttributeValueMemberB{Value: []byte("{")}
			case "empty_fence":
				f.db.items["secret"]["data"] = &d.AttributeValueMemberB{Value: []byte("{}")}
			case "missing_version":
				delete(api.versions, api.version)
			case "mismatched_version":
				api.versions[api.version] = `{"StateVersion":999}`
			case "put_failed":
				api.err = errors.New("RAW_PROVIDER_MARKER")
				if err = store.Save(ctx, s); !errors.Is(err, ErrRefused) {
					t.Fatal("failed put did not refuse", err)
				}
				api.err = nil
				if err = store.Save(ctx, s); !errors.Is(err, ErrRefused) || len(api.puts) != puts+1 {
					t.Fatal("failed put fence allowed stale retry", err)
				}
			}
			if _, err = store.Load(ctx); !errors.Is(err, ErrRefused) {
				t.Fatal("missing/ambiguous state did not refuse", err)
			}
			if _, err = Bootstrap(ctx, f.h.Config, f.h.Ledger, store, f.backend, f.at); !errors.Is(err, ErrRefused) {
				t.Fatal("bootstrap replaced ambiguous state", err)
			}
		})
	}
}

type fakeS3API struct {
	head   *s3.HeadObjectInput
	get    *s3.GetObjectInput
	output s3.HeadObjectOutput
}

func (s *fakeS3API) HeadObject(_ context.Context, i *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	s.head = i
	return &s.output, nil
}
func (s *fakeS3API) GetObject(_ context.Context, i *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	s.get = i
	return &s3.GetObjectOutput{Body: io.NopCloser(strings.NewReader("data"))}, nil
}
func TestSDKPinAdapterAndKMS(t *testing.T) {
	api := &fakeS3API{output: s3.HeadObjectOutput{ContentLength: aws.Int64(4), ETag: aws.String(`"etag"`), VersionId: aws.String("version")}}
	client := S3Client{Client: api}
	for _, r := range []Request{{
		Bucket:    "bucket",
		Key:       "key",
		VersionID: "version",
		End:       -1,
	}, {
		Bucket:  "bucket",
		Key:     "key",
		IfMatch: `"etag"`,
		Start:   1,
		End:     3,
	}} {
		h, e := client.Head(ctx, r)
		if e != nil || h.ETag != "etag" || h.Size != 4 {
			t.Fatal(h, e)
		}
		body, e := client.Get(ctx, r)
		if e != nil {
			t.Fatal(e)
		}
		body.Close()
		if aws.ToString(api.head.VersionId) != r.VersionID || aws.ToString(api.get.VersionId) != r.VersionID || aws.ToString(api.get.IfMatch) != r.IfMatch || aws.ToString(api.head.IfMatch) != r.IfMatch {
			t.Fatal("pin absent")
		}
		if r.End >= 0 && aws.ToString(api.get.Range) != "bytes=1-3" {
			t.Fatal("range")
		}
	}
	if _, e := client.Get(ctx, Request{}); e == nil {
		t.Fatal("unpinned read")
	}
	api.output.ServerSideEncryption = s3types.ServerSideEncryptionAwsKms
	api.output.SSEKMSKeyId = aws.String("arn:aws:kms:eu-north-1:123456789012:key/abc")
	r := Request{
		Bucket:    "bucket",
		Key:       "key",
		VersionID: "version",
		End:       -1,
	}
	if _, e := client.Head(ctx, r); e == nil {
		t.Fatal("missing KMS grant allowed")
	}
	client.KMS = aws.ToString(api.output.SSEKMSKeyId)
	if _, e := client.Head(ctx, r); e != nil {
		t.Fatal(e)
	}
}
func TestRealSDKRetriesPreserveVersionAndETag(t *testing.T) {
	for _, version := range []string{"", "pinned-version"} {
		t.Run(version, func(t *testing.T) {
			attempts := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts++
				if version != "" {
					if r.URL.Query().Get("versionId") != version || r.Header.Get("If-Match") != "" {
						t.Error("retry version changed")
					}
				} else if r.Header.Get("If-Match") != `"pin"` {
					t.Error("retry ETag changed")
				}
				if r.Header.Get("Range") != "bytes=1-3" {
					t.Error("retry range changed")
				}
				if attempts == 1 {
					w.WriteHeader(503)
					io.WriteString(w, "<Error><Code>SlowDown</Code></Error>")
					return
				}
				w.Header().Set("Content-Length", "3")
				w.Header().Set("Content-Range", "bytes 1-3/4")
				w.WriteHeader(206)
				io.WriteString(w, "ata")
			}))
			defer server.Close()
			api := s3.New(s3.Options{
				Region:       "eu-north-1",
				Credentials:  credentials.NewStaticCredentialsProvider("test", "test", ""),
				BaseEndpoint: aws.String(server.URL),
				UsePathStyle: true,
				HTTPClient:   server.Client(),
				Retryer: retry.NewStandard(func(o *retry.StandardOptions) {
					o.MaxAttempts = 2
					o.MaxBackoff = time.Millisecond
				}),
			})
			c := S3Client{Client: api}
			r := Request{
				Bucket:    "bucket",
				Key:       "key",
				VersionID: version,
				Start:     1,
				End:       3,
			}
			if version == "" {
				r.IfMatch = `"pin"`
			}
			body, e := c.Get(ctx, r)
			if e != nil {
				t.Fatal(e)
			}
			defer body.Close()
			raw, e := io.ReadAll(body)
			if e != nil || string(raw) != "ata" || attempts != 2 {
				t.Fatal("retry", attempts, e)
			}
		})
	}
}
