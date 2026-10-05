package awsverification

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	sm "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

type fakeSecretsAPI struct {
	value string
	err   error
	puts  []*secretsmanager.PutSecretValueInput
}

func (s *fakeSecretsAPI) GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &secretsmanager.GetSecretValueOutput{SecretString: aws.String(s.value)}, nil
}
func (s *fakeSecretsAPI) PutSecretValue(_ context.Context, i *secretsmanager.PutSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
	s.puts = append(s.puts, i)
	s.value = aws.ToString(i.SecretString)
	return &secretsmanager.PutSecretValueOutput{}, s.err
}
func TestSecretsAdapterEmptyUnavailableAndRetainedMaterial(t *testing.T) {
	api := &fakeSecretsAPI{err: &sm.ResourceNotFoundException{Message: aws.String("Can't find secret value for staging label: AWSCURRENT")}}
	store := Secrets{Client: api, ID: "secret"}
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
