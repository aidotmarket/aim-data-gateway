package awsverification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	core "github.com/aidotmarket/aim-data-gateway/verification"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	d "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	sm "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/smithy-go"
)

type S3API interface {
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}
type S3Client struct {
	Client S3API
	KMS    string
}

func (s S3Client) Head(ctx context.Context, r Request) (Head, error) {
	i := &s3.HeadObjectInput{Bucket: aws.String(r.Bucket), Key: aws.String(r.Key)}
	if r.VersionID != "" {
		i.VersionId = aws.String(r.VersionID)
	} else {
		if r.IfMatch == "" {
			return Head{}, ErrRefused
		}
		i.IfMatch = aws.String(r.IfMatch)
	}
	o, e := s.Client.HeadObject(ctx, i)
	if e != nil {
		return Head{}, storageRefusal(e)
	}
	if string(o.ServerSideEncryption) == "aws:kms" || string(o.ServerSideEncryption) == "aws:kms:dsse" {
		if s.KMS == "" || aws.ToString(o.SSEKMSKeyId) != s.KMS {
			return Head{}, ErrRefused
		}
	}
	return Head{Size: aws.ToInt64(o.ContentLength), VersionID: aws.ToString(o.VersionId), ETag: strings.Trim(aws.ToString(o.ETag), "\"")}, nil
}
func (s S3Client) Get(ctx context.Context, r Request) (io.ReadCloser, error) {
	i := &s3.GetObjectInput{Bucket: aws.String(r.Bucket), Key: aws.String(r.Key)}
	if r.VersionID != "" {
		i.VersionId = aws.String(r.VersionID)
	} else {
		if r.IfMatch == "" {
			return nil, ErrRefused
		}
		i.IfMatch = aws.String(r.IfMatch)
	}
	if r.End >= 0 {
		i.Range = aws.String(fmt.Sprintf("bytes=%d-%d", r.Start, r.End))
	}
	o, e := s.Client.GetObject(ctx, i)
	if e != nil {
		return nil, storageRefusal(e)
	}
	return o.Body, nil
}

type SecretsAPI interface {
	GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
	PutSecretValue(context.Context, *secretsmanager.PutSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error)
}
type Secrets struct {
	Client SecretsAPI
	ID     string
	Ledger Ledger
}

type secretFence struct {
	Version int64
	ID      string
}

func (s Secrets) Load(ctx context.Context) (*Secret, error) {
	if s.Ledger.Client == nil || s.Ledger.Table == "" {
		return nil, ErrRefused
	}
	var fence secretFence
	fenced, e := s.Ledger.get(ctx, "secret", &fence)
	if e != nil || (fenced && (fence.Version <= 0 || len(fence.ID) != 43)) {
		return nil, ErrRefused
	}
	i := &secretsmanager.GetSecretValueInput{SecretId: aws.String(s.ID)}
	if fenced {
		// Versions are immutable. Never fall back to AWSCURRENT if a fenced put
		// is incomplete, unavailable, or its response was lost.
		i.VersionId = aws.String(fence.ID)
	}
	o, e := s.Client.GetSecretValue(ctx, i)
	if e != nil {
		// Empty CloudFormation Secret has no AWSCURRENT version. Only this precise
		// condition can initialize; a missing/deleted secret is never recreated.
		var x *sm.ResourceNotFoundException
		if !fenced && errors.As(e, &x) && strings.Contains(aws.ToString(x.Message), "staging label: AWSCURRENT") {
			return nil, nil
		}
		return nil, ErrRefused
	}
	if o.SecretString == nil || len(*o.SecretString) > 64<<10 {
		return nil, ErrRefused
	}
	var v Secret
	if json.Unmarshal([]byte(*o.SecretString), &v) != nil || v.StateVersion != fence.Version || (fenced && aws.ToString(o.VersionId) != fence.ID) {
		return nil, ErrRefused
	}
	return &v, nil
}
func (s Secrets) Save(ctx context.Context, v *Secret) error {
	if s.Ledger.Client == nil || s.Ledger.Table == "" || v == nil || v.StateVersion < 0 || v.StateVersion+1 <= 0 {
		return ErrRefused
	}
	next := *v
	next.StateVersion++
	b, e := json.Marshal(&next)
	if e != nil || len(b) > 64<<10 {
		return ErrRefused
	}
	n, e := randomToken()
	if e != nil {
		return ErrRefused
	}
	// Reserve the next immutable version before putting any secret bytes. Only
	// a reader of that completed version can advance again; a crash leaves an
	// unreadable fence and refuses work rather than resetting key history.
	fence, _ := json.Marshal(secretFence{Version: next.StateVersion, ID: n})
	m := key("secret")
	m["data"], m["version"] = &d.AttributeValueMemberB{Value: fence}, num(next.StateVersion)
	cond := "attribute_not_exists(pk)"
	var values map[string]d.AttributeValue
	if v.StateVersion != 0 {
		cond, values = "version = :old", map[string]d.AttributeValue{":old": num(v.StateVersion)}
	}
	_, e = s.Ledger.Client.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(s.Ledger.Table), Item: m, ConditionExpression: aws.String(cond), ExpressionAttributeValues: values})
	if e != nil {
		return ErrRefused
	}
	_, e = s.Client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{SecretId: aws.String(s.ID), SecretString: aws.String(string(b)), ClientRequestToken: aws.String(n)})
	if e != nil {
		return ErrRefused
	}
	v.StateVersion = next.StateVersion
	return nil
}

func storageRefusal(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var api smithy.APIError
	if errors.As(err, &api) {
		switch api.ErrorCode() {
		case "AccessDenied", "Forbidden", "403":
			return core.ErrPermissionDenied
		case "PreconditionFailed", "NoSuchKey", "NoSuchVersion", "NotFound", "404", "412":
			return core.ErrArtifactChanged
		}
	}
	return core.ErrScannerFailure
}
