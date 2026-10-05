package awsverification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	sm "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
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
		return Head{}, ErrRefused
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
		return nil, ErrRefused
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
}

func (s Secrets) Load(ctx context.Context) (*Secret, error) {
	o, e := s.Client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(s.ID)})
	if e != nil {
		// Empty CloudFormation Secret has no AWSCURRENT version. Only this precise
		// condition can initialize; a missing/deleted secret is never recreated.
		var x *sm.ResourceNotFoundException
		if errors.As(e, &x) && strings.Contains(aws.ToString(x.Message), "staging label: AWSCURRENT") {
			return nil, nil
		}
		return nil, ErrRefused
	}
	if o.SecretString == nil || len(*o.SecretString) > 64<<10 {
		return nil, ErrRefused
	}
	var v Secret
	if json.Unmarshal([]byte(*o.SecretString), &v) != nil {
		return nil, ErrRefused
	}
	return &v, nil
}
func (s Secrets) Save(ctx context.Context, v *Secret) error {
	b, e := json.Marshal(v)
	if e != nil || len(b) > 64<<10 {
		return ErrRefused
	}
	n, e := randomToken()
	if e != nil {
		return ErrRefused
	}
	_, e = s.Client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{SecretId: aws.String(s.ID), SecretString: aws.String(string(b)), ClientRequestToken: aws.String(n)})
	if e != nil {
		return ErrRefused
	}
	return nil
}
