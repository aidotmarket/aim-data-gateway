package main

import (
	"context"
	av "github.com/aidotmarket/aim-data-gateway/internal/awsverification"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"net/http"
	"os"
	"time"
)

func handler(ctx context.Context) error {
	c, e := av.ParseConfig(os.Getenv)
	if e != nil || os.Getenv("AWS_REGION") != c.Region {
		return av.ErrRefused
	}
	// Lambda supplies short-lived execution-role credentials. No shared profiles,
	// STS, metadata fallback, endpoint overrides or seller-selected HTTP proxy.
	creds := credentials.NewStaticCredentialsProvider(os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"), os.Getenv("AWS_SESSION_TOKEN"))
	if os.Getenv("AWS_ACCESS_KEY_ID") == "" || os.Getenv("AWS_SECRET_ACCESS_KEY") == "" || os.Getenv("AWS_SESSION_TOKEN") == "" {
		return av.ErrRefused
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return av.ErrRefused }}
	// SDK service constructors supply a Nop logger when Logger is nil.
	base := aws.Config{Region: c.Region, Credentials: creds, HTTPClient: client, RetryMaxAttempts: 3}
	audit := av.Logs{Client: client, Credentials: creds, Region: c.Region, Group: c.LogGroup, Stream: "aim-verification"}
	h := av.Handler{Config: c, Ledger: av.Ledger{Table: c.Table, Client: dynamodb.NewFromConfig(base)}, Store: av.Secrets{ID: c.Secret, Client: secretsmanager.NewFromConfig(base)}, S3: av.S3Client{Client: s3.NewFromConfig(base), KMS: c.KMS}, Backend: av.HTTPBackend{Config: c, Client: av.MarketplaceClient(audit)}, Audit: audit}
	return h.Invoke(ctx)
}
func main() { lambda.Start(handler) }
