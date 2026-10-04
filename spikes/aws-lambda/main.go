package main

import (
	"context"
	"github.com/aidotmarket/aim-data-gateway/spikes/cloud"
	h "github.com/aidotmarket/aim-data-gateway/spikes/harness"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func handle(ctx context.Context, e h.Event) (h.Result, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return h.Result{Mode: e.Mode, Error: err.Error()}, nil
	}
	return h.Run(ctx, e, cloud.Factory(s3.NewFromConfig(cfg, func(o *s3.Options) { o.RetryMaxAttempts = 1 }), "s3_listing")), nil
}
func main() { lambda.Start(handle) }
