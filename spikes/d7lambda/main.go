//go:build d7spike

// D7 read-ahead benchmark Lambda (S1791 spike branch only, never merged).
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/awsverification"
	"github.com/aidotmarket/aim-data-gateway/verification"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type Event struct {
	Bucket, Key, Format string
	Ahead               int64
}
type Result struct {
	Bucket, Key, VersionID, ETag string
	Size, Ahead, Gets, Heads     int64
	FetchedBytes, BudgetPeak     int64
	ElapsedMs, VmHWMKiB          int64
	FactsSHA256, Error           string
	MemoryMB                     string
}

type client struct {
	c            *s3.Client
	gets, heads  atomic.Int64
	fetched      atomic.Int64
}
type counting struct {
	io.ReadCloser
	n *atomic.Int64
}

func (r counting) Read(p []byte) (int, error) { n, e := r.ReadCloser.Read(p); r.n.Add(int64(n)); return n, e }

func (c *client) Head(ctx context.Context, r awsverification.Request) (awsverification.Head, error) {
	c.heads.Add(1)
	in := &s3.HeadObjectInput{Bucket: aws.String(r.Bucket), Key: aws.String(r.Key)}
	if r.VersionID != "" {
		in.VersionId = aws.String(r.VersionID)
	} else if r.IfMatch != "" {
		in.IfMatch = aws.String(r.IfMatch)
	}
	o, e := c.c.HeadObject(ctx, in)
	if e != nil {
		return awsverification.Head{}, e
	}
	return awsverification.Head{Size: aws.ToInt64(o.ContentLength), VersionID: aws.ToString(o.VersionId), ETag: aws.ToString(o.ETag)}, nil
}
func (c *client) Get(ctx context.Context, r awsverification.Request) (io.ReadCloser, error) {
	c.gets.Add(1)
	in := &s3.GetObjectInput{Bucket: aws.String(r.Bucket), Key: aws.String(r.Key)}
	if r.VersionID != "" {
		in.VersionId = aws.String(r.VersionID)
	} else if r.IfMatch != "" {
		in.IfMatch = aws.String(r.IfMatch)
	}
	if r.End >= 0 {
		in.Range = aws.String(fmt.Sprintf("bytes=%d-%d", r.Start, r.End))
	}
	o, e := c.c.GetObject(ctx, in)
	if e != nil {
		return nil, e
	}
	return counting{o.Body, &c.fetched}, nil
}

func hwm() int64 {
	b, _ := os.ReadFile("/proc/self/status")
	s := bufio.NewScanner(bytes.NewReader(b))
	for s.Scan() {
		if strings.HasPrefix(s.Text(), "VmHWM:") {
			var v int64
			fmt.Sscanf(strings.TrimSpace(strings.TrimPrefix(s.Text(), "VmHWM:")), "%d", &v)
			return v
		}
	}
	return -1
}

func handle(ctx context.Context, e Event) (Result, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return Result{}, err
	}
	c := &client{c: s3.NewFromConfig(cfg)}
	h, err := c.c.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(e.Bucket), Key: aws.String(e.Key)})
	if err != nil {
		return Result{}, err
	}
	o := awsverification.Object{Key: e.Key, VersionID: aws.ToString(h.VersionId), ETag: aws.ToString(h.ETag), Format: e.Format, Size: aws.ToInt64(h.ContentLength)}
	res := Result{Bucket: e.Bucket, Key: e.Key, VersionID: o.VersionID, ETag: o.ETag, Size: o.Size, Ahead: e.Ahead, MemoryMB: os.Getenv("AWS_LAMBDA_FUNCTION_MEMORY_SIZE")}
	src, err := awsverification.NewSourceReadAhead(c, e.Bucket, []awsverification.Object{o}, e.Ahead)
	if err != nil {
		return res, err
	}
	var peak int64
	p := verification.Policy{CanonicalizationVersion: "python-json-sort-compact-v1", RowCountAlgorithmVersion: "exact-v1", DistinctAlgorithmVersion: "hll-sha256-v1", HistogramVersion: "fixed-buckets-v1", NumericBucketVersion: "fixed-buckets-v1", MinimumAggregateOccupancy: 10, LengthBounds: []int{0, 1, 4, 8, 16, 32, 64, 128, 256}, NumericBoundaries: []float64{-1000, -100, -10, 0, 10, 100, 1000}, Deadline: 14 * time.Minute, MemoryPeak: &peak,
		Commitments: awsverification.Commitments{Bucket: e.Bucket, ManifestHash: strings.Repeat("a", 64)}}
	start := time.Now()
	facts, err := verification.Scan(ctx, src, p)
	res.ElapsedMs = time.Since(start).Milliseconds()
	res.Gets, res.Heads, res.FetchedBytes, res.BudgetPeak, res.VmHWMKiB = c.gets.Load(), c.heads.Load(), c.fetched.Load(), peak, hwm()
	if err != nil {
		res.Error = err.Error()
		if errors.Is(err, context.DeadlineExceeded) {
			res.Error = "deadline"
		}
		return res, nil
	}
	j, _ := json.Marshal(facts)
	sum := sha256.Sum256(j)
	res.FactsSHA256 = hex.EncodeToString(sum[:])
	return res, nil
}

func main() { lambda.Start(handle) }
