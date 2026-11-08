package awsverification

import (
	"encoding/json"
	"errors"
	"math"
	"strings"

	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	core "github.com/aidotmarket/aim-data-gateway/verification"
)

const (
	AWS_VERIFY_TEXT_MAX_BYTES            = int64(6_000_000_000)
	AWS_VERIFY_PARQUET_MAX_BYTES         = int64(1_000_000_000)
	AWS_VERIFY_ESTIMATED_TEXT_BPS        = int64(10_000_000)
	AWS_VERIFY_ESTIMATED_PARQUET_BPS     = int64(1_800_000)
	AWS_VERIFY_OVERHEAD_SECONDS          = 120
	AWS_VERIFY_ESTIMATE_MAX_SECONDS      = 720
	AWS_VERIFY_DEADLINE_SECONDS          = 780
	AWS_VERIFY_TERMINAL_DEADLINE_SECONDS = 1920
	MaxMembers                           = 17033
	MaxReport                            = 2 << 20
	APIBaseURL                           = "https://api.ai.market"
	EnvConnection                        = "AIM_AWS_CONNECTION_ID"
	EnvBucket                            = "AIM_AWS_BUCKET"
	EnvRegion                            = "AIM_AWS_BUCKET_REGION"
	EnvReadScope                         = "AIM_AWS_READ_SCOPE_MODE"
	EnvScope                             = "AIM_AWS_READ_SCOPE"
	EnvSecret                            = "AIM_AWS_SECRET_ID"
	EnvTable                             = "AIM_AWS_LEDGER_TABLE"
	EnvToken                             = "AIM_AWS_REGISTRATION_TOKEN"
	EnvVersion                           = "AIM_AWS_SCANNER_VERSION"
	EnvDigest                            = "AIM_AWS_IMAGE_DIGEST"
	EnvAPI                               = "AIM_AWS_API_BASE_URL"
	EnvLogGroup                          = "AIM_AWS_LOG_GROUP"
	EnvKMS                               = "AIM_AWS_SSE_KMS_KEY_ARN"
	EnvMemory                            = "AWS_LAMBDA_FUNCTION_MEMORY_SIZE"
)

var ErrRefused = errors.New("verification_refused")

type Scope struct {
	Keys     []string `json:"keys"`
	Prefixes []string `json:"prefixes"`
}
type Config struct {
	Connection, Bucket, Region, Secret, Table, Token, Version, Digest, LogGroup, KMS string
	ReadScope                                                                        string
	Scope                                                                            Scope
}

func ParseConfig(get func(string) string) (Config, error) {
	c := Config{
		Connection: get(EnvConnection),
		Bucket:     get(EnvBucket),
		Region:     get(EnvRegion),
		Secret:     get(EnvSecret),
		Table:      get(EnvTable),
		Token:      get(EnvToken),
		Version:    get(EnvVersion),
		Digest:     get(EnvDigest),
		LogGroup:   get(EnvLogGroup),
		KMS:        get(EnvKMS),
		ReadScope:  get(EnvReadScope),
	}
	if json.Unmarshal([]byte(get(EnvScope)), &c.Scope) != nil {
		return c, ErrRefused
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(get(EnvScope)), &fields) != nil || len(fields) != 2 || fields["keys"] == nil || fields["prefixes"] == nil {
		return c, ErrRefused
	}
	if get(EnvMemory) != "1769" && get(EnvMemory) != "3008" {
		return c, ErrRefused
	}
	if get(EnvAPI) != APIBaseURL || !uuid.MatchString(c.Connection) || !identifier.MatchString(c.Version) || !strings.HasPrefix(c.Digest, "sha256:") || !hex64.MatchString(strings.TrimPrefix(c.Digest, "sha256:")) || c.Secret == "" || c.Table == "" || c.LogGroup == "" || len(c.Bucket) < 3 || strings.ContainsAny(c.Bucket, "/:*?\\\x00") {
		return c, ErrRefused
	}
	if b, e := wire.DecodeDocument(c.Token, 32); e != nil || len(b) != 32 {
		return c, ErrRefused
	}
	if !strings.Contains(" eu-north-1 eu-west-1 eu-central-1 us-east-1 us-west-2 ", " "+c.Region+" ") {
		return c, ErrRefused
	}
	if c.ReadScope != "" && c.ReadScope != "prefix" && c.ReadScope != "whole_bucket" {
		return c, ErrRefused
	}
	if c.ReadScope != "whole_bucket" && len(c.Scope.Keys)+len(c.Scope.Prefixes) == 0 || len(c.Scope.Keys)+len(c.Scope.Prefixes) > 50 {
		return c, ErrRefused
	}
	if c.ReadScope == "whole_bucket" && (len(c.Scope.Keys) != 0 || len(c.Scope.Prefixes) > 1 || len(c.Scope.Prefixes) == 1 && c.Scope.Prefixes[0] != "") {
		return c, ErrRefused
	}
	for _, s := range append(append([]string{}, c.Scope.Keys...), c.Scope.Prefixes...) {
		if s == "" && c.ReadScope != "whole_bucket" || strings.Contains(s, "${") || strings.ContainsAny(s, "*?\x00") {
			return c, ErrRefused
		}
	}
	return c, nil
}
func (c Config) permits(key string) bool {
	if c.ReadScope == "whole_bucket" {
		return key != "" && !strings.ContainsRune(key, 0)
	}
	for _, k := range c.Scope.Keys {
		if key == k {
			return true
		}
	}
	for _, p := range c.Scope.Prefixes {
		if p != "" && strings.HasPrefix(key, strings.TrimRight(p, "/")+"/") {
			return true
		}
	}
	return false
}

// Integer units make the shared mixed budget and throughput inequalities exact.
func AdmitSize(objects []Object, planned ...int64) error {
	if len(objects) == 0 {
		return core.ErrEmptyVersion
	}
	if len(objects) > MaxMembers {
		return core.ErrMemberCountExceeded
	}
	if WorstReportSize(len(objects)) > MaxReport {
		return ErrRefused
	}
	var t, p, census int64
	for _, o := range objects {
		if o.Size < 0 {
			return ErrRefused
		}
		switch o.Format {
		case "csv", "tsv", "jsonl":
			if o.Size > AWS_VERIFY_TEXT_MAX_BYTES-t {
				return ErrRefused
			}
			t += o.Size
		case "parquet":
			if o.Size > AWS_VERIFY_PARQUET_MAX_BYTES-p {
				return ErrRefused
			}
			p += o.Size
		default:
			if o.Size > math.MaxInt64-census {
				return core.ErrResourceLimit
			}
			census += o.Size
		}
		if t > AWS_VERIFY_TEXT_MAX_BYTES || p > AWS_VERIFY_PARQUET_MAX_BYTES {
			return ErrRefused
		}
	}
	if census > math.MaxInt64-t-p {
		return core.ErrResourceLimit
	}
	if t+6*p > AWS_VERIFY_TEXT_MAX_BYTES || 9*t+50*p > int64(AWS_VERIFY_ESTIMATE_MAX_SECONDS-AWS_VERIFY_OVERHEAD_SECONDS)*90_000_000 {
		return ErrRefused
	}
	if len(planned) > 1 {
		return ErrRefused
	}
	if len(planned) == 1 {
		if planned[0] < 0 || planned[0] > censusR1BudgetBytes {
			return core.ErrResourceLimit
		}
		// C3's §3.6 estimator lowers this signed allowance using R1's rates;
		// the adapter enforces it exactly. Full census stored size is not a read cost.
	}
	return nil
}

func WorstReportSize(members int) int {
	if members < 1 || members > MaxMembers {
		return MaxReport + 1
	}
	return 955734 + 171 + 67*members - 1
}
