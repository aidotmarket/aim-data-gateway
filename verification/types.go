// Package verification computes the frozen S1590 aggregates on pinned source bytes.
// Adapters own consent, containment, version and offer checks; this package has no
// transport, persistence, credentials or enabled caller.
package verification

import (
	"context"
	"errors"
	"io"
	"time"
)

type Member struct {
	Identity      string
	Size          int64
	SHA256        [32]byte
	DigestPresent bool   // Gateway digests remain required by default.
	OrderingKey   []byte // Cloud identity bytes; nil selects the gateway contract.
	Format        string // csv, tsv, jsonl, parquet; other formats are disclosed skips.
}
type RandomAccess interface {
	io.ReaderAt
	io.Closer
	Size() int64
}

// Members returns the immutable, identity-ascending retained member set.
// Every open must resolve exactly the pinned identity, under adapter scope checks.
type Source interface {
	Members() []Member
	Open(context.Context, string) (io.ReadCloser, error)
	OpenAt(context.Context, string) (RandomAccess, error)
}
type Policy struct {
	Seed                                                                        [32]byte
	CanonicalizationVersion, RowCountAlgorithmVersion, DistinctAlgorithmVersion string
	HistogramVersion, NumericBucketVersion                                      string
	MinimumAggregateOccupancy                                                   int
	LengthBounds                                                                []int
	NumericBoundaries                                                           []float64
	MaxMemoryBytes                                                              int64
	MaxRecordBytes, MaxScalarBytes, MaxColumns, MaxFactBytes                    int
	Deadline                                                                    time.Duration
	MemoryPeak                                                                  *int64 // Optional observation of scanner reservations, including adapter buffers.
	// The adapter constructs typed preimages; gateway inputs must be ASCII UUID/hex.
	GatewayID, SnapshotHash string
	CommitmentKey           [32]byte
	// Future cloud adapters supply their approved typed commitment strategy.
	// Nil selects section 6.3's gateway preimages. Values remain fixed opaque hex;
	// strategy output cannot influence traversal, parsers or aggregate computation.
	Commitments interface {
		LocatorCommitment() string
		ObjectID(Member) string
	}
}
type Coverage struct {
	Discovered int            `json:"objects_discovered"`
	Scanned    int            `json:"objects_scanned"`
	Reasons    map[string]int `json:"objects_skipped_by_reason"`
	Skipped    []Skip         `json:"skipped"`
}
type Skip struct {
	ObjectID string `json:"object_id"`
	Reason   string `json:"reason"`
}
type Object struct {
	ObjectID  string   `json:"object_id"`
	Names     []string `json:"column_names"`
	Types     []string `json:"column_types"`
	NullRate  []any    `json:"null_rate"`
	Distinct  []any    `json:"approx_distinct_count"`
	Length    []any    `json:"length_histograms"`
	Numeric   []any    `json:"numeric_range_buckets"`
	Rows      int64    `json:"row_count"`
	RowMethod string   `json:"row_count_method"`
}
type Facts struct {
	Coverage          Coverage `json:"coverage"`
	Objects           []Object `json:"objects"`
	FingerprintHash   string   `json:"fingerprint_hash"`
	ContentSHA256     string   `json:"content_sha256"`
	LocatorCommitment string   `json:"artifact_locator_commitment"`
}
type ProbeResult struct {
	ObjectsDiscovered       int
	SizeClass               string
	EstimatedMaxInputTokens int
	SupportedCapabilities   []string
}

var (
	ErrArtifactChanged = errors.New("artifact_changed") // caller terminates FAILED_VOIDED; no partial facts.
	ErrUnsupported     = errors.New("unsupported_type")
	ErrBudget          = errors.New("scanner_failure")
	ErrTimeout         = errors.New("timeout")
)

const suppressed = "suppressed_low_occupancy"
