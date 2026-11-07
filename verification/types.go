// Package verification computes the frozen S1590 aggregates on pinned source bytes.
// Adapters own consent, containment, version and offer checks; this package has no
// transport, persistence, credentials or enabled caller.
package verification

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"time"
)

type Member struct {
	Identity        string
	Size            int64
	SHA256          [32]byte
	DigestPresent   bool   // Gateway digests remain required by default.
	OrderingKey     []byte // Cloud identity bytes; nil selects the gateway contract.
	Format          string // The signed format selects tables versus census.
	ETag, VersionID string // Unquoted provider metadata, bound under v2.
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
	censusMemory                                                                *censusMemory
	ScanMode, BindingMethod                                                     string
	ContentReadBudgetBytes, PlannedProcessedBytes, ArchiveAllowanceBytes        int64
	ArchiveCaps                                                                 ArchiveCaps
	PatternVersions                                                             []string
	RunStats                                                                    *RunStats // Local only: actual GET and HEAD requests, never public facts.
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
	InCensus   int            `json:"objects_in_census,omitempty"`
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
	ContentCensus       *ContentCensus `json:"content_census,omitempty"`
	UnreadBindingSHA256 string         `json:"unread_binding_sha256,omitempty"`
	memberDigests       map[string][32]byte
	Coverage            Coverage `json:"coverage"`
	Objects             []Object `json:"objects"`
	FingerprintHash     string   `json:"fingerprint_hash"`
	ContentSHA256       string   `json:"content_sha256"`
	LocatorCommitment   string   `json:"artifact_locator_commitment"`
}
type ProbeResult struct {
	ObjectsDiscovered       int      `json:"objects_discovered"`
	SizeClass               string   `json:"size_class"`
	EstimatedMaxInputTokens int      `json:"estimated_max_input_tokens"`
	SupportedCapabilities   []string `json:"supported_capabilities"`
	SourceReachable         bool     `json:"source_reachable"`
	RefusalReason           string   `json:"refusal_reason,omitempty"`
}

// RefusalError is stable across adapters; wrapping preserves errors.Is.
type RefusalError string

func (e RefusalError) Error() string { return string(e) }

var (
	ErrArtifactChanged = RefusalError("artifact_changed")
	ErrUnsupported     = RefusalError("unsupported_type")
	ErrSummaryBudget   = RefusalError("summary_budget_exceeded")
	ErrResourceLimit   = RefusalError("resource_limit_exceeded")
	// ErrBudget preserves direct comparisons in legacy adapters without ScanMode.
	ErrBudget                      = ErrResourceLimit
	ErrTimeout                     = RefusalError("timeout")
	ErrPermissionDenied            = RefusalError("permission_denied")
	ErrScannerFailure              = RefusalError("scanner_failure")
	ErrVerifierUpgradeRequired     = RefusalError("verifier_upgrade_required")
	ErrInsufficientReadableContent = RefusalError("insufficient_readable_content")
	ErrMemberCountExceeded         = RefusalError("member_count_exceeded")
)

func RefusalReason(err error) string {
	if err == nil {
		return ""
	}
	var refusal RefusalError
	if errors.As(err, &refusal) {
		return refusal.Error()
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return ErrTimeout.Error()
	}
	if errors.Is(err, fs.ErrPermission) {
		return ErrPermissionDenied.Error()
	}
	return ErrScannerFailure.Error()
}

const suppressed = "suppressed_low_occupancy"
