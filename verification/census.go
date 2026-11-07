package verification

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"io"
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"
)

const ContentCensusV1, archiveTransportSlack = "content_census_v1", int64(1 << 20)
const CensusAdvisoryTokens = 2304 // Provisional bytes/3 estimate rounded up to 256; C3 measures provider tokens. Advisory only.
const CensusR1AWSBudgetBytes, CensusR1CloudflareBudgetBytes, CensusR1ArchiveAllowanceBytes = int64(4_000_000_000), int64(3_000_000_000), int64(64 << 20)

var patternVersions = []string{"email_v1", "phone_e164_or_separated_v1", "credential_v1", "licence_families_v1", "simhash64_5shingle_v1"}

type ArchiveCaps struct {
	UncompressedBytes int64
	Entries           int
	CompressionRatio  int64
}

type censusMemory struct {
	used   atomic.Int64
	limit  int64
	failed atomic.Bool
	spools chan struct{} // Two allowances: at most 128 MiB of decoded tar spool per run.
}

func (m *censusMemory) reserve(n int64) bool {
	if m == nil {
		return true
	}
	for {
		v := m.used.Load()
		if n > m.limit-v || m.failed.Load() {
			m.failed.Store(true)
			return false
		}
		if m.used.CompareAndSwap(v, v+n) {
			return true
		}
	}
}

// RunStats counts actual census GET and HEAD calls, including failures, locally.
// Atomics allow all sixteen workers to share it; table requests stay adapter-owned.
type RunStats struct {
	GETs, HEADs                atomic.Int64
	ProcessedBytes             atomic.Int64
	PlannedBytes, StoredBytes  atomic.Int64 // Planned decoded ZIP bytes; actual transport bytes, including preflight.
	RequestedBytes             atomic.Int64 // Sum of OpenRange lengths, including failed requests.
	SpoolBytes, SpoolPeakBytes atomic.Int64
}

type statsReader struct {
	r     io.Reader
	stats *RunStats
}

func (r *statsReader) Read(b []byte) (int, error) {
	n, e := r.r.Read(b)
	r.stats.StoredBytes.Add(int64(n))
	return n, e
}

// CensusSource must enforce signed snapshot containment for both operations.
// OpenRange uses offset and length (not an inclusive end); tar.gz uses exactly
// one call: offset 0, length allowance+1MiB, even if the provider ignores Range.
type CensusSource interface {
	Source
	OpenRange(context.Context, string, int64, int64) (io.ReadCloser, error)
	Head(context.Context, string) (Member, error)
}

func (p Policy) checkCensusPolicy() error {
	if p.ScanMode != "" && p.ScanMode != "table_v1" && p.ScanMode != ContentCensusV1 {
		return ErrUnsupported
	}
	if p.BindingMethod != "" && p.BindingMethod != "full_sha256_v1" && p.BindingMethod != "planned_read_commitment_v2" {
		return ErrUnsupported
	}
	census := p.ScanMode == ContentCensusV1
	if (census || p.ContentReadBudgetBytes != 0) && p.ContentReadBudgetBytes != CensusR1AWSBudgetBytes && p.ContentReadBudgetBytes != CensusR1CloudflareBudgetBytes || p.PlannedProcessedBytes < 0 || p.PlannedProcessedBytes > p.ContentReadBudgetBytes {
		return ErrUnsupported
	}
	if (census || p.ArchiveAllowanceBytes != 0) && p.ArchiveAllowanceBytes != CensusR1ArchiveAllowanceBytes {
		return ErrUnsupported
	}
	if (census || p.ArchiveCaps != (ArchiveCaps{})) && p.ArchiveCaps != (ArchiveCaps{256 << 20, 10000, 1000}) {
		return ErrUnsupported
	}
	if census || len(p.PatternVersions) > 0 {
		if len(p.PatternVersions) != len(patternVersions) {
			return ErrUnsupported
		}
		for i, v := range patternVersions {
			if p.PatternVersions[i] != v {
				return ErrUnsupported
			}
		}
	}
	if census && p.BindingMethod != "planned_read_commitment_v2" || !census && p.BindingMethod == "planned_read_commitment_v2" {
		return ErrUnsupported
	}
	return nil
}

// PlannedReadSet is pure and leaves snapshot order and input slices unchanged.
// A member that does not fit is skipped; unused archive allowance is not respent.
func PlannedReadSet(seed [32]byte, members []Member, literals Policy) []string {
	type ranked struct {
		m    Member
		rank [32]byte
	}
	xs := make([]ranked, 0, len(members))
	for _, m := range members {
		if supported(m.Format) {
			continue
		}
		h := hmac.New(sha256.New, seed[:])
		h.Write([]byte(m.Identity))
		xs = append(xs, ranked{m, [32]byte(h.Sum(nil))})
	}
	sort.Slice(xs, func(i, j int) bool {
		c := bytes.Compare(xs[i].rank[:], xs[j].rank[:])
		if c == 0 {
			return xs[i].m.Identity < xs[j].m.Identity
		}
		return c < 0
	})
	out := []string{}
	remaining := literals.PlannedProcessedBytes
	for _, x := range xs {
		cost := x.m.Size
		if archiveFormat(x.m) != "" {
			cost = literals.ArchiveAllowanceBytes
		}
		if cost >= 0 && cost <= remaining {
			out = append(out, x.m.Identity)
			remaining -= cost
		}
	}
	return out
}

type memberSlice struct {
	Source
	members []Member
}

func (s memberSlice) Members() []Member { return s.members }

type censusMemberResult struct {
	err                                         error // Verifier failures refuse the entire run before any facts/binding can publish.
	plain                                       bool  // An archive candidate whose content proved to be a plain member.
	commitment                                  MemberCommitment
	state, reason                               string
	opened                                      bool
	storedRead, processed, readable, unreadable int64
	entries, entryBytes                         int64
	findings                                    inspection
	reasons                                     map[string]int64
}

func unreadResult(m Member, reason string) censusMemberResult {
	return censusMemberResult{commitment: unreadCommitment(m), state: "unread", reason: reason}
}
func parallel(n int, fn func(int)) {
	var wg sync.WaitGroup
	var next atomic.Int64
	for range min(16, n) {
		wg.Go(func() {
			for {
				i := int(next.Add(1)) - 1
				if i >= n {
					return
				}
				fn(i)
			}
		})
	}
	wg.Wait()
}

func scanCensus(ctx context.Context, s Source, p Policy) (Facts, error) {
	cs, ok := s.(CensusSource)
	if !ok {
		return Facts{}, ErrUnsupported
	}
	members := append([]Member(nil), s.Members()...)
	if len(members) == 0 {
		return Facts{}, ErrEmptyVersion
	}
	if len(members) > 100000 {
		return Facts{}, ErrMemberCountExceeded
	}
	var tables, census []Member
	var total int64
	for i, m := range members {
		if !utf8.ValidString(m.Identity) || !utf8.ValidString(m.ETag) || !utf8.ValidString(m.VersionID) || m.Identity == "" || m.OrderingKey == nil && !fileIDASCII(m.Identity) || m.OrderingKey != nil && (p.Commitments == nil || string(m.OrderingKey) != m.Identity) || m.Size < 0 || m.Size > math.MaxInt64-total || i > 0 && members[i-1].Identity >= m.Identity {
			return Facts{}, ErrArtifactChanged
		}
		total += m.Size
		if supported(m.Format) {
			tables = append(tables, m)
		} else {
			census = append(census, m)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, p.Deadline)
	defer cancel()
	f := Facts{Coverage: Coverage{Reasons: map[string]int{}, Skipped: []Skip{}}, Objects: []Object{}, memberDigests: map[string][32]byte{}}
	if len(tables) > 0 {
		var err error
		f, err = scanTables(ctx, memberSlice{s, tables}, p)
		if err != nil {
			return Facts{}, err
		}
	}
	f.Coverage.Discovered = len(members)
	f.Coverage.InCensus = len(census)
	plan := PlannedReadSet(p.Seed, census, p)
	in := map[string]bool{}
	for _, id := range plan {
		in[id] = true
	}
	// Reserve worker buffers, central directories, metadata and compact fingerprints.
	// No file body is retained, and a tar.gz decoded commitment is spooled locally.
	if int64(len(census))*1024+16*(4<<20) > p.MaxMemoryBytes {
		return Facts{}, ErrResourceLimit
	}
	p.censusMemory = &censusMemory{limit: p.MaxMemoryBytes, spools: make(chan struct{}, 2)}
	p.censusMemory.used.Store(int64(len(census))*1024 + 16*(4<<20))
	defer func() {
		if p.MemoryPeak != nil {
			*p.MemoryPeak = max(*p.MemoryPeak, p.censusMemory.used.Load())
		}
	}()
	results := make([]censusMemberResult, len(census))
	stats := p.RunStats
	if stats == nil {
		stats = &RunStats{}
	}
	parallel(len(census), func(i int) {
		m := census[i]
		r := unreadResult(m, "not_sampled")
		if in[m.Identity] {
			if ctx.Err() != nil {
				r.reason = "budget_exhausted"
			} else {
				r = readCensusMember(ctx, cs, m, p, stats)
			}
		}
		results[i] = r
		stats.ProcessedBytes.Add(r.processed)
	})
	if p.censusMemory.failed.Load() {
		return Facts{}, ErrResourceLimit
	}
	for _, r := range results {
		if r.err != nil {
			return Facts{}, r.err
		}
	}
	// HEAD unread members even after a scan deadline, with a fresh bounded context:
	// timing stops are publishable only after unread metadata was checked.
	headCtx, headCancel := context.WithTimeout(context.WithoutCancel(ctx), p.Deadline)
	defer headCancel()
	errs := make([]error, len(census))
	parallel(len(census), func(i int) {
		if results[i].state != "unread" {
			return
		}
		m := census[i]
		stats.HEADs.Add(1)
		got, err := cs.Head(headCtx, m.Identity)
		if err != nil {
			errs[i] = err
			return
		}
		if got.Size != m.Size || strings.Trim(got.ETag, "\"") != strings.Trim(m.ETag, "\"") || got.VersionID != m.VersionID {
			errs[i] = ErrArtifactChanged
		}
	})
	for _, err := range errs {
		if err != nil {
			return Facts{}, err
		}
	}
	commitments := map[string]MemberCommitment{}
	for id, d := range f.memberDigests {
		commitments[id] = MemberCommitment{"full", d}
	}
	raw := newCensusRaw(census)
	for i, r := range results {
		commitments[census[i].Identity] = r.commitment
		raw.add(census[i], r)
	}
	if len(census) > 0 {
		f.ContentCensus = raw.finish()
		if err := ValidateCensusCoverage(*f.ContentCensus, int64(len(census)), int64(len(plan))); err != nil {
			return Facts{}, err
		}
	}
	f.UnreadBindingSHA256 = UnreadBindingSHA256(members, plan)
	var err error
	f.ContentSHA256, err = ContentBindingV2(members, commitments)
	if err != nil {
		return Facts{}, err
	}
	f.LocatorCommitment = keyed(p.CommitmentKey, "gateway_listing\x00"+p.GatewayID+"\x00"+p.SnapshotHash)
	if p.Commitments != nil {
		f.LocatorCommitment = p.Commitments.LocatorCommitment()
	}
	if !hexASCII(f.LocatorCommitment) {
		return Facts{}, ErrUnsupported
	}
	payload := map[string]any{"coverage": f.Coverage, "objects": f.Objects, "schema_preview": preview(f.Objects), "content_census": f.ContentCensus}
	b, err := canonical(payload)
	if err != nil {
		return Facts{}, err
	}
	if len(b) > p.MaxFactBytes {
		return Facts{}, ErrSummaryBudget
	}
	b, err = canonical(map[string]any{"facts": payload, "binding_method": p.BindingMethod, "scan_mode": p.ScanMode})
	if err != nil {
		return Facts{}, err
	}
	h := sha256.Sum256(b)
	f.FingerprintHash = hexDigest(h)
	return f, nil
}
func readCensusMember(ctx context.Context, s CensusSource, m Member, p Policy, stats *RunStats) censusMemberResult {
	if ctx.Err() != nil {
		return unreadResult(m, "budget_exhausted")
	}
	switch archiveFormat(m) {
	case "zip":
		return readZip(ctx, s, m, p, stats)
	case "tar.gz":
		return readTarGzip(ctx, s, m, p, stats)
	}
	r := unreadResult(m, "read_error")
	r.findings.memory = p.censusMemory
	stats.GETs.Add(1)
	stats.RequestedBytes.Add(m.Size)
	stream, err := s.OpenRange(ctx, m.Identity, 0, m.Size)
	if err != nil {
		if ctx.Err() != nil {
			r.reason = "budget_exhausted"
		} else {
			r.unreadable = m.Size
		}
		return r
	}
	r.opened = true
	stop := context.AfterFunc(ctx, func() { stream.Close() })
	defer stop()
	defer stream.Close()
	scan := newFileInspection("." + m.Format)
	n, err := copyInspected(ctx, scan, io.LimitReader(&statsReader{stream, stats}, m.Size+1))
	r.processed = min(n, m.Size)
	if ctx.Err() != nil {
		r.reason = "budget_exhausted"
		return r
	}
	if err != nil || n != m.Size {
		r.unreadable = m.Size
		return r
	}
	digest := scan.digest()
	if m.DigestPresent && digest != m.SHA256 {
		r.reason = "read_error"
		r.unreadable = m.Size
		return r
	}
	r.commitment = MemberCommitment{"full", digest}
	r.state = "fully_read"
	r.reason = ""
	r.storedRead = m.Size
	r.readable = m.Size
	r.findings.addFile(scan.finish())
	return r
}
