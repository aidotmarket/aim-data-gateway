package awsverification

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"io"
	"math"
	"sort"
	"sync"

	"github.com/aidotmarket/aim-data-gateway/internal/inventory"
	core "github.com/aidotmarket/aim-data-gateway/verification"
)

func tableFormat(f string) bool { return f == "csv" || f == "tsv" || f == "jsonl" || f == "parquet" }

type tableSource struct {
	*Source
	members []core.Member
}

func (s tableSource) Members() []core.Member { return s.members }

type probeResult struct {
	core.ProbeResult
	CensusPreflight *censusPreflight
}

// censusPreflight is the closed, aggregate-only free-check wire contract.
type censusPreflight struct {
	KnownProcessedBytes         int64 `json:"known_processed_bytes"`
	KnownReadableStoredBytes    int64 `json:"known_readable_stored_bytes"`
	UnknownExpansionContainers  int64 `json:"unknown_expansion_containers"`
	UnknownExpansionStoredBytes int64 `json:"unknown_expansion_stored_bytes"`
	ZipEntries                  int64 `json:"zip_entries"`
	ArchiveGetRequests          int64 `json:"archive_get_requests"`
}
type preflightMember struct {
	censusPreflight
	err error
}

// Census members never enter core.Probe: it intentionally scans its whole source.
func probe(ctx context.Context, src *Source, p core.Policy) (out probeResult, err error) {
	if p.ScanMode != core.ContentCensusV1 {
		out.ProbeResult, err = core.Probe(ctx, src, p)
		return
	}
	tables, census := []core.Member{}, []core.Member{}
	for _, m := range src.Members() {
		if tableFormat(m.Format) {
			tables = append(tables, m)
		} else {
			census = append(census, m)
		}
	}
	if len(tables) > 0 {
		tablePolicy := p
		tablePolicy.ScanMode, tablePolicy.BindingMethod = "table_v1", "full_sha256_v1"
		out.ProbeResult, err = core.Probe(ctx, tableSource{src, tables}, tablePolicy)
		if err != nil {
			return
		}
	} else {
		out.EstimatedMaxInputTokens = 171
	}
	if len(census) == 0 {
		return out, ctx.Err()
	}
	out.CensusPreflight = &censusPreflight{}
	results := make([]preflightMember, len(census))
	var wg sync.WaitGroup
	jobs := make(chan int)
	for worker := 0; worker < min(16, len(census)); worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				results[i] = preflight(ctx, src, census[i], p)
			}
		}()
	}
	for i := range census {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	var total int64
	for i, r := range results {
		if r.err != nil {
			return out, r.err
		}
		if census[i].Size > math.MaxInt64-total {
			return out, core.ErrResourceLimit
		}
		total += census[i].Size
		sums := []*int64{&out.CensusPreflight.KnownProcessedBytes, &out.CensusPreflight.KnownReadableStoredBytes, &out.CensusPreflight.UnknownExpansionContainers, &out.CensusPreflight.UnknownExpansionStoredBytes, &out.CensusPreflight.ZipEntries, &out.CensusPreflight.ArchiveGetRequests}
		values := []int64{r.KnownProcessedBytes, r.KnownReadableStoredBytes, r.UnknownExpansionContainers, r.UnknownExpansionStoredBytes, r.ZipEntries, r.ArchiveGetRequests}
		for j, n := range values {
			if n > math.MaxInt64-*sums[j] {
				return out, core.ErrResourceLimit
			}
			*sums[j] += n
		}
	}
	if total > 0 && out.CensusPreflight.KnownReadableStoredBytes+out.CensusPreflight.UnknownExpansionStoredBytes < total/10+boolInt(total%10 != 0) {
		return out, core.ErrInsufficientReadableContent
	}
	out.EstimatedMaxInputTokens += core.CensusAdvisoryTokens
	return out, ctx.Err()
}
func boolInt(v bool) int64 {
	if v {
		return 1
	}
	return 0
}
func preflight(ctx context.Context, src *Source, m core.Member, p core.Policy) preflightMember {
	kind := inventory.ArchiveFormat(m.Format)
	if kind == "" {
		return preflightMember{censusPreflight: censusPreflight{KnownProcessedBytes: m.Size, KnownReadableStoredBytes: m.Size}}
	}
	n, off := min(m.Size, int64(64<<10)), int64(0)
	if kind == "zip" {
		n = min(m.Size, int64(1<<20))
		off = m.Size - n
	}
	if n == 0 {
		return preflightMember{censusPreflight: censusPreflight{ArchiveGetRequests: 1}}
	}
	r, err := src.OpenRange(ctx, m.Identity, off, n)
	if err != nil {
		return preflightMember{err: err}
	}
	defer r.Close()
	stop := context.AfterFunc(ctx, func() { r.Close() })
	defer stop()
	b, err := io.ReadAll(io.LimitReader(r, n+1))
	if err != nil {
		return preflightMember{err: err}
	}
	if int64(len(b)) != n {
		return preflightMember{err: core.ErrArtifactChanged}
	}
	if kind == "zip" {
		z := core.PreflightZip(b, m.Size, p)
		if z.Reason != "" {
			// Even an unopened/over-cap ZIP contributes its directory count, when
			// the bounded tail contains an end record, and its planned tail GET.
			out := preflightMember{censusPreflight: censusPreflight{ArchiveGetRequests: 1}}
			for i := len(b) - 22; i >= max(0, len(b)-65557); i-- {
				if bytes.Equal(b[i:i+4], []byte("PK\x05\x06")) && i+22+int(binary.LittleEndian.Uint16(b[i+20:])) == len(b) {
					out.ZipEntries = min(int64(binary.LittleEndian.Uint16(b[i+10:])), 10001)
					break
				}
			}
			return out
		}
		return zipPreflight(z, b, m.Size, p)
	}
	// Only decode enough to validate the first tar header; expansion stays unknown.
	g, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return preflightMember{censusPreflight: censusPreflight{ArchiveGetRequests: 1}}
	}
	defer g.Close()
	var header [512]byte
	if _, err = io.ReadFull(g, header[:]); err != nil || !inventory.IsTarHeader(header[:]) {
		return preflightMember{censusPreflight: censusPreflight{ArchiveGetRequests: 1}}
	}
	return preflightMember{censusPreflight: censusPreflight{UnknownExpansionContainers: 1, UnknownExpansionStoredBytes: m.Size, ArchiveGetRequests: 1}}
}

// Mirror C1 planZip using the already validated directory; no member data is read.
// q counts selected, valid, unencrypted Store/Deflate extents. d counts the
// optional full-hash prefix GET, decided at plan time (never from actual GETs).
func zipPreflight(z core.ZipPreflight, tail []byte, size int64, p core.Policy) (out preflightMember) {
	out.ZipEntries, out.ArchiveGetRequests = int64(min(len(z.Reader.File), 10001)), 1
	offsets := make([]int64, len(z.Reader.File))
	bounds := make([]int64, len(offsets))
	valid := make([]bool, len(offsets))
	cd := tail[z.CDOffset-(size-int64(len(tail))):]
	order := make([]int, 0, len(offsets))
	var compressed uint64
	selected := 0
	stopped := false
	for i, f := range z.Reader.File {
		offsets[i] = int64(binary.LittleEndian.Uint32(cd[42:]))
		cd = cd[46+int(binary.LittleEndian.Uint16(cd[28:]))+int(binary.LittleEndian.Uint16(cd[30:]))+int(binary.LittleEndian.Uint16(cd[32:])):]
		bounds[i], valid[i] = z.CDOffset, offsets[i] <= z.CDOffset-30
		if valid[i] {
			order = append(order, i)
		}
		compressed += f.CompressedSize64
		if stopped {
			continue
		}
		if i >= p.ArchiveCaps.Entries || f.UncompressedSize64 > uint64(p.ArchiveAllowanceBytes-out.KnownProcessedBytes) {
			stopped = true
			continue
		}
		selected++
		out.KnownProcessedBytes += int64(f.UncompressedSize64)
	}
	sort.Slice(order, func(i, j int) bool { return offsets[order[i]] < offsets[order[j]] })
	for j, i := range order {
		if j+1 < len(order) {
			bounds[i] = offsets[order[j+1]]
		}
		if bounds[i]-offsets[i] < 30 || z.Reader.File[i].CompressedSize64 > uint64(max(0, bounds[i]-offsets[i]-30)) {
			valid[i] = false
			if j+1 < len(order) {
				valid[order[j+1]] = false
			}
		}
	}
	complete, first := selected == len(offsets), z.CDOffset
	for i, f := range z.Reader.File {
		first = min(first, offsets[i])
		if !valid[i] || f.Flags&1 != 0 || f.Method != 0 && f.Method != 8 {
			complete = false
			continue
		}
		if i < selected {
			out.KnownReadableStoredBytes += int64(min(f.CompressedSize64, uint64(size-out.KnownReadableStoredBytes)))
			out.ArchiveGetRequests++
		}
	}
	if complete && z.CDOffset-int64(compressed) <= p.ArchiveAllowanceBytes && first > 0 {
		out.ArchiveGetRequests++
	}
	return
}
