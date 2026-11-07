package awsverification

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"math"
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
	KnownProcessedBytes        int64
	UnknownExpansionContainers int
}
type preflightMember struct {
	known, readable, unknown int64
	err                      error
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
	var total, readable, unknown int64
	for i, r := range results {
		if r.err != nil {
			return out, r.err
		}
		if census[i].Size > math.MaxInt64-total || r.known > math.MaxInt64-out.KnownProcessedBytes {
			return out, core.ErrResourceLimit
		}
		total += census[i].Size
		readable += r.readable
		unknown += r.unknown
		out.KnownProcessedBytes += r.known
		if r.unknown > 0 {
			out.UnknownExpansionContainers++
		}
	}
	if total > 0 && readable+unknown < total/10+boolInt(total%10 != 0) {
		return out, core.ErrInsufficientReadableContent
	}
	if len(census) > 0 {
		out.EstimatedMaxInputTokens += core.CensusAdvisoryTokens
	}
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
		return preflightMember{known: m.Size, readable: m.Size}
	}
	n, off := min(m.Size, int64(64<<10)), int64(0)
	if kind == "zip" {
		n = min(m.Size, int64(1<<20))
		off = m.Size - n
	}
	if n == 0 {
		return preflightMember{}
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
			return preflightMember{}
		}
		var expanded, readable uint64
		for _, f := range z.Reader.File {
			if f.UncompressedSize64 > math.MaxInt64-expanded {
				return preflightMember{err: core.ErrResourceLimit}
			}
			expanded += f.UncompressedSize64
			if f.Flags&1 == 0 && (f.Method == 0 || f.Method == 8) {
				readable += min(f.CompressedSize64, uint64(m.Size)-min(readable, uint64(m.Size)))
			}
		}
		return preflightMember{known: int64(expanded), readable: int64(readable)}
	}
	// Only decode enough to validate the first tar header; expansion stays unknown.
	g, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return preflightMember{}
	}
	defer g.Close()
	var header [512]byte
	if _, err = io.ReadFull(g, header[:]); err != nil || !inventory.IsTarHeader(header[:]) {
		return preflightMember{}
	}
	return preflightMember{unknown: m.Size}
}
