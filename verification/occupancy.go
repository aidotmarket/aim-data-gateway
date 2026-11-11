package verification

import "sort"

type CensusCell struct {
	Class   string `json:"class"`
	Members any    `json:"members"`
}
type CensusPartition struct {
	State      string       `json:"state"`
	Population any          `json:"population"`
	Cells      []CensusCell `json:"cells,omitempty"`
}
type CensusFinding struct {
	Class             string `json:"class,omitempty"`
	PatternVersion    string `json:"pattern_version,omitempty"`
	Family            string `json:"family,omitempty"`
	Population        any    `json:"population"`
	State             string `json:"state"`
	FilesBand         string `json:"files_band,omitempty"`
	FilesWithHitsBand string `json:"files_with_hits_band,omitempty"`
	HitCountBand      string `json:"hit_count_band,omitempty"`
}
type CensusInventory struct {
	Members           any             `json:"members"`
	StoredBytes       any             `json:"stored_bytes"`
	ByExtensionClass  CensusPartition `json:"by_extension_class"`
	SizeBuckets       CensusPartition `json:"size_buckets"`
	ArchiveContainers any             `json:"archive_containers"`
}
type CensusCoverage struct {
	ReadState        CensusPartition `json:"read_state"`
	MembersTotal     any             `json:"members_total"`
	StoredBytesRead  any             `json:"stored_bytes_read"`
	StoredBytesTotal any             `json:"stored_bytes_total"`
	ProcessedBytes   any             `json:"processed_bytes"`
	Sampled          bool            `json:"sampled"`
	SampleMethod     string          `json:"sample_method"`
	UnreadByReason   CensusPartition `json:"unread_by_reason"`
	LimitedCoverage  bool            `json:"limited_coverage"`
}
type CensusInteriors struct {
	State                 string          `json:"state"`
	Population            any             `json:"population"`
	ArchivesOpened        any             `json:"archives_opened"`
	ArchivesPartiallyRead any             `json:"archives_partially_read"`
	EntriesRead           any             `json:"entries_read"`
	EntryProcessedBytes   any             `json:"entry_processed_bytes"`
	UnreadByReason        CensusPartition `json:"unread_by_reason"`
}
type CensusInspected struct {
	ByContentClass  CensusPartition `json:"by_content_class"`
	Detectors       []CensusFinding `json:"detectors"`
	Licences        []CensusFinding `json:"licences"`
	PlainFiles      int64           `json:"plain_files"`
	EmptyPlainFiles int64           `json:"empty_plain_files"`
	ArchiveEntries  any             `json:"archive_entries,omitempty"`
	Encodings       CensusPartition `json:"encodings"`
	Scripts         CensusPartition `json:"scripts"`
}
type ContentCensus struct {
	Method          string          `json:"method"`
	DepthClass      string          `json:"depth_class"`
	Inventory       CensusInventory `json:"inventory"`
	CoverageContent CensusCoverage  `json:"coverage_content"`
	Interiors       CensusInteriors `json:"interiors"`
	Inspected       CensusInspected `json:"inspected"`
}

func countBand(n int64) string {
	switch {
	case n == 0:
		return "0"
	case n < 10:
		return "1-9"
	case n < 100:
		return "10-99"
	case n < 1000:
		return "100-999"
	default:
		return "1000+"
	}
}
func sizeBucket(n int64) string {
	switch {
	case n == 0:
		return "0"
	case n < 1<<10:
		return "<1KB"
	case n < 10<<10:
		return "<10KB"
	case n < 100<<10:
		return "<100KB"
	case n < 1<<20:
		return "<1MB"
	case n < 10<<20:
		return "<10MB"
	case n < 100<<20:
		return "<100MB"
	default:
		return ">=100MB"
	}
}
func population(n int64) any {
	if n < 10 {
		return countBand(n)
	}
	return n
}
func findingState(n int64) string {
	if n == 0 {
		return "not_checked"
	}
	if n < 10 {
		return suppressed
	}
	return "checked"
}

// partition suppresses the entire partition when merging leaves only its total.
// It never publishes a small complement, including zero-only or singleton cells.
func partition(counts map[string]int64, pop int64) CensusPartition {
	out := CensusPartition{State: findingState(pop), Population: population(pop)}
	if pop < 10 {
		return out
	}
	cells := map[string]int64{}
	for k, n := range counts {
		if n > 0 {
			cells[k] = n
		}
	}
	var other int64
	for k, n := range cells {
		if n < 10 {
			other += n
			delete(cells, k)
		}
	}
	if other > 0 {
		for other < 10 && len(cells) > 0 {
			key := ""
			for k, n := range cells {
				if key == "" || n < cells[key] || n == cells[key] && k < key {
					key = k
				}
			}
			other += cells[key]
			delete(cells, key)
		}
		cells["other"] += other
	}
	if len(cells) <= 1 {
		out.State = suppressed
		return out
	}
	keys := make([]string, 0, len(cells))
	for k := range cells {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out.Cells = append(out.Cells, CensusCell{k, cells[k]})
	}
	return out
}
func lowMap(m map[string]int64) bool {
	for _, n := range m {
		if n > 0 && n < 10 {
			return true
		}
	}
	return false
}

type censusRaw struct {
	members, stored, archives, opened, partial, entries, entryBytes    int64
	fully, partly, unread, storedRead, processed, readable, unreadable int64
	extensions, sizes, reasons, interiorReasons                        map[string]int64
	inspected                                                          inspection
}

func newCensusRaw(ms []Member) *censusRaw {
	r := &censusRaw{extensions: map[string]int64{}, sizes: map[string]int64{}, reasons: map[string]int64{}, interiorReasons: map[string]int64{}}
	for _, m := range ms {
		r.members++
		r.stored += m.Size
		r.extensions[extensionClass(m.Format)]++
		r.sizes[sizeBucket(m.Size)]++
		if archiveFormat(m) != "" {
			r.archives++
		}
	}
	return r
}
func (r *censusRaw) add(m Member, x censusMemberResult) {
	switch x.state {
	case "fully_read":
		r.fully++
	case "partly_read":
		r.partly++
	default:
		r.unread++
	}
	if x.reason != "" {
		r.reasons[x.reason]++
	}
	if x.state == "fully_read" {
		r.storedRead += m.Size
	}
	if archiveFormat(m) == "" || x.plain {
		r.processed += x.processed
		r.inspected.merge(x.findings)
	}
	r.readable += x.readable
	r.unreadable += x.unreadable
	if archiveFormat(m) != "" && x.opened && !x.plain {
		r.opened++
		if x.state != "fully_read" {
			r.partial++
		}
		r.entries += x.entries
		r.entryBytes += x.entryBytes
	}
	for k, n := range x.reasons {
		r.interiorReasons[k] += n
	}
}

// exactPartition is receipt coverage; public projection applies its own merges.
func exactPartition(counts map[string]int64, pop int64) CensusPartition {
	out := CensusPartition{State: "checked", Population: pop}
	keys := make([]string, 0, len(counts))
	for k, n := range counts {
		if n > 0 {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		out.Cells = append(out.Cells, CensusCell{k, counts[k]})
	}
	return out
}
func fileCountBand(n, p int64) string {
	if p == 10 && n >= 1 && n <= 10 {
		return "1+"
	}
	if p == 100 && n >= 10 && n <= 100 {
		return "10+"
	}
	if p == 1000 && n >= 100 && n <= 1000 {
		return "100+"
	}
	return countBand(n)
}
func (r *censusRaw) finish() *ContentCensus {
	c := &ContentCensus{Method: ContentCensusV1, DepthClass: "content_census_complete_v1"}
	if r.fully != r.members {
		c.DepthClass = "content_census_sampled_v1"
	}
	states := exactPartition(map[string]int64{"fully_read": r.fully, "partly_read": r.partly, "unread": r.unread}, r.members)
	c.Inventory = CensusInventory{r.members, r.stored, partition(r.extensions, r.members), partition(r.sizes, r.members), r.archives}
	c.CoverageContent = CensusCoverage{states, r.members, r.storedRead, r.stored, r.processed, r.fully != r.members, "hmac_seed_byte_budget_v1", exactPartition(r.reasons, r.members), r.unreadable > 0 && r.readable < (r.readable+r.unreadable+9)/10}
	c.Interiors = CensusInteriors{findingState(r.opened), r.opened, r.opened, r.partial, countBand(r.entries), sizeBucket(r.entryBytes), partition(r.interiorReasons, r.opened)}
	if r.opened < 10 || lowMap(r.interiorReasons) {
		c.Interiors.UnreadByReason = CensusPartition{State: suppressed, Population: r.opened}
	} else {
		c.Interiors.UnreadByReason = exactPartition(r.interiorReasons, r.opened)
	}
	a := r.inspected
	a.init()
	n := a.files - a.empty
	c.Inspected.PlainFiles, c.Inspected.EmptyPlainFiles = a.files, a.empty
	if r.opened > 0 {
		c.Inspected.ArchiveEntries = countBand(r.entries)
	}
	c.Inspected.ByContentClass = partition(a.classes, n)
	c.Inspected.Encodings = partition(a.encodings, n)
	c.Inspected.Scripts = partition(a.scripts, n)
	cross := !lowMap(a.classes) && !lowMap(a.encodings) && !lowMap(a.scripts)
	if !cross || r.opened > 0 {
		c.Inspected.Encodings = CensusPartition{State: suppressed, Population: n}
		c.Inspected.Scripts = c.Inspected.Encodings
	}
	if r.opened > 0 {
		c.Inspected.ByContentClass = CensusPartition{State: suppressed, Population: n}
	}
	state := "checked"
	if n < 10 {
		state = suppressed
	}
	for i, name := range []string{"email", "phone", "credential_like"} {
		f := CensusFinding{Class: name, PatternVersion: patternVersions[i], Population: n, State: state}
		if n >= 10 {
			f.FilesWithHitsBand = fileCountBand(a.hitFiles[i], n)
			f.HitCountBand = countBand(a.hits[i])
		}
		c.Inspected.Detectors = append(c.Inspected.Detectors, f)
	}
	for _, l := range licencePatterns {
		f := CensusFinding{Family: l.family, Population: n, State: state}
		if n >= 10 {
			f.FilesBand = fileCountBand(a.licences[l.family], n)
		}
		c.Inspected.Licences = append(c.Inspected.Licences, f)
	}
	return c
}
