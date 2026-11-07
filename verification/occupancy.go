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
	Count             any    `json:"count,omitempty"`
}
type CensusDuplicates struct {
	ExactRatePPM any    `json:"exact_rate_ppm,omitempty"`
	NearRatePPM  any    `json:"near_rate_ppm,omitempty"`
	NearState    string `json:"near_state"`
	Definition   string `json:"definition"`
	Population   any    `json:"population"`
	State        string `json:"state"`
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
	ByContentClass CensusPartition  `json:"by_content_class"`
	Detectors      []CensusFinding  `json:"detectors"`
	Licences       []CensusFinding  `json:"licences"`
	Duplicates     CensusDuplicates `json:"duplicates"`
	Encodings      CensusPartition  `json:"encodings"`
	Scripts        CensusPartition  `json:"scripts"`
	EmptyFiles     CensusFinding    `json:"empty_files"`
	GarbageFiles   CensusFinding    `json:"garbage_files"`
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
func partCount(part, whole int64) any {
	if part >= 10 && whole-part >= 10 {
		return part
	}
	return countBand(part)
}
func byteCount(n, pop int64, exact bool) any {
	if pop >= 10 && exact {
		return n
	}
	return sizeBucket(n)
}

// partition suppresses the entire partition when merging leaves only its total.
// It never publishes a small complement, including zero-only or singleton cells.
func partition(counts map[string]int64, pop int64, readState bool) CensusPartition {
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
	if readState {
		// The combined read label is always other. Any small cell forces the fixed
		// partly -> fully -> unread order, preventing 10+10+1 reconstruction.
		if lowMap(cells) {
			n := cells["fully_read"] + cells["partly_read"]
			delete(cells, "fully_read")
			delete(cells, "partly_read")
			cells["other"] = n
			if cells["unread"] < 10 || n < 10 {
				cells["other"] += cells["unread"]
				delete(cells, "unread")
			}
		}
	} else {
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
	r.storedRead += x.storedRead
	r.processed += x.processed
	r.readable += x.readable
	r.unreadable += x.unreadable
	r.inspected.merge(x.findings)
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
func duplicateRate[K comparable](counts map[K]int64, n int64) int64 {
	var repeated int64
	for _, v := range counts {
		if v > 1 {
			repeated += v - 1
		}
	}
	if n == 0 {
		return 0
	}
	return rateUnits(repeated, n)
}
func (r *censusRaw) finish() *ContentCensus {
	c := &ContentCensus{Method: ContentCensusV1, DepthClass: "content_census_complete_v1"}
	if r.fully != r.members {
		c.DepthClass = "content_census_sampled_v1"
	}
	states := partition(map[string]int64{"fully_read": r.fully, "partly_read": r.partly, "unread": r.unread}, r.members, true)
	exact := states.State == "checked" && r.fully+r.partly >= 10 && r.unread >= 10
	c.Inventory = CensusInventory{population(r.members), byteCount(r.stored, r.members, true), partition(r.extensions, r.members, false), partition(r.sizes, r.members, false), partCount(r.archives, r.members)}
	c.CoverageContent = CensusCoverage{states, population(r.members), byteCount(r.storedRead, r.fully+r.partly, exact), byteCount(r.stored, r.members, exact), byteCount(r.processed, r.fully+r.partly, exact), r.fully != r.members, "hmac_seed_byte_budget_v1", partition(r.reasons, r.members, false), r.unreadable > 0 && r.readable < (r.readable+r.unreadable+9)/10}
	// Interior totals share contributing archives. Bands and size buckets avoid
	// inferring a single archive's entries through cross-partition subtraction.
	interiorState := findingState(r.opened)
	c.Interiors = CensusInteriors{interiorState, population(r.opened), partCount(r.opened, r.archives), partCount(r.partial, r.opened), countBand(r.entries), sizeBucket(r.entryBytes), partition(r.interiorReasons, r.opened, false)}
	if r.opened < 10 {
		c.Interiors.ArchivesOpened = nil
		c.Interiors.ArchivesPartiallyRead = nil
		c.Interiors.EntriesRead = nil
		c.Interiors.EntryProcessedBytes = nil
		c.Interiors.UnreadByReason = CensusPartition{State: interiorState, Population: population(r.opened)}
	}
	a := r.inspected
	a.init()
	n := a.files
	c.Inspected.ByContentClass = partition(a.classes, n, false)
	for i, name := range []string{"email", "phone", "credential_like"} {
		f := CensusFinding{Class: name, PatternVersion: patternVersions[i], Population: population(n), State: findingState(n)}
		if n >= 10 {
			f.FilesWithHitsBand = countBand(a.hitFiles[i])
			f.HitCountBand = countBand(a.hits[i])
		}
		c.Inspected.Detectors = append(c.Inspected.Detectors, f)
	}
	for _, l := range licencePatterns {
		f := CensusFinding{Family: l.family, Population: population(n), State: findingState(n)}
		if n >= 10 {
			f.FilesBand = countBand(a.licences[l.family])
		}
		c.Inspected.Licences = append(c.Inspected.Licences, f)
	}
	c.Inspected.Duplicates = CensusDuplicates{Definition: "sha256_exact_and_simhash64_5shingle_v1_ge_256_bytes_among_inspected_files", Population: population(n), State: findingState(n)}
	if n >= 10 {
		c.Inspected.Duplicates.ExactRatePPM = duplicateRate(a.exact, n)
		if a.nearFiles >= 10 {
			c.Inspected.Duplicates.NearRatePPM = duplicateRate(a.near, n)
		}
	}
	c.Inspected.Duplicates.NearState = findingState(a.nearFiles)
	c.Inspected.Encodings = partition(a.encodings, n, false)
	var text int64
	for _, v := range a.scripts {
		text += v
	}
	c.Inspected.Scripts = partition(a.scripts, text, false)
	c.Inspected.EmptyFiles = CensusFinding{Population: population(n), State: findingState(n)}
	c.Inspected.GarbageFiles = c.Inspected.EmptyFiles
	if n >= 10 {
		c.Inspected.EmptyFiles.Count = countBand(a.empty)
		c.Inspected.GarbageFiles.Count = countBand(a.garbage)
	}
	if r.opened > 0 && r.opened < 10 {
		suppressInspected(&c.Inspected, a.files)
	}
	return c
}
func suppressInspected(s *CensusInspected, n int64) {
	pop := countBand(n)
	s.ByContentClass = CensusPartition{State: suppressed, Population: pop}
	s.Encodings = s.ByContentClass
	s.Scripts = s.ByContentClass
	for i := range s.Detectors {
		s.Detectors[i].State = suppressed
		s.Detectors[i].Population = pop
		s.Detectors[i].FilesWithHitsBand = ""
		s.Detectors[i].HitCountBand = ""
	}
	for i := range s.Licences {
		s.Licences[i].State = suppressed
		s.Licences[i].Population = pop
		s.Licences[i].FilesBand = ""
	}
	s.Duplicates.State = suppressed
	s.Duplicates.Population = pop
	s.Duplicates.ExactRatePPM = nil
	s.Duplicates.NearRatePPM = nil
	s.Duplicates.NearState = suppressed
	s.EmptyFiles = CensusFinding{State: suppressed, Population: pop}
	s.GarbageFiles = s.EmptyFiles
}
