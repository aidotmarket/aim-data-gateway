package verification

import (
	"fmt"
	"strings"
	"testing"
)

// Group by the entire disclosure, including exact receipt coverage. For each
// uncertain emitted licence band, demand two distinct values in its preimage.
func TestS3APreimagesActualLicencePatterns(t *testing.T) {
	samples := []string{"MIT License", "Apache License Version 2.0", "BSD-3-Clause", "GNU GENERAL PUBLIC LICENSE", "GNU LESSER GENERAL PUBLIC LICENSE", "GNU AFFERO GENERAL PUBLIC LICENSE", "Mozilla Public License", "CC-BY-4.0", "CC-BY-SA-4.0", "CC-BY-NC-4.0", "CC0", "Unlicense", "all rights reserved", "copyright"}
	for target, l := range licencePatterns {
		t.Run(l.family, func(t *testing.T) {
			if !l.pattern.MatchString(samples[target]) {
				t.Fatal("sample does not exercise actual pattern")
			}
			type image struct {
				counts map[string]map[int64]bool
				bands  map[string]string
			}
			groups := map[string]*image{}
			// The four actual match sets include containment, overlap and catch-all-only
			// texts. No synthetic assumption that a family implies the catch-all is used.
			texts := []string{samples[target], samples[target] + " copyright", "copyright", "neutral text"}
			if l.family == "mit" {
				texts[0] = "permission is hereby granted free of charge"
			}
			findings := make([]fileFinding, len(texts))
			for i, s := range texts {
				findings[i] = inspectChunks([]byte(s), "x.txt", 7)
				for _, p := range licencePatterns {
					if findings[i].licences[p.family] != p.pattern.MatchString(s) {
						t.Fatal("pattern/stream disagreement", p.family, s)
					}
				}
			}
			for n := int64(1); n <= 25; n++ {
				for f := int64(0); f <= n; f++ {
					for overlap := int64(0); overlap <= f; overlap++ {
						for unknown := int64(0); unknown <= n-f; unknown++ {
							r := newCensusRaw(nil)
							r.members = n
							r.fully = n
							r.stored = n * 1024
							r.storedRead = r.stored
							r.processed = r.stored
							counts := []int64{f - overlap, overlap, unknown, n - f - unknown}
							for i, count := range counts {
								for j := int64(0); j < count; j++ {
									r.inspected.addFile(findings[i])
								}
							}
							c := r.finish()
							raw, _ := canonical(c)
							key := string(raw)
							g := groups[key]
							if g == nil {
								g = &image{map[string]map[int64]bool{}, map[string]string{}}
								groups[key] = g
							}
							for _, finding := range c.Inspected.Licences {
								if finding.State != "checked" || finding.FilesBand == "0" {
									continue
								}
								name := finding.Family
								if g.counts[name] == nil {
									g.counts[name] = map[int64]bool{}
								}
								g.counts[name][r.inspected.licences[name]] = true
								g.bands[name] = finding.FilesBand
							}
						}
					}
				}
			}
			for _, g := range groups {
				for name, counts := range g.counts {
					if len(counts) < 2 {
						t.Fatalf("single preimage: target %s finding %s band %s values %v", l.family, name, g.bands[name], counts)
					}
				}
			}
		})
	}
}

// Content classes and archive interiors: enumerate the distributions, retaining
// fixed snapshot sizes and exact coverage. Exact cells and the 0 band are exempt.
func TestS3APreimagesContentAndArchives(t *testing.T) {
	classes := []string{"table_like_csv", "table_like_tsv", "table_like_jsonl", "source_code", "markdown", "html_xml", "pdf", "image", "other_binary"}
	type image struct{ entries, bytes map[int64]bool }
	for n := int64(1); n <= 25; n++ {
		for archives := int64(0); archives <= min(3, n); archives++ {
			groups := map[string]*image{}
			for a := int64(0); a <= n-archives; a++ {
				for b := int64(0); b <= n-archives-a; b++ {
					for entries := archives; entries <= archives*8; entries++ {
						for delta := int64(0); delta <= min(1, archives); delta++ {
							r := newCensusRaw(nil)
							r.members = n
							r.fully = n
							r.archives = archives
							r.opened = archives
							r.entries = entries
							r.entryBytes = entries*16 + delta
							r.stored = n * 4096
							r.storedRead = r.stored
							r.processed = (n - archives) * 4096
							r.inspected.init()
							r.inspected.files = n - archives
							r.inspected.classes = map[string]int64{"plain_text": a, "json_document": b, classes[(a+b)%int64(len(classes))]: n - archives - a - b}
							for k, v := range r.inspected.classes {
								if v == 0 {
									delete(r.inspected.classes, k)
									continue
								}
								encoding, script := "utf8", "latin"
								if k == "pdf" || k == "image" || k == "other_binary" {
									encoding, script = "binary", "non_text"
								}
								r.inspected.encodings[encoding] += v
								r.inspected.scripts[script] += v
							}
							c := r.finish()
							raw, _ := canonical(c)
							key := string(raw)
							g := groups[key]
							if g == nil {
								g = &image{map[int64]bool{}, map[int64]bool{}}
								groups[key] = g
							}
							g.entries[entries] = true
							g.bytes[r.entryBytes] = true
						}
					}
				}
			}
			if archives > 0 {
				for raw, g := range groups {
					if len(g.entries) < 2 || len(g.bytes) < 2 {
						t.Fatalf("archive singleton n=%d archives=%d %s: entries %v bytes %v", n, archives, fmt.Sprint(raw), g.entries, g.bytes)
					}
				}
			}
		}
	}
}

func TestS3APreimagesDetectorFilesAndMatches(t *testing.T) {
	samples := make([]fileFinding, 251)
	samples[0] = inspectChunks([]byte("neutral text"), "x.txt", 7)
	for hits := 1; hits < len(samples); hits++ {
		samples[hits] = inspectChunks([]byte(strings.Repeat("alice@example.org ", hits)), "x.txt", 7)
		if samples[hits].hits[0] != int64(hits) {
			t.Fatal("actual email pattern", hits, samples[hits].hits)
		}
	}
	type image struct {
		files, hits map[int64]bool
		checked     bool
	}
	for n := int64(1); n <= 25; n++ {
		groups := map[string]*image{}
		for files := int64(0); files <= n; files++ {
			start, end := files, int64(250)
			if files == 0 {
				end = 0
			}
			for hits := start; hits <= end; hits++ {
				r := newCensusRaw(nil)
				r.members = n
				r.fully = n
				r.stored = n * 65536
				r.storedRead = r.stored
				r.processed = r.stored
				for i := int64(0); i < n; i++ {
					sample := samples[0]
					if i < files {
						sample = samples[1]
						if i == 0 {
							sample = samples[hits-files+1]
						}
					}
					r.inspected.addFile(sample)
				}
				c := r.finish()
				raw, _ := canonical(c)
				g := groups[string(raw)]
				if g == nil {
					g = &image{map[int64]bool{}, map[int64]bool{}, c.Inspected.Detectors[0].State == "checked"}
					groups[string(raw)] = g
				}
				g.files[files] = true
				g.hits[hits] = true
			}
		}
		for _, g := range groups {
			if !g.checked || g.files[0] {
				continue
			}
			if len(g.files) < 2 || len(g.hits) < 2 {
				t.Fatalf("detector singleton P=%d files=%v hits=%v", n, g.files, g.hits)
			}
		}
	}
}
