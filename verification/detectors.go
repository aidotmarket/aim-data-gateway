package verification

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"io"
	"math"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// Patterns are bounded so a 2 KiB look-behind is enough across arbitrary reads.
// The TLD and token-prefix lists are deliberately frozen by patternVersions.
var emailPattern = regexp.MustCompile(`(?i)[a-z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]{1,64}@[a-z0-9][a-z0-9.-]{0,180}\.(com|org|net|edu|gov|mil|io|ai|co|uk|de|fr|es|info|biz|dev|app|me)\b`)
var phonePattern = regexp.MustCompile(`\+?[0-9][0-9 ().-]{6,40}[0-9]`)
var excludedPhoneLine = regexp.MustCompile(`(?i)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|\b[0-9]{4}-[0-9]{2}-[0-9]{2}[T ]|\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|\b0x[0-9a-f]+\b)`)
var credentialPattern = regexp.MustCompile(`(?:\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----|\b(?:ghp_|github_pat_|sk_live_|sk_test_|sk-proj-|xoxb-|xoxp-|glpat-)[A-Za-z0-9_-]{16,200}|(?i:\b(?:key|secret|token|password)\b)[ \t]{0,16}[=:][ \t"']{0,16}[A-Za-z0-9_+/=-]{20,200})`)
var licencePatterns = []struct {
	family  string
	pattern *regexp.Regexp
	hints   []string
}{
	{"mit", regexp.MustCompile(`(?i)permission is hereby granted,? free of charge|\bMIT License\b`), []string{"permission", "mit license"}},
	{"apache_2", regexp.MustCompile(`(?i)Apache License[ ,\r\n]+(?:Version )?2\.0|SPDX-License-Identifier: Apache-2\.0`), []string{"apache"}},
	{"bsd", regexp.MustCompile(`(?i)redistribution and use in source and binary forms|\bBSD-[23]-Clause\b`), []string{"redistribution", "bsd-"}},
	{"gpl", regexp.MustCompile(`(?i)GNU GENERAL PUBLIC LICENSE|SPDX-License-Identifier: GPL-`), []string{"gnu general", "spdx-license-identifier: gpl-"}},
	{"lgpl", regexp.MustCompile(`(?i)GNU LESSER GENERAL PUBLIC LICENSE|SPDX-License-Identifier: LGPL-`), []string{"gnu lesser", "spdx-license-identifier: lgpl-"}},
	{"agpl", regexp.MustCompile(`(?i)GNU AFFERO GENERAL PUBLIC LICENSE|SPDX-License-Identifier: AGPL-`), []string{"gnu affero", "spdx-license-identifier: agpl-"}},
	{"mpl", regexp.MustCompile(`(?i)Mozilla Public License|SPDX-License-Identifier: MPL-`), []string{"mozilla", "spdx-license-identifier: mpl-"}},
	{"cc_by", regexp.MustCompile(`(?i)\bCC-BY-[1-4]|Creative Commons Attribution [1-4]`), []string{"cc-by-", "creative commons attribution"}},
	{"cc_by_sa", regexp.MustCompile(`(?i)CC-BY-SA|Attribution-ShareAlike`), []string{"cc-by-sa", "attribution-sharealike"}},
	{"cc_by_nc", regexp.MustCompile(`(?i)CC-BY-NC|Attribution-NonCommercial`), []string{"cc-by-nc", "attribution-noncommercial"}},
	{"cc0", regexp.MustCompile(`(?i)\bCC0\b`), []string{"cc0"}},
	{"unlicense", regexp.MustCompile(`(?i)\bUnlicense\b|free and unencumbered software released into the public domain`), []string{"unlicense", "free and unencumbered"}},
	{"proprietary_notice", regexp.MustCompile(`(?i)all rights reserved|confidential and proprietary`), []string{"all rights reserved", "confidential and proprietary"}},
	{"unknown_licence_text", regexp.MustCompile(`(?i)\blicen[cs]e\b|\bcopyright\b`), []string{"licen", "copyright"}},
}

func hexDigest(h [32]byte) string { return hex.EncodeToString(h[:]) }

type fileFinding struct {
	class, encoding, script string
	size                    int64
	hits                    [3]int64
	licences                map[string]bool
}
type fileInspection struct {
	textSize                         int64
	decided, wideUTF16, littleEndian bool
	start, wideTail                  []byte
	highSurrogate                    uint16

	phoneTail                             []byte
	phoneLineSize, phoneEnd, phonePending int64
	phoneExcluded                         bool

	name             string
	h                hash.Hash
	size, patternEnd int64
	prefix, tail     []byte
	utfTail          []byte
	scripts          [5]int64
	hits             [3]int64
	licences         map[string]bool
}

func newFileInspection(name string) *fileInspection {
	return &fileInspection{name: name, h: sha256.New(), licences: map[string]bool{}}
}
func (f *fileInspection) digest() [32]byte { return [32]byte(f.h.Sum(nil)) }
func hexByte(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F'
}
func alpha(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_'
}
func entropy(s string) float64 {
	var counts [256]int
	for i := range s {
		counts[s[i]]++
	}
	var h float64
	for _, n := range counts {
		if n > 0 {
			p := float64(n) / float64(len(s))
			h -= p * math.Log2(p)
		}
	}
	return h
}
func (f *fileInspection) patterns(b []byte, old, limit int) {
	// Normalise Unicode case folding for necessary-literal prefilters only.
	lower := strings.ReplaceAll(strings.ToLower(string(b)), "ſ", "s")
	for _, k := range []int{0, 2} {
		var locations [][]int
		if k == 0 {
			locations = emailLocations(b)
		} else {
			for _, hint := range []string{"akia", "asia", "-----begin ", "ghp_", "github_pat_", "sk_live_", "sk_test_", "sk-proj-", "xoxb-", "xoxp-", "glpat-", "key", "secret", "token", "password"} {
				if strings.Contains(lower, hint) {
					locations = credentialPattern.FindAllIndex(b, -1)
					break
				}
			}
		}
		for _, loc := range locations {
			a, z := loc[0], loc[1]
			if z <= old || z > limit || a > 0 && alpha(b[a-1]) || z < len(b) && alpha(b[z]) {
				continue
			}
			s := string(b[a:z])
			if k == 2 && strings.ContainsAny(s, "=:") {
				_, v, ok := strings.Cut(s, "=")
				if !ok {
					_, v, _ = strings.Cut(s, ":")
				}
				if entropy(strings.Trim(v, " \t\"'")) < 3.5 {
					continue
				}
			}
			f.hits[k]++
		}
	}
	for _, v := range licencePatterns {
		if f.licences[v.family] {
			continue
		}
		for _, hint := range v.hints {
			if strings.Contains(lower, hint) {
				if v.pattern.Match(b) {
					f.licences[v.family] = true
				}
				break
			}
		}
	}
}

func (f *fileInspection) Write(b []byte) (int, error) {
	n := len(b)
	f.h.Write(b)
	f.size += int64(n)
	if len(f.prefix) < 4096 {
		f.prefix = append(f.prefix, b[:min(len(b), 4096-len(f.prefix))]...)
	}
	if !f.decided {
		take := min(2-len(f.start), len(b))
		f.start = append(f.start, b[:take]...)
		b = b[take:]
		if len(f.start) < 2 {
			return n, nil
		}
		f.decided = true
		f.wideUTF16 = bytes.Equal(f.start, []byte{0xff, 0xfe}) || bytes.Equal(f.start, []byte{0xfe, 0xff})
		f.littleEndian = f.start[0] == 0xff
		if !f.wideUTF16 {
			f.writeText(f.start)
		}
		f.start = nil
	}
	if f.wideUTF16 {
		f.writeWide(b)
	} else {
		f.writeText(b)
	}
	return n, nil
}
func (f *fileInspection) writeWide(b []byte) {
	b = append(append([]byte(nil), f.wideTail...), b...)
	f.wideTail = nil
	var text []byte
	for len(b) >= 2 {
		v := binary.BigEndian.Uint16(b)
		if f.littleEndian {
			v = binary.LittleEndian.Uint16(b)
		}
		b = b[2:]
		if f.highSurrogate != 0 {
			r := utf16.DecodeRune(rune(f.highSurrogate), rune(v))
			text = utf8.AppendRune(text, r)
			f.highSurrogate = 0
			if r != unicode.ReplacementChar {
				continue
			}
		}
		if v >= 0xd800 && v <= 0xdbff {
			f.highSurrogate = v
			continue
		}
		text = utf8.AppendRune(text, rune(v))
	}
	f.wideTail = append(f.wideTail, b...)
	f.writeText(text)
}
func (f *fileInspection) writeText(b []byte) {
	f.textSize += int64(len(b))
	f.feedPhone(b, false)
	// Delay the last 1024 bytes to avoid accepting a match before its right boundary
	// has arrived. This also makes short-read segmentation irrelevant.
	joined := append(append([]byte(nil), f.tail...), b...)
	offset := f.textSize - int64(len(joined))
	if len(joined) >= 4096 {
		cut := len(joined) - 1024
		f.patterns(joined, int(f.patternEnd-offset), cut)
		f.patternEnd = offset + int64(cut)
		f.tail = append(f.tail[:0], joined[len(joined)-2048:]...)
	} else {
		f.tail = joined
	}
	runes := append(append([]byte(nil), f.utfTail...), b...)
	f.utfTail = nil
	for len(runes) > 0 {
		if !utf8.FullRune(runes) {
			f.utfTail = append(f.utfTail, runes...)
			break
		}
		r, n := utf8.DecodeRune(runes)
		runes = runes[n:]
		if unicode.IsLetter(r) {
			i := 4
			switch {
			case unicode.In(r, unicode.Latin):
				i = 0
			case unicode.In(r, unicode.Cyrillic):
				i = 1
			case unicode.In(r, unicode.Han, unicode.Hiragana, unicode.Katakana, unicode.Hangul):
				i = 2
			case unicode.In(r, unicode.Arabic):
				i = 3
			}
			f.scripts[i]++
		}
	}
}
func (f *fileInspection) finish() fileFinding {
	if !f.decided {
		f.writeText(f.start)
		f.start = nil
		f.decided = true
	}
	if f.highSurrogate != 0 || len(f.wideTail) > 0 {
		f.writeText([]byte("�"))
		f.highSurrogate = 0
		f.wideTail = nil
	}
	f.feedPhone(nil, true)
	f.patterns(f.tail, int(f.patternEnd-(f.textSize-int64(len(f.tail)))), len(f.tail))
	d := detectContent(f.prefix, f.name)
	encoding := "utf8"
	switch {
	case len(f.prefix) >= 2 && (f.prefix[0] == 0xff && f.prefix[1] == 0xfe || f.prefix[0] == 0xfe && f.prefix[1] == 0xff):
		encoding = "utf16"
	case strings.HasPrefix(string(f.prefix), "\ufeff"):
		encoding = "utf8_bom"
	case d.Class == "other_binary" || d.Class == "image" || d.Class == "pdf":
		encoding = "binary"
	case !utf8.Valid(f.prefix):
		encoding = "latin1_like"
	}
	script := "non_text"
	if encoding != "binary" {
		script = "other"
		i := 0
		for j := range f.scripts {
			if f.scripts[j] > f.scripts[i] {
				i = j
			}
		}
		if f.scripts[i] > 0 {
			script = []string{"latin", "cyrillic", "cjk", "arabic", "other"}[i]
		}
	}
	return fileFinding{d.Class, encoding, script, f.size, f.hits, f.licences}
}
func copyInspected(ctx context.Context, w io.Writer, r io.Reader) (int64, error) {
	var total int64
	buf := make([]byte, 64<<10)
	for {
		if ctx.Err() != nil {
			return total, ctx.Err()
		}
		n, e := r.Read(buf)
		if n > 0 {
			if _, err := w.Write(buf[:n]); err != nil {
				return total, err
			}
			total += int64(n)
		}
		if e == io.EOF {
			return total, nil
		}
		if e != nil {
			return total, e
		}
		if n == 0 {
			return total, io.ErrNoProgress
		}
	}
}

type inspection struct {
	files, empty                          int64
	classes, encodings, scripts, licences map[string]int64
	hits, hitFiles                        [3]int64
}

func (a *inspection) init() {
	if a.classes != nil {
		return
	}
	a.classes = map[string]int64{}
	a.encodings = map[string]int64{}
	a.scripts = map[string]int64{}
	a.licences = map[string]int64{}
}
func (a *inspection) addFile(f fileFinding) {
	a.init()
	a.files++
	if f.size == 0 {
		a.empty++
		return
	}
	a.classes[f.class]++
	a.encodings[f.encoding]++
	a.scripts[f.script]++
	for k, n := range f.hits {
		a.hits[k] += n
		if n > 0 {
			a.hitFiles[k]++
		}
	}
	for k := range f.licences {
		a.licences[k]++
	}
}
func (a *inspection) merge(b inspection) {
	a.init()
	a.files += b.files
	a.empty += b.empty
	for _, pair := range []struct{ dst, src map[string]int64 }{{a.classes, b.classes}, {a.encodings, b.encodings}, {a.scripts, b.scripts}, {a.licences, b.licences}} {
		for k, v := range pair.src {
			pair.dst[k] += v
		}
	}
	for k := range a.hits {
		a.hits[k] += b.hits[k]
		a.hitFiles[k] += b.hitFiles[k]
	}
}

// feedPhone retains a bounded suffix and counters, never an unbounded line.
// Exclusion evidence anywhere on a line invalidates all its phone candidates.
func (f *fileInspection) feedPhone(b []byte, final bool) {
	for len(b) > 0 || final {
		part := b
		end := final
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			part = b[:i]
			b = b[i+1:]
			end = true
		} else {
			b = nil
		}
		joined := append(append([]byte(nil), f.phoneTail...), part...)
		offset := f.phoneLineSize - int64(len(f.phoneTail))
		f.phoneLineSize += int64(len(part))
		exclusionEnd := len(joined)
		for exclusionEnd > 0 && !hexByte(joined[exclusionEnd-1]) {
			exclusionEnd--
		}
		// Keep one following byte for word-boundary assertions. No exclusion
		// can end past the last hex digit, and no phone past the last digit.
		if !f.phoneExcluded && excludedPhoneLine.Match(joined[:min(len(joined), exclusionEnd+1)]) {
			f.phoneExcluded = true
		}
		limit := len(joined)
		if !end {
			limit = max(0, limit-64)
		}
		phoneEnd := len(joined)
		for phoneEnd > 0 && (joined[phoneEnd-1] < '0' || joined[phoneEnd-1] > '9') {
			phoneEnd--
		}
		var locations [][]int
		if !f.phoneExcluded {
			locations = phonePattern.FindAllIndex(joined[:phoneEnd], -1)
		}
		for _, loc := range locations {
			a, z := loc[0], loc[1]
			if offset+int64(z) <= f.phoneEnd || z > limit || a > 0 && alpha(joined[a-1]) || z < len(joined) && alpha(joined[z]) {
				continue
			}
			s := joined[a:z]
			digits := 0
			for _, c := range s {
				if c >= '0' && c <= '9' {
					digits++
				}
			}
			if digits >= 8 && digits <= 15 && (s[0] == '+' || bytes.ContainsAny(s, " ().-")) {
				f.phonePending++
			}
		}
		f.phoneEnd = offset + int64(limit)
		f.phoneTail = append(f.phoneTail[:0], joined[max(0, len(joined)-256):]...)
		if end {
			if !f.phoneExcluded {
				f.hits[1] += f.phonePending
			}
			f.phoneTail = nil
			f.phoneLineSize = 0
			f.phoneEnd = 0
			f.phonePending = 0
			f.phoneExcluded = false
		}
		if final {
			final = false
		}
	}
}

// Searching for the mandatory @ first avoids a 64-state regex walk on every
// byte of long source-code identifiers and other strings without an address.
func emailLocations(b []byte) [][]int {
	var out [][]int
	for start := 0; start < len(b); {
		n := bytes.IndexByte(b[start:], '@')
		if n < 0 {
			break
		}
		at := start + n
		start = at + 1
		left := at
		for count := 0; left > 0 && count < 64; count++ {
			r, n := utf8.DecodeLastRune(b[:left])
			if !emailRune(r, true) {
				break
			}
			left -= n
		}
		right := at + 1
		for count := 0; right < len(b) && count < 186; count++ {
			r, n := utf8.DecodeRune(b[right:])
			if !emailRune(r, false) {
				break
			}
			right += n
		}
		for _, loc := range emailPattern.FindAllIndex(b[left:right], -1) {
			out = append(out, []int{left + loc[0], left + loc[1]})
		}
	}
	return out
}

// Unicode SimpleFold adds these two runes to the regex's ASCII letter classes.
func emailRune(r rune, local bool) bool {
	return r == 'ſ' || r == 'K' || r < utf8.RuneSelf && (alpha(byte(r)) || r == '.' || r == '-' || local && strings.ContainsRune("!#$%&'*+/=?^_`{|}~", r))
}
