package verification

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

func rateString(q int64) string { return fmt.Sprintf("%d.%06d", q/1000000, q%1000000) }

var nullTokens = map[string]bool{"": true, "#N/A": true, "#N/A N/A": true, "#NA": true, "-1.#IND": true, "-1.#QNAN": true, "-NaN": true, "-nan": true, "1.#IND": true, "1.#QNAN": true, "N/A": true, "NA": true, "NULL": true, "NaN": true, "n/a": true, "nan": true, "null": true}

type cell struct {
	text  string
	value any
	json  bool
}

func nameOK(names []string, p Policy) error {
	if len(names) == 0 || len(names) > p.MaxColumns {
		return ErrUnsupported
	}
	seen := map[string]bool{}
	for _, n := range names {
		if !utf8.ValidString(n) || utf8.RuneCountInString(n) == 0 || utf8.RuneCountInString(n) > 256 || seen[n] {
			return ErrUnsupported
		}
		seen[n] = true
	}
	return nil
}

// limitRecords tracks CSV logical boundaries before encoding/csv buffers them.
// State: field start, unquoted field, quoted field, closing/escaped quote.
type limitRecords struct {
	r         io.Reader
	max, size int
	state     byte
	comma     byte
}

func (l *limitRecords) Read(p []byte) (int, error) {
	n, e := l.r.Read(p[:min(len(p), blockSize, l.max-l.size+1)])
	for _, c := range p[:n] {
		l.size++
		if l.size > l.max {
			return 0, ErrBudget
		}
		switch l.state {
		case 0:
			if c == '"' {
				l.state = 2
			} else if c != l.comma && c != '\n' {
				l.state = 1
			}
		case 1:
			if c == l.comma {
				l.state = 0
			}
		case 2:
			if c == '"' {
				l.state = 3
			}
		case 3:
			if c == '"' {
				l.state = 2
			} else if c == l.comma {
				l.state = 0
			}
		}
		if c == '\n' && l.state != 2 {
			l.size, l.state = 0, 0
		}
	}
	return n, e
}
func walkText(ctx context.Context, r io.Reader, format string, p Policy, visit func([]string, []cell, int64) error) error {
	if format == "jsonl" {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, min(64<<10, p.MaxRecordBytes)), p.MaxRecordBytes+1)
		var offset int64
		for sc.Scan() {
			if ctx.Err() != nil {
				return ErrTimeout
			}
			raw := sc.Bytes()
			offset += int64(len(raw) + 1)
			if len(raw) > p.MaxRecordBytes || !utf8.Valid(raw) {
				return ErrBudget
			}
			if len(bytes.TrimSpace(raw)) == 0 {
				continue
			}
			d := json.NewDecoder(bytes.NewReader(raw))
			d.UseNumber()
			t, e := d.Token()
			if e != nil || t != json.Delim('{') {
				return ErrUnsupported
			}
			names := []string{}
			values := []cell{}
			seen := map[string]bool{}
			for d.More() {
				t, e = d.Token()
				if e != nil {
					return ErrUnsupported
				}
				k, ok := t.(string)
				if !ok || seen[k] {
					return ErrUnsupported
				}
				seen[k] = true
				v, e := jsonValue(d, 1)
				if e != nil {
					return e
				}
				switch v.(type) {
				case map[string]any, []any:
					return ErrUnsupported
				}
				names = append(names, k)
				values = append(values, cell{value: v, json: true})
				if len(names) > p.MaxColumns {
					return ErrUnsupported
				}
			}
			if _, e = d.Token(); e != nil {
				return ErrUnsupported
			}
			if _, e = d.Token(); e != io.EOF {
				return ErrUnsupported
			}
			if e := nameOK(names, p); e != nil {
				return e
			}
			if e := visit(names, values, offset); e != nil {
				return e
			}
		}
		if e := sc.Err(); e != nil {
			if errors.Is(e, ErrArtifactChanged) || errors.Is(e, ErrTimeout) {
				return e
			}
			return ErrBudget
		}
		return nil
	}
	comma := byte(',')
	if format == "tsv" {
		comma = '\t'
	}
	cr := csv.NewReader(&limitRecords{r: r, max: p.MaxRecordBytes, comma: comma})
	cr.Comma = rune(comma)
	cr.FieldsPerRecord = -1
	cr.ReuseRecord = true
	names, e := cr.Read()
	if e != nil {
		return textReadError(e)
	}
	names = append([]string(nil), names...)
	if len(names) > 0 {
		names[0] = strings.TrimPrefix(names[0], "\ufeff")
	}
	if e = nameOK(names, p); e != nil {
		return e
	}
	cr.FieldsPerRecord = len(names)
	if e = visit(names, nil, cr.InputOffset()); e != nil {
		return e
	}
	last := cr.InputOffset()
	for {
		if ctx.Err() != nil {
			return ErrTimeout
		}
		record, e := cr.Read()
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return textReadError(e)
		}
		if cr.InputOffset()-last > int64(p.MaxRecordBytes) {
			return ErrBudget
		}
		last = cr.InputOffset()
		values := make([]cell, len(record))
		for i, v := range record {
			if !utf8.ValidString(v) || len(v) > p.MaxScalarBytes {
				return ErrUnsupported
			}
			values[i] = cell{text: v}
		}
		if e := visit(names, values, last); e != nil {
			return e
		}
	}
}
func textReadError(e error) error {
	if errors.Is(e, ErrArtifactChanged) {
		return ErrArtifactChanged
	}
	if errors.Is(e, ErrBudget) {
		return ErrBudget
	}
	if errors.Is(e, ErrTimeout) {
		return ErrTimeout
	}
	return ErrUnsupported
}
func timestamp(s string) (time.Time, bool, bool) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999", "2006-01-02T15:04:05.999999999"} {
		if t, e := time.Parse(layout, s); e == nil {
			return t, true, layout == time.RFC3339Nano
		}
	}
	return time.Time{}, false, false
}
func inferCell(c cell) string {
	if c.json {
		switch v := c.value.(type) {
		case nil:
			return "unknown"
		case bool:
			return "boolean"
		case json.Number:
			if strings.ContainsAny(string(v), ".eE") {
				return "float"
			}
			return "integer"
		case string:
			if _, ok, _ := timestamp(v); ok && !strings.ContainsAny(v, ".,") {
				return "datetime"
			}
			return "string"
		}
		return "unsupported"
	}
	v := strings.TrimSpace(c.text)
	if nullTokens[c.text] {
		return "unknown"
	}
	if v == "true" || v == "false" || v == "True" || v == "False" || v == "TRUE" || v == "FALSE" {
		return "boolean"
	}
	if _, e := strconv.ParseInt(v, 10, 64); e == nil && !strings.HasPrefix(v, "+") {
		return "integer"
	}
	if _, e := strconv.ParseFloat(v, 64); e == nil || errors.Is(e, strconv.ErrRange) {
		return "float"
	}
	if _, e := time.Parse("2006-01-02", v); e == nil {
		return "date"
	}
	if _, ok, _ := timestamp(v); ok {
		return "datetime"
	}
	return "string"
}
func promote(a, z string, isJSON bool) (string, error) {
	if a == "unknown" {
		return z, nil
	}
	if z == "unknown" || z == a {
		return a, nil
	}
	if a == "integer" && z == "float" || a == "float" && z == "integer" {
		return "float", nil
	}
	if isJSON {
		return "", ErrUnsupported
	}
	return "string", nil
}
func inferText(ctx context.Context, r io.Reader, x *pinned, p Policy, b *budget) error {
	order := map[string]int{}
	x.names = []string{}
	x.kinds = []string{}
	return walkText(ctx, r, x.member.Format, p, func(names []string, values []cell, offset int64) error {
		for j, n := range names {
			i, ok := order[n]
			if !ok {
				if len(x.names) >= p.MaxColumns {
					return ErrUnsupported
				}
				if e := b.reserve(int64(len(n) + 1024)); e != nil {
					return e
				}
				i = len(x.names)
				order[n] = i
				x.names = append(x.names, n)
				x.kinds = append(x.kinds, "unknown")
			}
			if values == nil {
				continue
			}
			if x.member.Format != "jsonl" && offset > 1<<20 {
				continue
			}
			z := inferCell(values[j])
			kind, e := promote(x.kinds[i], z, x.member.Format == "jsonl")
			if e != nil {
				return e
			}
			x.kinds[i] = kind
		}
		return nil
	})
}
func scalar(c cell, kind string) ([]byte, int, float64, bool, error) {
	var v any = c.text
	valid := true
	if c.json {
		v = c.value
		valid = v != nil
	} else if kind != "string" {
		valid = !nullTokens[c.text]
	}
	if !valid {
		return nil, 0, 0, false, nil
	}
	if kind == "unknown" {
		return nil, 0, 0, false, ErrUnsupported
	}
	text := c.text
	if c.json {
		switch x := v.(type) {
		case string:
			text = x
		case json.Number:
			text = string(x)
		case bool:
			text = strconv.FormatBool(x)
		}
	}
	var raw []byte
	number := 0.0
	length := 0
	var e error
	switch kind {
	case "string":
		if _, ok := v.(string); c.json && !ok {
			return nil, 0, 0, false, ErrUnsupported
		}
		raw, e = canonical(text)
		length = len(text)
	case "integer":
		var n int64
		n, e = strconv.ParseInt(strings.TrimSpace(text), 10, 64)
		if e == nil {
			raw = []byte(strconv.FormatInt(n, 10))
			number = float64(n)
		}
	case "float":
		number, e = strconv.ParseFloat(strings.TrimSpace(text), 64)
		if e == nil {
			raw, e = canonical(number)
		}
	case "boolean":
		var z bool
		z, e = strconv.ParseBool(text)
		if e == nil {
			raw = []byte(strconv.FormatBool(z))
		}
	case "date":
		var t time.Time
		t, e = time.Parse("2006-01-02", text)
		if e == nil {
			raw = []byte("time:" + t.Format("2006-01-02"))
		}
	case "datetime":
		t, ok, tz := timestamp(text)
		if !ok {
			e = ErrUnsupported
		} else {
			// Arrow CSV retains its inferred precision; without pandas the pinned
			// Python oracle refuses sub-microsecond values. JSON uses seconds UTC
			// with no timezone metadata, even when the input has an offset.
			if !c.json && t.Nanosecond()%1000 != 0 {
				return nil, 0, 0, false, ErrUnsupported
			}
			if tz {
				t = t.UTC()
			}
			raw = []byte("time:" + isoPython(t, tz && !c.json, t.Nanosecond() != 0))
		}
	default:
		e = ErrUnsupported
	}
	if e != nil {
		return nil, 0, 0, false, ErrUnsupported
	}
	return raw, length, number, true, nil
}
func isoPython(t time.Time, tz, frac bool) string {
	s := t.Format("2006-01-02T15:04:05")
	if frac {
		s += fmt.Sprintf(".%06d", t.Nanosecond()/1000)
	}
	if tz {
		s += t.Format("-07:00")
	}
	return s
}
func textObject(ctx context.Context, s Source, x *pinned, p Policy, b *budget) (Object, error) {
	r, reader, e := openText(ctx, s, x)
	if e != nil {
		return Object{}, e
	}
	defer r.Close()
	stop := context.AfterFunc(ctx, func() { r.Close() })
	defer stop()
	acc := make([]*aggregate, len(x.names))
	indices := map[string]int{}
	for i, n := range x.names {
		indices[n] = i
		acc[i] = newAggregate(x.kinds[i], i, p)
	}
	var rows int64
	e = walkText(ctx, reader, x.member.Format, p, func(names []string, values []cell, _ int64) error {
		if values == nil {
			return nil
		}
		rows++
		if rows > math.MaxInt64/1000000 {
			return ErrBudget
		}
		present := make([]bool, len(acc))
		for j, n := range names {
			i, ok := indices[n]
			if !ok {
				return ErrArtifactChanged
			}
			textLen := len(values[j].text)
			if z, ok := values[j].value.(string); ok {
				textLen = len(z)
			}
			// Reserve worst-case Python string escaping before constructing scalar
			// bytes. The operation's fixed reserve already covers parser buffers.
			extra := max(int64(0), int64(textLen)*6+1024-int64(p.MaxRecordBytes))
			if e := b.reserve(extra); e != nil {
				return e
			}
			raw, l, num, valid, e := scalar(values[j], acc[i].kind)
			b.used -= extra
			if e != nil {
				return e
			}
			if e = acc[i].add(raw, l, num, valid, p, b); e != nil {
				return e
			}
			present[i] = true
		}
		for i, yes := range present {
			if !yes {
				acc[i].nulls++
			}
		}
		return nil
	})
	if e != nil {
		return Object{}, e
	}
	return finish(x.names, acc, rows), nil
}
