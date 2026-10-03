package verification

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// canonical implements python-json-sort-compact-v1, not the gateway audit codec.
func canonical(v any) ([]byte, error) {
	var b bytes.Buffer
	if e := encodePython(&b, v); e != nil {
		return nil, e
	}
	return b.Bytes(), nil
}
func pythonFloat(f float64) (string, error) {
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return "", ErrUnsupported
	}
	// Python uses scientific notation below 1e-4 and at/above 1e16.
	form := byte('f')
	if f != 0 && (math.Abs(f) < 1e-4 || math.Abs(f) >= 1e16) {
		form = 'e'
	}
	s := strconv.FormatFloat(f, form, -1, 64)
	if form == 'f' && !strings.Contains(s, ".") {
		s += ".0"
	}
	return s, nil
}
func pythonString(b *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return ErrUnsupported
	}
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 32 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return nil
}
func encodePython(b *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case string:
		return pythonString(b, x)
	case float64:
		s, e := pythonFloat(x)
		if e != nil {
			return e
		}
		b.WriteString(s)
	case json.Number:
		if strings.ContainsAny(string(x), ".eE") {
			f, e := x.Float64()
			if e != nil {
				return ErrUnsupported
			}
			return encodePython(b, f)
		}
		n, ok := new(big.Int).SetString(string(x), 10)
		if !ok {
			return ErrUnsupported
		}
		b.WriteString(n.String())
	case *big.Int:
		b.WriteString(x.String())
	case int:
		b.WriteString(strconv.Itoa(x))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case uint64:
		b.WriteString(strconv.FormatUint(x, 10))
	case []any:
		b.WriteByte('[')
		for i, z := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if e := encodePython(b, z); e != nil {
				return e
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			if e := pythonString(b, k); e != nil {
				return e
			}
			b.WriteByte(':')
			if e := encodePython(b, x[k]); e != nil {
				return e
			}
		}
		b.WriteByte('}')
	default:
		raw, e := json.Marshal(v)
		if e != nil {
			return ErrUnsupported
		}
		value, e := decodeJSON(raw)
		if e != nil {
			return e
		}
		return encodePython(b, value)
	}
	return nil
}

// decodeJSON rejects duplicate keys and trailing data, including within nested values.
func decodeJSON(raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, ErrUnsupported
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, e := jsonValue(d, 0)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, ErrUnsupported
	}
	return v, nil
}
func jsonValue(d *json.Decoder, depth int) (any, error) {
	if depth > 32 {
		return nil, ErrUnsupported
	}
	t, e := d.Token()
	if e != nil {
		return nil, ErrUnsupported
	}
	switch t {
	case json.Delim('{'):
		m := map[string]any{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return nil, ErrUnsupported
			}
			s, ok := k.(string)
			if !ok {
				return nil, ErrUnsupported
			}
			if _, ok = m[s]; ok {
				return nil, ErrUnsupported
			}
			v, e := jsonValue(d, depth+1)
			if e != nil {
				return nil, e
			}
			m[s] = v
		}
		_, e = d.Token()
		return m, e
	case json.Delim('['):
		a := []any{}
		for d.More() {
			v, e := jsonValue(d, depth+1)
			if e != nil {
				return nil, e
			}
			a = append(a, v)
		}
		_, e = d.Token()
		return a, e
	}
	return t, nil
}
func requireCanonical(raw []byte) (any, error) {
	v, e := decodeJSON(raw)
	if e != nil {
		return nil, e
	}
	b, e := canonical(v)
	if e != nil || !bytes.Equal(b, raw) {
		return nil, ErrUnsupported
	}
	return v, nil
}

// Canonical encodes the frozen Python-compatible fact and receipt format.
func Canonical(v any) ([]byte, error) { return canonical(v) }

// ParseCanonical rejects alternate encodings, duplicates and trailing bytes.
func ParseCanonical(raw []byte) (any, error) { return requireCanonical(raw) }
