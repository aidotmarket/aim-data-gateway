package inventory

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"io"
	"path"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ContentType contains fixed labels only. Names are local tie breakers, never output.
type ContentType struct{ Class, MediaType, Archive string }

// DetectContent classifies census content from a bounded prefix. Signed Format
// selects tables; the gateway runner retains its frozen Detect admission rules.
func DetectContent(b []byte, name string) ContentType {
	result := func(c, m string) ContentType { return ContentType{Class: c, MediaType: m} }
	if len(b) == 0 {
		return result("empty", "application/octet-stream")
	}
	if len(b) >= 2 && (bytes.Equal(b[:2], []byte{0xff, 0xfe}) || bytes.Equal(b[:2], []byte{0xfe, 0xff})) {
		little := b[0] == 0xff
		units := make([]uint16, 0, len(b)/2)
		for i := 2; i+1 < len(b); i += 2 {
			v := binary.BigEndian.Uint16(b[i:])
			if little {
				v = binary.LittleEndian.Uint16(b[i:])
			}
			units = append(units, v)
		}
		return DetectContent([]byte(string(utf16.Decode(units))), name)
	}
	if bytes.HasPrefix(b, []byte("PAR1")) {
		return result("other_binary", "application/vnd.apache.parquet")
	}
	if bytes.HasPrefix(b, []byte("PK\x03\x04")) || bytes.HasPrefix(b, []byte("PK\x05\x06")) {
		return ContentType{"other_binary", "application/zip", "zip"}
	}
	if bytes.HasPrefix(b, []byte{0x1f, 0x8b}) {
		t := ContentType{"other_binary", "application/gzip", ""}
		if gz, e := gzip.NewReader(bytes.NewReader(b)); e == nil {
			var header [512]byte
			if _, e = io.ReadFull(gz, header[:]); e == nil && IsTarHeader(header[:]) {
				t.Archive = "tar.gz"
			}
			gz.Close()
		}
		return t
	}
	if bytes.HasPrefix(b, []byte("%PDF-")) {
		return result("pdf", "application/pdf")
	}
	for _, magic := range [][]byte{[]byte("\x89PNG\r\n\x1a\n"), {0xff, 0xd8, 0xff}, []byte("GIF87a"), []byte("GIF89a"), []byte("RIFF")} {
		if bytes.HasPrefix(b, magic) {
			return result("image", "image/*")
		}
	}
	// A prefix may end midway through a UTF-8 rune.
	text := b
	for i := 0; i < 3 && len(text) > 0 && !utf8.Valid(text); i++ {
		text = text[:len(text)-1]
	}
	printable := 0
	for _, c := range b {
		if c >= 32 || c == '\n' || c == '\r' || c == '\t' {
			printable++
		}
	}
	if bytes.IndexByte(b, 0) >= 0 || !utf8.Valid(text) && printable*100 < len(b)*90 {
		return result("other_binary", "application/octet-stream")
	}
	s := strings.TrimSpace(strings.TrimPrefix(string(text), "\ufeff"))
	line, _, _ := strings.Cut(s, "\n")
	if json.Valid([]byte(line)) && (strings.HasPrefix(line, "{") || strings.HasPrefix(line, "[")) {
		class := "json_document"
		if strings.Contains(s, "\n") {
			class = "table_like_jsonl"
		}
		return result(class, "application/x-ndjson") // Retains gateway's existing single-line JSON media type.
	}
	if json.Valid([]byte(s)) && (strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[")) {
		return result("json_document", "application/json")
	}
	if strings.HasPrefix(s, "<") {
		return result("html_xml", "text/html")
	}
	if strings.Contains(line, "\t") {
		return result("table_like_tsv", "text/tab-separated-values")
	}
	if strings.Contains(line, ",") {
		return result("table_like_csv", "text/csv")
	}
	ext := strings.ToLower(path.Ext(name))
	if ext == ".md" || ext == ".markdown" || strings.HasPrefix(s, "# ") || strings.HasPrefix(s, "## ") {
		return result("markdown", "text/markdown")
	}
	switch ext {
	case ".go", ".py", ".cpp", ".c", ".h", ".java", ".js", ".ts", ".rs", ".rb", ".sh", ".cs", ".sql":
		return result("source_code", "text/plain")
	}
	for _, prefix := range []string{"package ", "import ", "def ", "function ", "#include", "//", "#!/"} {
		if strings.HasPrefix(s, prefix) {
			return result("source_code", "text/plain")
		}
	}
	return result("plain_text", "text/plain")
}
