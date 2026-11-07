package inventory

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"strconv"
	"strings"
)

// Archive candidates and aliases are shared verbatim with the Python planner.
// Names determine conservative planned cost; content must confirm interiors.
// Plain .gz members always cost their stored size, even if they contain tar.
//
//go:embed archive_formats.json
var archiveFormatsJSON []byte
var archiveFormats = func() map[string]string {
	var m map[string]string
	if err := json.Unmarshal(archiveFormatsJSON, &m); err != nil {
		panic(err)
	}
	return m
}()

func ArchiveFormat(format string) string {
	return archiveFormats[strings.ToLower(strings.TrimPrefix(format, "."))]
}

// IsTarHeader confirms the first decoded 512-byte block, including old tar
// headers without ustar magic. Both historical checksum conventions are valid.
func IsTarHeader(b []byte) bool {
	if len(b) < 512 {
		return false
	}
	b = b[:512]
	if bytes.Equal(b, make([]byte, 512)) {
		return true
	}
	want, e := strconv.ParseInt(strings.Trim(string(b[148:156]), " \x00"), 8, 64)
	if e != nil {
		return false
	}
	var unsigned, signed int64
	for i, c := range b {
		if i >= 148 && i < 156 {
			c = ' '
		}
		unsigned += int64(c)
		signed += int64(int8(c))
	}
	return want == unsigned || want == signed
}
