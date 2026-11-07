package inventory

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// Frozen verbatim decision rules from 5553f33b. Census detection can evolve;
// these 29 cases guard the gateway runner's existing table admission decisions.
func baseDetect5553f33b(b []byte) string {
	if len(b) >= 4 && bytes.Equal(b[:4], []byte("PAR1")) {
		return "application/vnd.apache.parquet"
	}
	s := strings.TrimPrefix(string(b), "\ufeff")
	line, _, _ := strings.Cut(s, "\n")
	line = strings.TrimSuffix(line, "\r")
	if len(line) == 0 || bytes.IndexByte(b, 0) >= 0 {
		return "application/octet-stream"
	}
	if json.Valid([]byte(line)) && (strings.HasPrefix(strings.TrimSpace(line), "{") || strings.HasPrefix(strings.TrimSpace(line), "[")) {
		return "application/x-ndjson"
	}
	if strings.Contains(line, "\t") {
		return "text/tab-separated-values"
	}
	if strings.Contains(line, ",") {
		return "text/csv"
	}
	return "application/octet-stream"
}

func TestDetectRunnerBaseDifferential29(t *testing.T) {
	inputs := [][]byte{
		nil, []byte("plain"), []byte("a,b\n1,2\n"), []byte("a\tb\n1\t2\n"), []byte("{\"a\":1}\n"), []byte("[1,2]\n"), []byte(" {\"a\":1}\r\n"), []byte("{bad, json}\n"), []byte("PAR1"), []byte("PAR1\x00,"),
		[]byte("\ufeffa,b\n"), []byte("\ufeffa\tb\n"), []byte("\xff\xfea\x00,\x00b\x00\n\x00"), []byte("\xff\xfea\x00\t\x00b\x00\n\x00"), []byte("\xfe\xff\x00a\x00,\x00b\x00\n"), []byte("\xfe\xff\x00a\x00\t\x00b\x00\n"),
		[]byte("\na,b\n"), []byte("\r\na,b\n"), []byte("  \na,b\n"), []byte("\x1f\x8b,\n"), []byte("PK\x03\x04,\n"), []byte("%PDF-1.7,\n"), []byte("<html>,\n"), []byte("a\x00,b\n"), []byte("a,b\r\n"), []byte("a\tb,c\n"), []byte("# heading"), []byte("\xff,\n"), []byte("{\n\"a\":1\n}"),
	}
	if len(inputs) != 29 {
		t.Fatal(len(inputs))
	}
	for i, b := range inputs {
		if got, want := Detect(b), baseDetect5553f33b(b); got != want {
			t.Fatalf("case %d: got %s want %s", i, got, want)
		}
	}
}
