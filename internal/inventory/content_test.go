package inventory

import "testing"

func TestPlainTextTableFallback(t *testing.T) {
	for _, tc := range []struct {
		name, body, class, media, scanMedia string
	}{
		{"one.csv", "value\nv0\nv0\n", "table_like_csv", "text/csv", "text/csv"},
		{"one.TsV", "value\nv0\nv0\n", "table_like_tsv", "text/tab-separated-values", "text/tab-separated-values"},
		{"one.CSV", "value\nv0\n", "table_like_csv", "text/csv", "text/csv"},
		{"one.txt", "value\nv0\n", "plain_text", "text/plain", "application/octet-stream"},
		{"binary.csv", "value\n\x00\xff", "other_binary", "application/octet-stream", "application/octet-stream"},
		{"zip.csv", "PK\x03\x04zip", "other_binary", "application/zip", "application/octet-stream"},
		{"empty.csv", "", "empty", "application/octet-stream", "application/octet-stream"},
		{"json.csv", "{\n\"value\": 1\n}", "json_document", "application/json", "application/octet-stream"},
		{"html.csv", "<html>", "html_xml", "text/html", "application/octet-stream"},
		{"markdown.csv", "# Heading", "markdown", "text/markdown", "application/octet-stream"},
		{"source.csv", "package example", "source_code", "text/plain", "application/octet-stream"},
		{"invalid.csv", "value\n\xff", "plain_text", "text/plain", "application/octet-stream"},
		{"utf16.csv", "\xff\xfev\x00\n\x00", "plain_text", "text/plain", "application/octet-stream"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := DetectContent([]byte(tc.body), tc.name)
			if got.Class != tc.class || got.MediaType != tc.media {
				t.Fatalf("DetectContent = %+v; want %s, %s", got, tc.class, tc.media)
			}
			if got := Detect([]byte(tc.body), tc.name); got != tc.scanMedia {
				t.Fatalf("Detect = %s; want %s", got, tc.scanMedia)
			}
		})
	}
}
