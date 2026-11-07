package verification

import (
	"github.com/aidotmarket/aim-data-gateway/internal/inventory"
	"strings"
)

func detectContent(b []byte, name string) inventory.ContentType {
	return inventory.DetectContent(b, name)
}

func extensionClass(format string) string {
	f := strings.ToLower(strings.TrimPrefix(format, "."))
	switch f {
	case "csv", "tsv", "jsonl", "ndjson", "parquet":
		return "table"
	case "json":
		return "json"
	case "go", "py", "cpp", "c", "h", "java", "js", "ts", "rs", "rb", "sh", "cs", "sql":
		return "source_code"
	case "md", "markdown":
		return "markdown"
	case "txt", "text", "in", "out":
		return "text"
	case "html", "htm", "xml":
		return "html_xml"
	case "pdf":
		return "pdf"
	case "png", "jpg", "jpeg", "gif", "webp", "svg":
		return "image"
	case "zip":
		return "archive_zip"
	case "tar.gz", "tgz":
		return "archive_tar_gz"
	}
	return "other"
}
func archiveFormat(m Member) string {
	return inventory.ArchiveFormat(m.Format)
}
