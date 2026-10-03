package verification

import (
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

type countedReader struct {
	io.Reader
	bytes int
}

func (r *countedReader) Read(p []byte) (int, error) {
	n, e := r.Reader.Read(p)
	r.bytes += n
	return n, e
}

type countedSource struct {
	*memorySource
	bytes int
}

func (s *countedSource) Open(ctx context.Context, id string) (io.ReadCloser, error) {
	r, e := s.memorySource.Open(ctx, id)
	if e != nil {
		return nil, e
	}
	return &countedClose{r, s}, nil
}

type countedClose struct {
	io.ReadCloser
	source *countedSource
}

func (r *countedClose) Read(p []byte) (int, error) {
	n, e := r.ReadCloser.Read(p)
	r.source.bytes += n
	return n, e
}

func TestLogicalRecordBudgetBeforeBuffering(t *testing.T) {
	for _, format := range []string{"csv", "tsv"} {
		for name, data := range map[string]string{
			"multiline":       "n\n\"" + strings.Repeat("short\n", 100000) + "\"\n",
			"unterminated":    "n\n\"" + strings.Repeat("short\n", 100000),
			"header":          "\"" + strings.Repeat("short\n", 100000) + "\"\n1\n",
			"unquoted_header": strings.Repeat("a", 100000) + "\n1\n",
		} {
			t.Run(format+"/"+name, func(t *testing.T) {
				p := testPolicy()
				p.MaxColumns = 1000
				p.MaxScalarBytes = 16 << 20
				p.MaxRecordBytes = 1024
				r := &countedReader{Reader: strings.NewReader(data)}
				e := walkText(context.Background(), r, format, p, func([]string, []cell, int64) error { return nil })
				if !errors.Is(e, ErrBudget) {
					t.Fatalf("error=%v", e)
				}
				if r.bytes > p.MaxRecordBytes+3 {
					t.Fatalf("read %d bytes before refusal", r.bytes)
				}
				src := &countedSource{memorySource: sourceFor([]byte(data), format)}
				f, e := Scan(context.Background(), src, p)
				if src.bytes > p.MaxRecordBytes+blockSize+3 {
					t.Fatalf("source read %d bytes before refusal", src.bytes)
				}
				if !errors.Is(e, ErrBudget) || !reflect.DeepEqual(f, Facts{}) {
					t.Fatalf("facts=%+v error=%v", f, e)
				}
			})
		}
	}
}

func TestLogicalRecordBoundaries(t *testing.T) {
	for _, data := range []string{"n\n\"ab\"\"c\nd\"\n\"ef\"\n", "n\r\n\"ab\"\"c\r\nd\"\r\n\"ef\"\r\n"} {
		p := testPolicy()
		p.MaxColumns = 1000
		p.MaxScalarBytes = 16 << 20
		p.MaxRecordBytes = 16
		var rows int
		e := walkText(context.Background(), strings.NewReader(data), "csv", p, func(_ []string, v []cell, _ int64) error {
			if v != nil {
				rows++
			}
			return nil
		})
		if e != nil || rows != 2 {
			t.Fatalf("rows=%d error=%v", rows, e)
		}
	}
}
