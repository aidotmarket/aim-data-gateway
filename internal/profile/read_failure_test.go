package profile

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/config"
)

type partialErrorReader struct {
	body string
	err  error
}

func (r *partialErrorReader) Read(p []byte) (int, error) {
	n := copy(p, r.body)
	r.body = r.body[n:]
	if r.body == "" {
		return n, r.err
	}
	return n, nil
}
func TestReadErrorsNeverBecomeOpaque(t *testing.T) {
	injected := errors.New("injected read failure")
	for _, tc := range []struct {
		name, body string
		json       bool
	}{
		{"csv_header", "bad\"header,a", false}, {"csv_record", "a,b\n1,\"partial", false},
		{"json_partial", "{\"x\":1}\n{\"x\":", true}, {"json_complete_token", "{\"x\":1}", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &partialErrorReader{tc.body, injected}
			var d Description
			var e error
			if tc.json {
				d, e = jsonLines(context.Background(), r, config.Columns{}, "sha")
			} else {
				d, e = delimited(context.Background(), r, "text/csv", config.Columns{}, "sha")
			}
			if !errors.Is(e, injected) || d.Columns != nil {
				t.Fatalf("read_error required, no stored description: %+v %v", d, e)
			}
		})
	}
	// The syntax error arrives before the separate failure in the unread tail.
	for _, jsonLine := range []bool{false, true} {
		prefix := "a,b\n1,bad\"quote\n"
		if jsonLine {
			prefix = "{\"x\":1}\n[\n"
		}
		r := io.MultiReader(strings.NewReader(prefix), &partialErrorReader{"tail", injected})
		var d Description
		var e error
		if jsonLine {
			d, e = jsonLines(context.Background(), r, config.Columns{}, "sha")
		} else {
			d, e = delimited(context.Background(), r, "text/csv", config.Columns{}, "sha")
		}
		if !errors.Is(e, injected) || d.Columns != nil {
			t.Fatalf("unread tail error lost: %+v %v", d, e)
		}
	}
}

func TestCancelledMidReadNeverBecomesOpaque(t *testing.T) {
	for _, jsonLine := range []bool{false, true} {
		t.Run(map[bool]string{false: "csv", true: "ndjson"}[jsonLine], func(t *testing.T) {
			r, w, e := os.Pipe()
			if e != nil {
				t.Fatal(e)
			}
			defer r.Close()
			defer w.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stop := context.AfterFunc(ctx, func() { r.Close() })
			defer stop()
			done := make(chan error, 1)
			go func() {
				var d Description
				var e error
				if jsonLine {
					d, e = jsonLines(ctx, r, config.Columns{}, "sha")
				} else {
					d, e = delimited(ctx, r, "text/csv", config.Columns{}, "sha")
				}
				if d.Columns != nil {
					done <- errors.New("stored opaque description")
					return
				}
				done <- e
			}()
			prefix := "a,b\n1,\"partial"
			if jsonLine {
				prefix = "{\"x\":1}\n{\"x\":"
			}
			if _, e = w.Write([]byte(prefix)); e != nil {
				t.Fatal(e)
			}
			cancel()
			select {
			case e := <-done:
				if !errors.Is(e, ErrGatewayTimeout) {
					t.Fatal(e)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("cancel did not interrupt read")
			}
		})
	}
}
