package awsverification

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

type writeFunc func([]byte) (int, error)

func (f writeFunc) Write(b []byte) (int, error) {
	return f(b)
}

func TestRuntimeLogsBoundedAcknowledgedAndNoRawMarkers(t *testing.T) {
	var out bytes.Buffer
	l := Logs{Output: &out}
	hash := strings.Repeat("a", 64)
	if err := l.Event(ctx, "accepted", hash); err != nil {
		t.Fatal(err)
	}
	want := "{\"event\":\"accepted\",\"hash\":\"" + hash + "\"}\n"
	if out.String() != want {
		t.Fatal("unexpected audit bytes", out.String())
	}
	for _, input := range [][2]string{{"RAW_CELL_MARKER", hash}, {"received", "RAW_KEY_MARKER"}} {
		if l.Event(ctx, input[0], input[1]) == nil {
			t.Fatal("unbounded audit field accepted")
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if l.Event(cancelled, "accepted", hash) == nil || out.String() != want {
		t.Fatal("invalid/cancelled audit wrote bytes")
	}
}

func TestUnavailableRuntimeLogsRefuseBeforeSourceReads(t *testing.T) {
	for _, mode := range []string{"nil", "error", "short_write"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			f.job(t, 1, "scan")
			var l Logs
			if mode != "nil" {
				l.Output = writeFunc(func(b []byte) (int, error) {
					// Let received pass; admission must also acknowledge accepted.
					if bytes.Contains(b, []byte(`"event":"accepted"`)) {
						if mode == "short_write" {
							return len(b) - 1, nil
						}
						return 0, errors.New("RAW_PROVIDER_MARKER")
					}
					return len(b), nil
				})
			}
			f.h.Audit = l
			err := f.h.Invoke(ctx)
			if !errors.Is(err, ErrRefused) || strings.Contains(err.Error(), "RAW_") {
				t.Fatal("unavailable audit allowed or leaked provider error", err)
			}
			if len(f.s3.heads)+len(f.s3.requests)+len(f.backend.reports) != 0 {
				t.Fatal("source work before audit acknowledgment")
			}
		})
	}
}
