package verification

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/config"
	"github.com/aidotmarket/aim-data-gateway/internal/ledger"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	core "github.com/aidotmarket/aim-data-gateway/verification"
)

func TestParserFromContent(t *testing.T) {
	for _, name := range []string{"bin", "parquet", "alias"} {
		for _, ruleName := range []string{"none", "drop", "rename"} {
			t.Run(name+"/"+ruleName, func(t *testing.T) {
				ctx := context.Background()
				f := newRunner(t)
				kind := name
				if name == "alias" {
					kind = "csv"
					f.cfg.Aliases = map[string]string{"data/hidden.csv": "seller alias.parquet"}
				}
				_, j, s, _ := f.sourceJob(t, kind, []byte("id,value\n1,2\n3,4\n"), "scan")
				src := &source{runner: f.r, snapshot: s, ctx: ctx}
				if ruleName != "none" {
					rule := config.Columns{Drop: []string{"value"}}
					if ruleName == "rename" {
						rule = config.Columns{Rename: map[string]string{"value": "public"}}
					}
					f.cfg.Columns = map[string]config.Columns{"data/hidden." + kind: rule}
				}
				members := src.Members()
				if len(members) != 1 || members[0].Format != "csv" {
					t.Fatalf("content parser: %+v", members)
				}
				affected, e := src.eligibility(ctx)
				if e != nil {
					t.Fatal(e)
				}
				if ruleName == "none" {
					if len(affected) != 0 {
						t.Fatal(affected)
					}
					facts, e := core.Scan(ctx, src, policy(j, f.r.Keys))
					if e != nil || len(facts.Objects) != 1 || len(facts.Coverage.Skipped) != 0 || facts.Objects[0].Rows != 2 {
						t.Fatalf("CSV scan: %+v %v", facts, e)
					}
				} else {
					if len(affected) != 1 || affected[0] != s.Members[0].FileID {
						t.Fatal("eligibility bypassed E7", affected)
					}
					for _, open := range []func() (io.Closer, error){
						func() (io.Closer, error) { return src.Open(ctx, s.Members[0].FileID) },
						func() (io.Closer, error) { return src.OpenAt(ctx, s.Members[0].FileID) },
					} {
						handle, e := open()
						if !errors.Is(e, ErrE7) {
							if handle != nil {
								handle.Close()
							}
							t.Fatal("checkedOpen bypassed E7", e)
						}
					}
					if _, e = core.Scan(ctx, src, policy(j, f.r.Keys)); e == nil {
						t.Fatal("column rule scan issued facts")
					}
				}
			})
		}
	}
}

func TestProseProbeRefusesWithoutReceipt(t *testing.T) {
	f := newRunner(t)
	token, j, _, _ := f.sourceJob(t, "txt", []byte("Hello, reader\nThis has no second column\n"), "probe")
	f.start(t)
	if e := f.r.Submit(context.Background(), token); e != nil {
		t.Fatal(e)
	}
	a := f.wait(t, j.Text("spec_id"))
	var body struct {
		Variant  string
		Document string `json:"document_b64"`
	}
	if e := json.Unmarshal(a.Result, &body); e != nil {
		t.Fatal(e)
	}
	raw, _ := wire.DecodeDocument(body.Document, wire.MaxScanDocument)
	if a.State != "reported" || body.Variant != "probe" || !bytes.Contains(raw, []byte(`"source_reachable":false`)) {
		t.Fatalf("probe must be unreachable (backend source_unreachable): %s %s", a.State, raw)
	}
	if bytes.Contains(raw, []byte(`"objects":`)) {
		t.Fatal("scan receipt on failed probe")
	}
}

func TestContentDetectionFailureRefuses(t *testing.T) {
	for _, mode := range []string{"read", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			f := newRunner(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			_, j, s, _ := f.sourceJob(t, "bin", []byte("id,value\n1,2\n"), "scan")
			var writer *os.File
			if mode == "read" {
				f.r.OpenFile = func(v ledger.File) (*os.File, error) { return os.Open(v.Root) } // directory read fails
			} else {
				f.r.OpenFile = func(ledger.File) (*os.File, error) {
					r, w, e := os.Pipe()
					writer = w
					if e == nil {
						go func() { w.Write([]byte("id,")); cancel() }()
					}
					return r, e
				}
			}
			src := &source{runner: f.r, snapshot: s, ctx: ctx}
			done := make(chan []core.Member, 1)
			go func() { done <- src.Members() }()
			select {
			case members := <-done:
				if len(members) != 1 || members[0].Format != "" {
					t.Fatal(members)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("detection blocked")
			}
			if writer != nil {
				writer.Close()
				if !errors.Is(ctx.Err(), context.Canceled) {
					t.Fatal("detection did not wait for cancellation")
				}
			}
			// Failure remains sticky across the second Members call and a healthy reopen.
			f.r.OpenFile = func(v ledger.File) (*os.File, error) { return os.Open(filepath.Join(v.Root, v.RelativePath)) }
			if m := src.Members(); m[0].Format != "" || !src.failed[s.Members[0].FileID] {
				t.Fatal("lost detection failure", m)
			}
			if _, e := core.Scan(ctx, src, policy(j, f.r.Keys)); !errors.Is(e, core.ErrArtifactChanged) && !errors.Is(e, core.ErrTimeout) {
				t.Fatal("detection failure produced facts", e)
			}
			if h, e := src.Open(context.Background(), s.Members[0].FileID); !errors.Is(e, core.ErrArtifactChanged) || h != nil {
				t.Fatal("reopen after failure", e)
			}
		})
	}
}

func TestContentFormatRewinds(t *testing.T) {
	p := filepath.Join(t.TempDir(), "data.bin")
	if e := os.WriteFile(p, []byte("a,b\n1,2\n"), 0600); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(p)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	kind, e := contentFormat(context.Background(), f)
	pos, _ := f.Seek(0, io.SeekCurrent)
	if e != nil || kind != "csv" || pos != 0 {
		t.Fatal(kind, e, pos)
	}
}

func TestUnrecordedByteMutationGivesNoReceipt(t *testing.T) {
	f := newRunner(t)
	token, j, _, _ := f.sourceJob(t, "bin", []byte("id,value\n1,2\n"), "scan")
	if e := os.WriteFile(filepath.Join(f.dir, "hidden.bin"), []byte("id,value\n3,4\n"), 0600); e != nil {
		t.Fatal(e)
	}
	f.start(t)
	if e := f.r.Submit(context.Background(), token); e != nil {
		t.Fatal(e)
	}
	a := f.wait(t, j.Text("spec_id"))
	var body struct {
		Variant  string
		Document string `json:"document_b64"`
	}
	json.Unmarshal(a.Result, &body)
	raw, _ := wire.DecodeDocument(body.Document, wire.MaxScanDocument)
	if a.State != "refused" || body.Variant != "terminal" || !bytes.Contains(raw, []byte(`"terminal_error_code":"artifact_changed"`)) {
		t.Fatalf("mutation receipt: %s %s", body.Variant, raw)
	}
}

// Probe calls Members again after scanning, to compute the size class. A late
// detection failure must invalidate the probe even though core.Scan succeeded.
func TestProbeRefusesSecondDetectionFailure(t *testing.T) {
	f := newRunner(t)
	token, j, _, _ := f.sourceJob(t, "bin", []byte("id,value\n1,2\n"), "probe")
	open := f.r.OpenFile
	f.r.OpenFile = func(v ledger.File) (*os.File, error) {
		if f.opens.Load() == 4 {
			return os.Open(v.Root)
		}
		return open(v)
	}
	f.start(t)
	if e := f.r.Submit(context.Background(), token); e != nil {
		t.Fatal(e)
	}
	a := f.wait(t, j.Text("spec_id"))
	var body struct {
		Variant  string
		Document string `json:"document_b64"`
	}
	json.Unmarshal(a.Result, &body)
	raw, _ := wire.DecodeDocument(body.Document, wire.MaxScanDocument)
	if f.opens.Load() != 4 || body.Variant != "probe" || !bytes.Contains(raw, []byte(`"source_reachable":false`)) {
		t.Fatalf("late detection failure accepted: opens=%d %s", f.opens.Load(), raw)
	}
}
