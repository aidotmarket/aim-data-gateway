package cloudflareverification

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	core "github.com/aidotmarket/aim-data-gateway/verification"
)

func TestProbeArchiveBandCoversLaterSeed(t *testing.T) {
	const count = 45
	// The archive allowances exceed the read budget: one member is excluded.
	p := scanPolicy(wire.ScanJob{Payload: map[string]any{"scan_mode": core.ContentCensusV1, "planned_processed_bytes": censusR1BudgetBytes}}, nil)
	if int64(count)*p.ArchiveAllowanceBytes <= p.ContentReadBudgetBytes {
		t.Fatal("snapshot must exceed budget")
	}
	empty := seedBudgetZip(t, 0)
	objects := make([]Object, count)
	data := map[string][]byte{}
	for i := range objects {
		key := fmt.Sprintf("RAW_KEY_MARKER/%02d.zip", i)
		objects[i] = Object{Key: key, ETag: "pin", Format: "zip", Size: int64(len(empty))}
		data[key] = empty
	}
	src, _ := censusSource(t, objects, data)
	zeroPlan := core.PlannedReadSet(p.Seed, src.Members(), p)
	if len(zeroPlan) != count-1 {
		t.Fatal("unexpected zero-seed plan length", len(zeroPlan))
	}
	later := p
	later.Seed = [32]byte(bytes.Repeat([]byte{1}, 32))
	laterPlan := core.PlannedReadSet(later.Seed, src.Members(), later)
	hot := ""
	for _, m := range src.Members() {
		if !containsIdentity(zeroPlan, m.Identity) && containsIdentity(laterPlan, m.Identity) {
			hot = m.Identity
		}
	}
	if hot == "" {
		t.Fatal("later seed must include the zero-seed exclusion")
	}
	populated := seedBudgetZip(t, 10000)
	for i := range objects {
		id, _ := Identity(objects[i].Key, objects[i].ETag)
		if id == hot {
			objects[i].Size = int64(len(populated))
			data[objects[i].Key] = populated
		}
	}
	src, _ = censusSource(t, objects, data)
	v := generateCensusReceipts(t)["cf_receipt_success_complete.json"].(censusReceiptVector)
	j := s3aJob(t, v.Spec, "probe")
	_, doc := scanDocument(t, j, src)
	probeDoc := doc["probe"].(map[string]any)
	if j.Text("deterministic_seed") != "" || scanPolicy(j, nil).Seed != ([32]byte{}) {
		t.Fatal("probe must have no scan seed")
	}
	if probeDoc["source_reachable"] != true {
		t.Fatal(probeDoc)
	}
	aggregate := probeDoc["census_preflight"].(map[string]any)
	if len(aggregate) != 3 || aggregate["archive_requests_band"] != "8000-15999" || aggregate["admission_result"] != "within_bounds" || aggregate["floor_result"] != "meets_floor" {
		t.Fatal(aggregate)
	}
	// Keep the planned total separate from measured GETs; both must fit the band.
	var planned int64
	for _, m := range src.Members() {
		if containsIdentity(laterPlan, m.Identity) {
			r := preflight(context.Background(), src, m, later)
			if r.err != nil {
				t.Fatal(r.err)
			}
			planned += r.ArchiveGetRequests
		}
	}
	if planned != int64(10000+count-1) || planned > 15999 {
		t.Fatal("later scan request plan", planned)
	}
	later.Commitments = &collectedCommitments{Commitments: Commitments{Bucket: "fixture"}, Digests: map[string]string{}}
	later.RunStats = &core.RunStats{}
	if _, err := core.Scan(context.Background(), src, later); err != nil {
		t.Fatal(err)
	}
	if got := later.RunStats.GETs.Load(); got != planned {
		t.Fatal("actual vs planned GETs", got, planned)
	}
	raw := append(canonicalTest(t, aggregate), '\n')
	path := filepath.Join(censusWireDir, "cf_probe_seed_budget.json")
	if *updateCensusWire {
		if err := os.WriteFile(path, raw, 0644); err != nil {
			t.Fatal(err)
		}
	}
	stored, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(stored, raw) {
		t.Fatal("seed-budget probe vector drift", err)
	}
}

func containsIdentity(ids []string, id string) bool {
	for _, candidate := range ids {
		if candidate == id {
			return true
		}
	}
	return false
}

func seedBudgetZip(t *testing.T, entries int) []byte {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for i := range entries {
		w, err := z.CreateHeader(&zip.FileHeader{Name: fmt.Sprintf("e%05d.txt", i), Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(bytes.Repeat([]byte("x"), 1024)); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
