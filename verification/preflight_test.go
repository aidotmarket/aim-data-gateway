package verification

import (
	"encoding/json"
	"testing"
)

func TestS3APreflightBandsFloorAdmissionAndClosedObject(t *testing.T) {
	for _, tc := range []struct {
		n    int64
		band string
	}{{0, "0"}, {1, "1-9"}, {9, "1-9"}, {10, "10-99"}, {99, "10-99"}, {100, "100-999"}, {999, "100-999"}, {1000, "1000-1999"}, {1999, "1000-1999"}, {2000, "2000-3999"}, {512000, "512000-1023999"}, {1023999, "512000-1023999"}, {1024000, ""}} {
		if got := archiveRequestsBand(tc.n); got != tc.band {
			t.Fatal(tc, got)
		}
	}
	for _, tc := range []struct {
		total, known, unknown int64
		want                  string
	}{{100, 10, 0, "meets_floor"}, {101, 10, 1, "meets_floor_unknown_expansion"}, {101, 9, 1, "below_floor"}, {0, 0, 0, "meets_floor"}, {1 << 62, 1 << 61, 0, "meets_floor"}} {
		if got := NewCensusPreflight(tc.total, tc.known, tc.unknown, 1, 1, 0); got.FloorResult != tc.want {
			t.Fatal(tc, got)
		}
	}
	for _, tc := range []struct {
		members, possible int64
		want              string
	}{{1, 1, "within_bounds"}, {800, 800 + 800*10000, "over_bound"}, {0, (MaxMemoryBytes - 16*(4<<20)) / 384, "within_bounds"}, {0, (MaxMemoryBytes-16*(4<<20))/384 + 1, "over_bound"}} {
		if got := NewCensusPreflight(1, 1, 0, tc.members, tc.possible, 0); got.AdmissionResult != tc.want {
			t.Fatal(tc, got)
		}
	}
	valid := `{"floor_result":"meets_floor","admission_result":"within_bounds","archive_requests_band":"0"}`
	for _, raw := range []string{valid, valid[:len(valid)-1] + `,"known_processed_bytes":0}`, `{}`, `{"floor_result":"unknown","admission_result":"within_bounds","archive_requests_band":"0"}`, `{"floor_result":"meets_floor","admission_result":"within_bounds","archive_requests_band":"1000+"}`} {
		var p CensusPreflight
		err := json.Unmarshal([]byte(raw), &p)
		if (err == nil) != (raw == valid) {
			t.Fatal(raw, err)
		}
	}
}

func TestPreflightRequestLimitWire(t *testing.T) {
	for _, requests := range []int64{1023999, 1024000} {
		for _, possible := range []int64{1, MaxMemoryBytes} {
			p := NewCensusPreflight(1, 1, 0, 1, possible, requests)
			raw, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]any
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			band, present := fields["archive_requests_band"]
			if present != (requests < 1024000) || present && band != "512000-1023999" {
				t.Fatal(string(raw))
			}
			wantAdmission := "within_bounds"
			if requests >= 1024000 || possible == MaxMemoryBytes {
				wantAdmission = "over_bound"
			}
			if p.AdmissionResult != wantAdmission {
				t.Fatal(string(raw))
			}
			var decoded CensusPreflight
			if err := json.Unmarshal(raw, &decoded); err != nil || decoded != *p {
				t.Fatal(string(raw), err)
			}
		}
	}
	for _, tc := range []struct {
		admission, suffix string
		valid             bool
	}{
		{"within_bounds", "", false}, {"over_bound", "", true},
		{"within_bounds", `,"archive_requests_band":"over_bound"`, false},
		{"over_bound", `,"archive_requests_band":"over_bound"`, false},
		{"over_bound", `,"archive_requests_band":null`, false},
		{"over_bound", `,"archive_requests_band":""`, false},
		{"over_bound", `,"archive_requests_band":"0"`, true},
	} {
		raw := `{"floor_result":"meets_floor","admission_result":"` + tc.admission + `"` + tc.suffix + `}`
		var decoded CensusPreflight
		if err := json.Unmarshal([]byte(raw), &decoded); (err == nil) != tc.valid {
			t.Fatal(raw, err)
		}
	}
}
