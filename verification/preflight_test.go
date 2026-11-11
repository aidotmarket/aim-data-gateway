package verification

import (
	"encoding/json"
	"testing"
)

func TestS3APreflightBandsFloorAdmissionAndClosedObject(t *testing.T) {
	for _, tc := range []struct {
		n    int64
		band string
	}{{0, "0"}, {1, "1-9"}, {9, "1-9"}, {10, "10-99"}, {99, "10-99"}, {100, "100-999"}, {999, "100-999"}, {1000, "1000-1999"}, {1999, "1000-1999"}, {2000, "2000-3999"}, {512000, "512000-1023999"}, {1023999, "512000-1023999"}, {1024000, "over_bound"}} {
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
