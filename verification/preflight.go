package verification

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// CensusPreflight is the closed S3-A free-check disclosure. Exact inputs stay local.
type CensusPreflight struct {
	FloorResult         string `json:"floor_result"`
	AdmissionResult     string `json:"admission_result"`
	ArchiveRequestsBand string `json:"archive_requests_band"`
}

func (p *CensusPreflight) UnmarshalJSON(b []byte) error {
	type plain CensusPreflight
	var v plain
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(&v); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrUnsupported
	}
	if v.FloorResult != "meets_floor" && v.FloorResult != "meets_floor_unknown_expansion" && v.FloorResult != "below_floor" || v.AdmissionResult != "within_bounds" && v.AdmissionResult != "over_bound" {
		return ErrUnsupported
	}
	valid := v.ArchiveRequestsBand == "over_bound"
	for _, n := range []int64{0, 1, 10, 100, 1000, 2000, 4000, 8000, 16000, 32000, 64000, 128000, 256000, 512000} {
		if archiveRequestsBand(n) == v.ArchiveRequestsBand {
			valid = true
		}
	}
	if !valid {
		return ErrUnsupported
	}
	*p = CensusPreflight(v)
	return nil
}
func archiveRequestsBand(n int64) string {
	if n < 1000 {
		return countBand(n)
	}
	for lo := int64(1000); lo < 1024000; lo *= 2 {
		if n < lo*2 {
			return fmt.Sprintf("%d-%d", lo, lo*2-1)
		}
	}
	return "over_bound"
}

// NewCensusPreflight uses a ceiling comparison to avoid multiplying stored bytes.
func NewCensusPreflight(total, known, unknown, members, possible, requests int64) *CensusPreflight {
	p := &CensusPreflight{FloorResult: "meets_floor", AdmissionResult: "within_bounds", ArchiveRequestsBand: archiveRequestsBand(requests)}
	floor := total / 10
	if total%10 != 0 {
		floor++
	}
	if known < floor {
		p.FloorResult = "meets_floor_unknown_expansion"
		if unknown < floor-known {
			p.FloorResult = "below_floor"
		}
	}
	// Compare before multiplication; all counts originate in bounded snapshots/directories.
	available := MaxMemoryBytes - 16*(4<<20)
	if members > available/1024 || possible > (available-members*1024)/384 {
		p.AdmissionResult = "over_bound"
	}
	return p
}
