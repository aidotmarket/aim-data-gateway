package verification

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

type vectorMember struct {
	Identity  string `json:"identity"`
	Size      int64  `json:"size"`
	ETag      string `json:"etag"`
	VersionID string `json:"version_id"`
	Format    string `json:"format"`
}

func vectorMembers(in []vectorMember) []Member {
	out := []Member{}
	for _, m := range in {
		out = append(out, Member{Identity: m.Identity, Size: m.Size, ETag: m.ETag, VersionID: m.VersionID, Format: m.Format})
	}
	return out
}
func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestCensusContractVectorsPinned(t *testing.T) {
	raw := read(t, "../contract/census_plan_vectors.json")
	h := sha256.Sum256(raw)
	manifest := string(read(t, "../contract/VECTORS.sha256"))
	if !strings.Contains(manifest, fmt.Sprintf("%x  contract/census_plan_vectors.json\n", h)) {
		t.Fatal("contract vector SHA drift")
	}
	var v struct {
		Plans []struct {
			Seed     string `json:"seed_hex"`
			Literals struct {
				Budget    int64 `json:"planned_processed_bytes"`
				Allowance int64 `json:"archive_allowance_bytes"`
			} `json:"literals"`
			Members []vectorMember `json:"members"`
			Planned []string       `json:"planned"`
			Unread  string         `json:"unread_binding_sha256"`
		} `json:"plans"`
		Forms []struct {
			Tag, Bytes, SHA string
			Length          int64
			Extents         []struct{ Offset, Length int64 }
		} `json:"-"`
		CommitmentForms []struct {
			Tag     string                           `json:"tag"`
			Bytes   string                           `json:"bytes_hex"`
			SHA     string                           `json:"sha256"`
			Length  int64                            `json:"length"`
			Extents []struct{ Offset, Length int64 } `json:"extents"`
		} `json:"commitment_forms"`
		Binding struct {
			Members     []vectorMember `json:"members"`
			Commitments map[string]struct {
				Tag string `json:"tag"`
				SHA string `json:"sha256"`
			} `json:"commitments"`
			Preimage string `json:"preimage_hex"`
			Content  string `json:"content_sha256"`
		} `json:"content_binding"`
	}
	if e := json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	for i, p := range v.Plans {
		seed := [32]byte(unhex(t, p.Seed))
		ms := vectorMembers(p.Members)
		literals := Policy{PlannedProcessedBytes: p.Literals.Budget, ArchiveAllowanceBytes: p.Literals.Allowance}
		got := PlannedReadSet(seed, ms, literals)
		if !reflect.DeepEqual(got, p.Planned) || UnreadBindingSHA256(ms, got) != p.Unread {
			t.Fatal(i, got, p.Planned)
		}
	}
	for _, f := range v.CommitmentForms {
		b := unhex(t, f.Bytes)
		h := sha256.New()
		switch f.Tag {
		case "full":
			h.Write(b)
		case "decoded_prefix":
			writeU64(h, f.Length)
			h.Write([]byte("decoded_prefix"))
			h.Write(b[:f.Length])
		case "zip_entries":
			for _, x := range f.Extents {
				writeU64(h, x.Offset)
				writeU64(h, x.Length)
				h.Write(b[x.Offset : x.Offset+x.Length])
			}
		default:
			t.Fatal(f.Tag)
		}
		if hex.EncodeToString(h.Sum(nil)) != f.SHA {
			t.Fatal(f.Tag)
		}
	}
	commitments := map[string]MemberCommitment{}
	for id, c := range v.Binding.Commitments {
		commitments[id] = MemberCommitment{c.Tag, [32]byte(unhex(t, c.SHA))}
	}
	got, e := ContentBindingV2(vectorMembers(v.Binding.Members), commitments)
	if e != nil || got != v.Binding.Content {
		t.Fatal(got, e)
	}
	preimage := sha256.Sum256(unhex(t, v.Binding.Preimage))
	if hexDigest(preimage) != got {
		t.Fatal("framing drift")
	}
	for _, m := range vectorMembers(v.Binding.Members) {
		if commitments[m.Identity].Tag == "unread" && unreadCommitment(m) != commitments[m.Identity] {
			t.Fatal("unread metadata drift")
		}
	}
}
func TestBindingPlannedUnopenedExcludedAndV1Unchanged(t *testing.T) {
	ms := []Member{{Identity: "a", Size: 10, ETag: "tag", VersionID: "v1", Format: "txt"}, {Identity: "b", Size: 20, ETag: "tag2", Format: "txt"}}
	a := UnreadBindingSHA256(ms, []string{"a"})
	ms[0].ETag = "different"
	if UnreadBindingSHA256(ms, []string{"a"}) != a {
		t.Fatal("planned member included")
	}
	ms[1].ETag = "different"
	if UnreadBindingSHA256(ms, []string{"a"}) == a {
		t.Fatal("unplanned metadata not bound")
	}
	p := censusPolicy()
	p.BindingMethod = "tampered"
	if _, e := p.checked(); e != ErrUnsupported {
		t.Fatal(e)
	}
	if e := os.Setenv("C1_WRITE_BASELINE", ""); e != nil {
		t.Fatal(e)
	}
	TestTableV1Golden(t)
}

func TestBindingCoverageCompletePartialAndInfeasible(t *testing.T) {
	r := newCensusRaw(nil)
	r.members = 10
	r.fully = 10
	c := r.finish()
	if e := ValidateCensusCoverage(*c, 10, 10); e != nil {
		t.Fatal(e)
	}
	r.members = 30
	r.fully = 10
	r.partly = 10
	r.unread = 10
	c = r.finish()
	if e := ValidateCensusCoverage(*c, 30, 20); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*ContentCensus){func(c *ContentCensus) { c.CoverageContent.MembersTotal = 31 }, func(c *ContentCensus) { c.CoverageContent.ReadState.Cells[0].Members = int64(20) }, func(c *ContentCensus) { c.DepthClass = "complete_standard_v1" }, func(c *ContentCensus) { c.Method = "tampered" }} {
		bad := r.finish()
		mutate(bad)
		if e := ValidateCensusCoverage(*bad, 30, 20); e == nil {
			t.Fatal("infeasible bands accepted")
		}
	}
	if e := ValidateCensusCoverage(*c, 30, 10); e == nil {
		t.Fatal("more read than planned")
	}
}
