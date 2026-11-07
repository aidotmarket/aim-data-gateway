package verification

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"hash"
	"strings"
)

// MemberCommitment is local evidence, never a per-member wire field under v2.
type MemberCommitment struct {
	Tag    string
	Digest [32]byte
}

func writeU64(h hash.Hash, n int64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(n))
	h.Write(b[:])
}
func writeBytes(h hash.Hash, b []byte) { writeU64(h, int64(len(b))); h.Write(b) }
func metadata(h hash.Hash, m Member) {
	writeU64(h, m.Size)
	writeBytes(h, []byte(strings.Trim(m.ETag, "\"")))
	writeBytes(h, []byte(m.VersionID))
}
func unreadCommitment(m Member) MemberCommitment {
	h := sha256.New()
	metadata(h, m)
	return MemberCommitment{"unread", [32]byte(h.Sum(nil))}
}
func decodedCommitment(b []byte) MemberCommitment {
	h := sha256.New()
	writeU64(h, int64(len(b)))
	h.Write([]byte("decoded_prefix"))
	h.Write(b)
	return MemberCommitment{"decoded_prefix", [32]byte(h.Sum(nil))}
}

// UnreadBindingSHA256 binds members outside the plan, in snapshot order. Lengths
// are UTF-8 byte lengths; etags are unquoted. Planned-but-unopened are excluded.
func UnreadBindingSHA256(members []Member, planned []string) string {
	in := map[string]bool{}
	for _, id := range planned {
		in[id] = true
	}
	h := sha256.New()
	for _, m := range members {
		if supported(m.Format) || in[m.Identity] {
			continue
		}
		writeBytes(h, []byte(m.Identity))
		metadata(h, m)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ContentBindingV2 retains v1's table framing. Census fields use u64be lengths
// for tag and digest, so no concatenation of different typed fields can collide.
func ContentBindingV2(members []Member, commitments map[string]MemberCommitment) (string, error) {
	h := sha256.New()
	for _, m := range members {
		c, ok := commitments[m.Identity]
		if !ok {
			return "", ErrArtifactChanged
		}
		writeBytes(h, []byte(m.Identity))
		writeU64(h, m.Size)
		if supported(m.Format) {
			if c.Tag != "full" {
				return "", ErrArtifactChanged
			}
			h.Write(c.Digest[:])
			continue
		}
		switch c.Tag {
		case "full", "zip_entries", "decoded_prefix", "unread":
		default:
			return "", ErrUnsupported
		}
		writeBytes(h, []byte(c.Tag))
		writeBytes(h, c.Digest[:])
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ValidateCensusCoverage checks the public bands against the exact counts the
// backend derives from the snapshot and plan. It needs no per-member outcomes.
func ValidateCensusCoverage(c ContentCensus, members, planned int64) error {
	if members < 0 || planned < 0 || planned > members || c.Method != ContentCensusV1 || !containsCount(c.Inventory.Members, members) || !containsCount(c.CoverageContent.MembersTotal, members) {
		return ErrArtifactChanged
	}
	switch c.DepthClass {
	case "content_census_complete_v1":
		if planned != members || c.CoverageContent.Sampled {
			return ErrArtifactChanged
		}
	case "content_census_sampled_v1":
		if !c.CoverageContent.Sampled {
			return ErrArtifactChanged
		}
	default:
		return ErrUnsupported
	}
	p := c.CoverageContent.ReadState
	if p.State == suppressed || p.State == "not_checked" {
		return nil
	}
	if p.State != "checked" || !containsCount(p.Population, members) {
		return ErrArtifactChanged
	}
	var total, read, unread int64
	seen := map[string]bool{}
	for _, cell := range p.Cells {
		n, ok := exactCount(cell.Members)
		if !ok || n < 10 || n > members-total || seen[cell.Class] {
			return ErrArtifactChanged
		}
		seen[cell.Class] = true
		total += n
		switch cell.Class {
		case "fully_read", "partly_read", "other":
			read += n
		case "unread":
			unread += n
		default:
			return ErrUnsupported
		}
	}
	if total != members || read > planned || unread < members-planned {
		return ErrArtifactChanged
	}
	return nil
}
func exactCount(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case json.Number:
		x, e := n.Int64()
		return x, e == nil
	}
	return 0, false
}
func containsCount(v any, n int64) bool {
	if value, ok := exactCount(v); ok {
		return value == n
	}
	switch v {
	case "0":
		return n == 0
	case "1-9":
		return n >= 1 && n <= 9
	case "10-99":
		return n >= 10 && n <= 99
	case "100-999":
		return n >= 100 && n <= 999
	case "1000+":
		return n >= 1000
	}
	return false
}
