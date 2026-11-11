package awsverification

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	core "github.com/aidotmarket/aim-data-gateway/verification"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Assemble synthetic detector inputs at runtime so source never contains a token.
func s3aCredential(prefix string) string { return prefix + strings.Repeat("A1B2", 4) }

// Check before logging, returning wire disclosures, or persisting projection vectors.
func s3aAssertNoCredential(t *testing.T, raw []byte) {
	t.Helper()
	for _, prefix := range []string{"AKIA", "ASIA"} {
		if bytes.Contains(raw, []byte(s3aCredential(prefix))) {
			t.Fatal("synthetic credential escaped into output")
		}
	}
}

type s3aSource struct {
	members []core.Member
	data    map[string][]byte
}

func (s *s3aSource) OpenAt(context.Context, string) (core.RandomAccess, error) {
	return nil, core.ErrUnsupported
}
func (s *s3aSource) Members() []core.Member { return s.members }
func (s *s3aSource) Open(ctx context.Context, id string) (io.ReadCloser, error) {
	return s.OpenRange(ctx, id, 0, int64(len(s.data[id])))
}
func (s *s3aSource) OpenRange(_ context.Context, id string, off, n int64) (io.ReadCloser, error) {
	b := s.data[id]
	return io.NopCloser(bytes.NewReader(b[off:min(int64(len(b)), off+n)])), nil
}
func (s *s3aSource) Head(_ context.Context, id string) (core.Member, error) {
	for _, m := range s.members {
		if m.Identity == id {
			return m, nil
		}
	}
	return core.Member{}, core.ErrArtifactChanged
}
func s3aPolicy() core.Policy {
	return core.Policy{CanonicalizationVersion: "python-json-sort-compact-v1", RowCountAlgorithmVersion: "exact-v1", DistinctAlgorithmVersion: "hll-sha256-v1", HistogramVersion: "fixed-buckets-v1", NumericBucketVersion: "fixed-buckets-v1", MinimumAggregateOccupancy: 10, LengthBounds: []int{0, 1, 4, 8, 16, 32, 64, 128, 256}, NumericBoundaries: []float64{-1000, -100, -10, 0, 10, 100, 1000}, GatewayID: "11111111-1111-4111-8111-111111111111", SnapshotHash: strings.Repeat("a", 64), ScanMode: core.ContentCensusV1, BindingMethod: "planned_read_commitment_v2", ContentReadBudgetBytes: 4_000_000_000, PlannedProcessedBytes: 4_000_000_000, ArchiveAllowanceBytes: 64 << 20, ArchiveCaps: core.ArchiveCaps{UncompressedBytes: 256 << 20, Entries: 10000, CompressionRatio: 1000}, PatternVersions: []string{"email_v1", "phone_e164_or_separated_v1", "credential_v1", "licence_families_v1", "simhash64_5shingle_v1"}}
}

type s3aFile struct {
	format string
	body   []byte
}

func s3aPlain(body string) s3aFile {
	if body == "" {
		return s3aFile{"txt", nil}
	}
	return s3aFile{"txt", []byte(body + strings.Repeat(" ", 1024-len(body)))}
}
func s3aZip(t *testing.T, bodies ...string) s3aFile {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for i, s := range bodies {
		w, e := z.CreateHeader(&zip.FileHeader{Name: fmt.Sprintf("e%d.txt", i), Method: zip.Deflate})
		if e != nil {
			t.Fatal(e)
		}
		w.Write([]byte(s))
	}
	if e := z.Close(); e != nil {
		t.Fatal(e)
	}
	data := b.Bytes() // Pad with an archive comment to a fixed snapshot size.
	if len(data) > 65536 {
		t.Fatal("zip too large")
	} // Rebuild comment using EOCD length, preserving offsets.
	end := bytes.LastIndex(data, []byte("PK\x05\x06"))
	data = data[:end+22]
	pad := 65536 - len(data)
	data[end+20] = byte(pad)
	data[end+21] = byte(pad >> 8)
	data = append(data, bytes.Repeat([]byte("p"), pad)...)
	return s3aFile{"zip", data}
}
func s3aCorpus(files []s3aFile) *s3aSource {
	s := &s3aSource{data: map[string][]byte{}}
	for i, f := range files {
		id := fmt.Sprintf("%032x", i+1)
		s.members = append(s.members, core.Member{Identity: id, Size: int64(len(f.body)), Format: f.format, ETag: "fixed"})
		s.data[id] = f.body
	}
	return s
}
func s3aScan(t *testing.T, files []s3aFile) (core.Facts, []byte) {
	t.Helper()
	fixture := newFixture(t)
	fixture.at = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	fixture.s3.objects = map[string][]byte{}
	var objects []Object
	for i, file := range files {
		key := fmt.Sprintf("%032x.%s", i+1, file.format)
		fixture.s3.objects[key] = file.body
		objects = append(objects, Object{Key: key, Size: int64(len(file.body)), Format: file.format, ETag: fixture.s3.liveETag})
	}
	src, err := NewSource(fixture.s3, fixture.h.Config.Bucket, objects)
	if err != nil {
		t.Fatal(err)
	}
	s := &s3aSource{members: src.Members(), data: map[string][]byte{}}
	for _, m := range s.members {
		s.data[m.Identity] = fixture.s3.objects[src.objects[m.Identity].Key]
	}
	v := generateCensusReceipts(t)["receipt_success_complete.json"].(censusReceiptVector)
	j := s3aJob(t, v.Spec, "scan")
	p := s3aPolicy()
	p.Commitments = &collectedCommitments{Commitments: Commitments{Bucket: "fixture", ManifestHash: strings.Repeat("a", 64)}, Digests: map[string]string{}}
	f, e := core.Scan(context.Background(), src, p)
	if e != nil {
		t.Fatal("fixture scan failed")
	}
	factsRaw, err := core.Canonical(f)
	if err != nil {
		t.Fatal("facts encoding failed")
	}
	s3aAssertNoCredential(t, factsRaw)
	commitments := map[string]core.MemberCommitment{}
	for _, m := range s.members {
		c := core.MemberCommitment{Tag: "full", Digest: sha256.Sum256(s.data[m.Identity])}
		if m.Format == "zip" {
			z, _ := zip.NewReader(bytes.NewReader(s.data[m.Identity]), m.Size)
			if len(z.File) > 1 && z.File[len(z.File)-1].UncompressedSize64 > 64<<20 {
				h := sha256.New()
				for _, entry := range z.File[:len(z.File)-1] {
					dataOff, _ := entry.DataOffset()
					start := dataOff - int64(30+len(entry.Name)+len(entry.Extra))
					length := dataOff + int64(entry.CompressedSize64) - start
					binary.Write(h, binary.BigEndian, uint64(start))
					binary.Write(h, binary.BigEndian, uint64(length))
					h.Write(s.data[m.Identity][start : start+length])
				}
				c = core.MemberCommitment{Tag: "zip_entries", Digest: [32]byte(h.Sum(nil))}
			}
		}
		commitments[m.Identity] = c
	}
	binding, e := core.ContentBindingV2(s.members, commitments)
	if e != nil || binding != f.ContentSHA256 {
		t.Fatal("content binding", e)
	}
	if core.UnreadBindingSHA256(s.members, core.PlannedReadSet(p.Seed, s.members, p)) != f.UnreadBindingSHA256 {
		t.Fatal("unread binding")
	}
	payload := map[string]any{"coverage": f.Coverage, "objects": f.Objects, "schema_preview": []any{}, "content_census": f.ContentCensus}
	raw, e := core.Canonical(map[string]any{"facts": payload, "binding_method": p.BindingMethod, "scan_mode": p.ScanMode})
	if e != nil {
		t.Fatal(e)
	}
	if fmt.Sprintf("%x", sha256.Sum256(raw)) != f.FingerprintHash {
		t.Fatal("fingerprint recomputation")
	}
	raw, e = core.Canonical(map[string]any{"census": f.ContentCensus, "coverage": f.Coverage, "fingerprint_hash": f.FingerprintHash})
	if e != nil {
		t.Fatal(e)
	}
	j.ScannerVersion = ScannerVersion
	j.ReceiptKeyID = "fixed-receipt"
	d := report(j, f, j.Issued, j.Issued.Add(time.Second))
	s3aAssertNoCredential(t, canonicalTest(t, d))
	if err := signReceipt(d, censusTestKey(0x42), "scan"); err != nil {
		t.Fatal(err)
	}
	sig, _ := base64.StdEncoding.DecodeString(d["receipt_signature"].(string))
	preimage := canonicalTest(t, receiptBinding(d, "scan"))
	if !ed25519.Verify(censusTestKey(0x42).Public().(ed25519.PublicKey), preimage, sig) {
		t.Fatal("scan signature")
	}
	delete(d, "content_sha256")
	delete(d, "unread_binding_sha256")
	delete(d, "receipt_signature")
	j = s3aJob(t, v.Spec, "probe")
	body, err := fixture.h.scan(context.Background(), &Secret{Private: censusTestKey(0x42), Receipt: receiptID}, j, src)
	if err != nil {
		t.Fatal("fixture probe failed")
	}
	s3aAssertNoCredential(t, body)
	envelope := mapTest(t, body)
	docRaw, err := wire.DecodeDocument(envelope["document_b64"].(string), wire.MaxScanDocument)
	if err != nil {
		t.Fatal(err)
	}
	s3aAssertNoCredential(t, docRaw)
	probeDoc := mapTest(t, docRaw)
	s3aAssertNoCredential(t, canonicalTest(t, probeDoc))
	sig, _ = base64.StdEncoding.DecodeString(probeDoc["receipt_signature"].(string))
	delete(probeDoc, "receipt_signature")
	if !ed25519.Verify(censusTestKey(0x42).Public().(ed25519.PublicKey), canonicalTest(t, probeDoc), sig) {
		t.Fatal("probe signature")
	}
	raw = canonicalTest(t, map[string]any{"report": d, "probe": probeDoc})
	s3aAssertNoCredential(t, raw)
	return f, raw
}
func s3aRepeat(n int, body string) []s3aFile {
	var f []s3aFile
	for range n {
		f = append(f, s3aPlain(body))
	}
	return f
}
func TestS3ADifferentialPairs(t *testing.T) {
	type pair struct {
		name string
		a, b []s3aFile
	}
	var cases []pair
	add := func(name string, a, b []s3aFile) { cases = append(cases, pair{name, a, b}) }
	email := "alice@example.org"
	credential := s3aCredential("AKIA")
	for _, n := range []int{10, 100, 1000} {
		a, b := s3aRepeat(n, "neutral text"), s3aRepeat(n, "neutral text")
		hits := n / 2
		if n == 100 {
			hits = 55
		}
		for i := range n {
			a[i] = s3aPlain(email)
			if i < hits {
				body := email
				if i < n-hits {
					body += " " + email
				}
				b[i] = s3aPlain(body)
			}
		}
		add(fmt.Sprintf("P3a_%d", n), a, b)
	}
	for _, n := range []int{11, 20, 101, 110} {
		a, b := s3aRepeat(n, "neutral text"), s3aRepeat(n, "neutral text")
		mit, unknown := 10, 1
		if n > 100 {
			mit = 100
		}
		if n == 20 || n == 110 {
			unknown = 10
		}
		for i := 0; i < mit; i++ {
			body := "permission is hereby granted free of charge"
			if i < unknown {
				body = "MIT License"
			}
			a[i] = s3aPlain(body)
			b[i] = s3aPlain(body)
		}
		b[mit] = s3aPlain("permission is hereby granted free of charge")
		add(fmt.Sprintf("licence_MIT%d_unknown%d_P%d", mit, unknown, n), a, b)
	}
	for _, n := range []int{0, 8, 98, 197} {
		a, b := s3aRepeat(n, "plain text"), s3aRepeat(n, "plain text")
		a = append(a, s3aZip(t, "alpha"))
		b = append(b, s3aZip(t, "alpha", "bravo"))
		if n == 197 {
			for range 9 {
				a = append(a, s3aZip(t, "text"))
				b = append(b, s3aZip(t, "text"))
			}
		}
		add(fmt.Sprintf("archive_entry_%d_plain", n), a, b)
	}
	for _, empty := range []int{0, 9} {
		a, b := []s3aFile{s3aZip(t, strings.Repeat("x", 700001))}, []s3aFile{s3aZip(t, strings.Repeat("x", 700002))}
		for range empty {
			a = append(a, s3aZip(t))
			b = append(b, s3aZip(t))
		}
		add(fmt.Sprintf("single_entry_bytes_%d_empty_zips", empty), a, b)
	}
	add("archive_credential", []s3aFile{s3aZip(t, credential)}, []s3aFile{s3aZip(t, strings.Repeat("x", len(credential)))})
	a, b := s3aRepeat(10, email), s3aRepeat(10, "bravo@example.org")
	add("email_pair", a, b)
	a, b = s3aRepeat(11, email), s3aRepeat(11, email)
	b[0] = s3aPlain("bravo@example.org")
	add("eleven_identical", a, b)
	a, b = s3aRepeat(10, "neutral text"), s3aRepeat(10, "neutral text")
	a[0] = s3aPlain(credential)
	b[0] = s3aPlain(s3aCredential("ASIA"))
	add("planted_credential", a, b)
	a, b = s3aRepeat(10, strings.Repeat(email+" ", 10)), s3aRepeat(10, strings.Repeat(email+" ", 11))
	add("ten_files_ten_matches", a, b)
	a, b = s3aRepeat(10, ""), s3aRepeat(10, "")
	a = append(a, s3aRepeat(10, email)...)
	b = append(b, s3aRepeat(9, email)...)
	b = append(b, s3aPlain("neutral text"))
	b[10] = s3aPlain(email + " " + email)
	add("twenty_ten_empty_P10", a, b)

	for _, counts := range [][4]int{{50, 44, 50, 43}, {101, 100, 101, 99}} {
		a, b := []string{}, []string{}
		for range counts[0] {
			a = append(a, "plain text")
		}
		for range counts[1] {
			a = append(a, "{}")
		}
		for range counts[2] {
			b = append(b, "plain text")
		}
		for range counts[3] {
			b = append(b, "{}")
		}
		add(fmt.Sprint("CC_r2_F1_", counts), []s3aFile{s3aZip(t, a...)}, []s3aFile{s3aZip(t, b...)})
	}
	for _, counts := range [][6]int{{30, 5, 20, 30, 4, 21}, {30, 10, 1, 30, 9, 2}, {30, 7, 4, 31, 6, 4}} {
		makeFiles := func(text, json, binary int) []s3aFile {
			f := s3aRepeat(text, "plain text")
			f = append(f, s3aRepeat(json, "{}")...)
			body := "\x89PNG\r\n\x1a\n"
			if counts[2] == 4 {
				body = ""
			}
			return append(f, s3aRepeat(binary, body)...)
		}
		add(fmt.Sprint("content_scripts_empty_", counts), makeFiles(counts[0], counts[1], counts[2]), makeFiles(counts[3], counts[4], counts[5]))
	}
	a, b = s3aRepeat(98, "plain text"), s3aRepeat(98, "plain text")
	for i := range a {
		n := 3556
		if i == 0 {
			n = 3642
		}
		a[i].body = []byte(strings.Repeat("x", n))
		b[i].body = []byte(strings.Repeat("x", n))
	}
	add("CC_r3_F4_plain_348574_bytes", append(a, s3aZip(t, strings.Repeat("x", 700001))), append(b, s3aZip(t, strings.Repeat("x", 700002))))
	a, b = nil, nil
	for range 10 {
		a = append(a, s3aZip(t, "alpha", "bravo"))
		b = append(b, s3aZip(t, "alpha", "bravo"))
	}
	b[0] = s3aZip(t, "alpha", "bravo", "charlie")
	add("ten_archives_two_entries", a, b)
	partial := func(entries int) s3aFile {
		var buf bytes.Buffer
		z := zip.NewWriter(&buf)
		for i := 0; i < entries+1; i++ {
			content := strings.Repeat("a", 10/entries)
			if i == entries {
				content = strings.Repeat("z", 70000)
			}
			w, _ := z.CreateHeader(&zip.FileHeader{Name: fmt.Sprintf("e%d.txt", i), Method: zip.Store})
			w.Write([]byte(content))
		}
		z.Close()
		data := buf.Bytes()
		end := bytes.LastIndex(data, []byte("PK\x05\x06"))
		off := int(binary.LittleEndian.Uint32(data[end+16:]))
		for range entries {
			off += 46 + int(binary.LittleEndian.Uint16(data[off+28:]))
		}
		binary.LittleEndian.PutUint32(data[off+24:], 65<<20)
		pad := 80000 - len(data)
		data[end+20] = byte(pad)
		data[end+21] = byte(pad >> 8)
		data = append(data, bytes.Repeat([]byte("p"), pad)...)
		return s3aFile{"zip", data}
	}
	add("CC_r3_F1_partial_one_vs_two", []s3aFile{partial(1)}, []s3aFile{partial(2)})
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !reflect.DeepEqual(s3aCorpus(c.a).members, s3aCorpus(c.b).members) {
				t.Fatal("snapshot changed")
			}
			_, a := s3aScan(t, c.a)
			_, b := s3aScan(t, c.b)
			if !bytes.Equal(a, b) {
				t.Fatalf("within-band disclosure differs\n%s\n%s", a, b)
			}
		})
	}
}
func TestS3AMITPermissionOnlyAndRemovedFindings(t *testing.T) {
	f, raw := s3aScan(t, s3aRepeat(10, "permission is hereby granted free of charge"))
	for _, l := range f.ContentCensus.Inspected.Licences {
		if l.Family == "mit" && l.FilesBand != "1+" {
			t.Fatal(l)
		}
		if l.Family == "unknown_licence_text" && l.FilesBand != "0" {
			t.Fatal(l)
		}
	}
	for _, key := range []string{`"duplicates":`, `"empty_files":`, `"garbage_files":`} {
		if bytes.Contains(raw, []byte(key)) {
			t.Fatal("removed finding", key)
		}
	}
}

// Boundary outputs may change only the named bands and their derived fingerprint.
func TestS3ABoundaryPairs(t *testing.T) {
	for _, edge := range []int{10, 100, 1000} {
		t.Run(fmt.Sprint(edge), func(t *testing.T) {
			a, b := s3aRepeat(edge+1, "neutral text"), s3aRepeat(edge+1, "neutral text")
			for i := range edge {
				b[i] = s3aPlain("alice@example.org")
				if i < edge-1 {
					a[i] = s3aPlain("alice@example.org")
				}
			}
			fa, ra := s3aScan(t, a)
			fb, rb := s3aScan(t, b)
			if fa.ContentCensus.Inspected.Detectors[0].FilesWithHitsBand == fb.ContentCensus.Inspected.Detectors[0].FilesWithHitsBand {
				t.Fatal("missing boundary")
			}
			if bytes.Equal(ra, rb) {
				t.Fatal("boundary hidden")
			}
			var scrub func(any)
			scrub = func(v any) {
				switch x := v.(type) {
				case map[string]any:
					delete(x, "fingerprint_hash")
					if x["class"] == "email" {
						delete(x, "files_with_hits_band")
						delete(x, "hit_count_band")
					}
					for _, v := range x {
						scrub(v)
					}
				case []any:
					for _, v := range x {
						scrub(v)
					}
				}
			}
			va, _ := core.ParseCanonical(ra)
			vb, _ := core.ParseCanonical(rb)
			scrub(va)
			scrub(vb)
			ca, _ := core.Canonical(va)
			cb, _ := core.Canonical(vb)
			if !bytes.Equal(ca, cb) {
				t.Fatal("boundary changed another disclosure")
			}
		})
	}
}

// Backend consumes these two gateway-generated differential pairs through its
// public projection. They contain the actual normalized report/probe encodings.
func TestS3AProjectionVectors(t *testing.T) {
	cases := map[string][2][]s3aFile{
		"archive_credential": {[]s3aFile{s3aZip(t, s3aCredential("AKIA"))}, []s3aFile{s3aZip(t, "neutral archive text")}},
		"licence_overlap":    {s3aRepeat(11, "MIT License"), s3aRepeat(11, "MIT License")},
	}
	pair := cases["licence_overlap"]
	pair[1][0] = s3aPlain("copyright")
	cases["licence_overlap"] = pair
	out := map[string]any{}
	for name, pair := range cases {
		_, a := s3aScan(t, pair[0])
		_, b := s3aScan(t, pair[1])
		if !bytes.Equal(a, b) {
			t.Fatal(name, "differential drift")
		}
		left, _ := core.ParseCanonical(a)
		right, _ := core.ParseCanonical(b)
		out[name] = map[string]any{"left": left, "right": right}
	}
	raw := append(canonicalTest(t, out), '\n')
	s3aAssertNoCredential(t, raw)
	path := filepath.Join(censusWireDir, "s3a_projection_pairs.json")
	if *updateCensusWire {
		if err := os.WriteFile(path, raw, 0644); err != nil {
			t.Fatal(err)
		}
	}
	stored, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, stored) {
		t.Fatal("projection vector drift", err)
	}
}

func TestS3AP1BoundaryCoupling(t *testing.T) {
	makeFiles := func(text, binary int) []s3aFile {
		f := s3aRepeat(text, "plain text")
		f = append(f, s3aRepeat(10, "{}")...)
		return append(f, s3aRepeat(binary, "\x89PNG\r\n\x1a\n")...)
	}
	a, ra := s3aScan(t, makeFiles(30, 9))
	b, rb := s3aScan(t, makeFiles(29, 10))
	if a.ContentCensus.Inspected.Encodings.State != "suppressed_low_occupancy" || a.ContentCensus.Inspected.Scripts.State != "suppressed_low_occupancy" || b.ContentCensus.Inspected.Encodings.State != "checked" || b.ContentCensus.Inspected.Scripts.State != "checked" || b.ContentCensus.Inspected.Scripts.Population != int64(49) {
		t.Fatal("P1 merge switch", a.ContentCensus.Inspected, b.ContentCensus.Inspected)
	}
	var scrub func(any)
	scrub = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for _, k := range []string{"fingerprint_hash", "by_content_class", "encodings", "scripts"} {
				delete(x, k)
			}
			for _, v := range x {
				scrub(v)
			}
		case []any:
			for _, v := range x {
				scrub(v)
			}
		}
	}
	va, _ := core.ParseCanonical(ra)
	vb, _ := core.ParseCanonical(rb)
	scrub(va)
	scrub(vb)
	ca, _ := core.Canonical(va)
	cb, _ := core.Canonical(vb)
	if !bytes.Equal(ca, cb) {
		t.Fatal("P1 boundary changed other fields")
	}
}

func s3aJob(t *testing.T, v censusSpecVector, variant string) wire.ScanJob {
	t.Helper()
	raw, err := wire.DecodeDocument(strings.Split(v.Token, ".")[1], 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	env := mapTest(t, raw)
	env["variant"] = variant
	if variant == "probe" {
		delete(env, "d6_b64")
		delete(env, "d6_hash")
	}
	editPayload(env, func(p map[string]any) {
		p["planned_processed_bytes"] = censusR1BudgetBytes
		if variant == "probe" {
			allowed := map[string]bool{}
			for _, k := range strings.Fields(probeFields + " scan_mode binding_method planned_processed_bytes") {
				allowed[k] = true
			}
			for k := range p {
				if !allowed[k] {
					delete(p, k)
				}
			}
			p["probe_id"] = "11111111-1111-4111-8111-111111111111"
		}
	})
	at, _ := time.Parse(time.RFC3339, v.Now)
	j, err := VerifyWork(signCensusSpec(t, env), map[string]ed25519.PublicKey{censusPlatformKID: censusTestKey(0x24).Public().(ed25519.PublicKey)}, v.GatewayID, v.RunnerID, v.RunnerVersion, at)
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func TestS3AExactCoverageAndPlainBytes(t *testing.T) {
	files := append(s3aRepeat(8, "plain text"), s3aZip(t, "private archive text"))
	f, _ := s3aScan(t, files)
	var stored, plain int64
	for _, file := range files {
		stored += int64(len(file.body))
		if file.format != "zip" {
			plain += int64(len(file.body))
		}
	}
	if f.ContentCensus.CoverageContent.StoredBytesRead != stored || f.ContentCensus.CoverageContent.ProcessedBytes != plain {
		t.Fatal("coverage must use snapshot stored sizes and plain processed bytes", f.ContentCensus.CoverageContent)
	}
}
