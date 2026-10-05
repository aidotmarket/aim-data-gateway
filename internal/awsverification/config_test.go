package awsverification

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aidotmarket/aim-data-gateway/internal/wire"
)

func configEnv() map[string]string {
	return map[string]string{
		EnvConnection: connectionID,
		EnvBucket:     "fixture-bucket",
		EnvRegion:     "eu-north-1",
		EnvScope:      `{"keys":[],"prefixes":["workspace/approval/"]}`,
		EnvSecret:     "secret",
		EnvTable:      "table",
		EnvToken:      base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)),
		EnvVersion:    "0.3.0",
		EnvDigest:     "sha256:" + strings.Repeat("a", 64),
		EnvAPI:        APIBaseURL,
		EnvLogGroup:   "group",
		EnvMemory:     "1769",
	}
}
func TestConfigRegionsAndScope(t *testing.T) {
	env := configEnv()
	if _, e := ParseConfig(func(k string) string { return env[k] }); e != nil {
		t.Fatal(e)
	}
	for k, values := range map[string][]string{
		EnvRegion: {"us-east-2", "cn-north-1", ""},
		EnvAPI:    {"https://api.ai.market/", "http://api.ai.market", "https://other.example"},
		EnvScope:  {`{"keys":["*"],"prefixes":[]}`, `{"keys":[],"prefixes":[""]}`, `{"keys":[],"prefixes":["ok"],"url":"evil"}`},
		EnvMemory: {"128", "3009"},
	} {
		for _, v := range values {
			env := configEnv()
			env[k] = v
			if _, e := ParseConfig(func(k string) string {
				return env[k]
			}); e == nil {
				t.Fatal("bad config allowed", k, v)
			}
		}
	}
	env = configEnv()
	scope := Scope{Keys: make([]string, 51), Prefixes: []string{}}
	for i := range scope.Keys {
		scope.Keys[i] = "key"
	}
	b, _ := json.Marshal(scope)
	env[EnvScope] = string(b)
	if _, e := ParseConfig(func(k string) string {
		return env[k]
	}); e == nil {
		t.Fatal("scope ceiling")
	}
	c := Config{Scope: Scope{Keys: []string{"exact.csv"}, Prefixes: []string{"workspace/approval/"}}}
	if !c.permits("exact.csv") || !c.permits("workspace/approval/data.csv") || c.permits("workspace/other/data.csv") || c.permits("exact.csv/evil") {
		t.Fatal("scope broadened")
	}
}

func TestInvalidRegistrationTokenRefusesWithoutLedgerWrites(t *testing.T) {
	for _, token := range []string{"", "invalid!", base64.RawURLEncoding.EncodeToString(make([]byte, 31)), base64.RawURLEncoding.EncodeToString(make([]byte, 33)), base64.StdEncoding.EncodeToString(make([]byte, 32))} {
		t.Run(token, func(t *testing.T) {
			f := newFixture(t)
			env := configEnv()
			env[EnvToken] = token
			if _, err := ParseConfig(func(k string) string { return env[k] }); err == nil {
				t.Fatal("invalid registration token accepted by config parser")
			}
			// Direct bootstrap callers also refuse before the durable lease.
			f.h.Config.Token = token
			if _, err := Bootstrap(ctx, f.h.Config, f.h.Ledger, f.secrets, f.backend, f.at); err == nil {
				t.Fatal("invalid registration token accepted by bootstrap")
			}
			if f.db.puts != 0 || len(f.db.items) != 0 || f.secrets.saves != 0 || len(f.backend.calls) != 0 {
				t.Fatal("invalid token reached durable state or registration")
			}
		})
	}
}
func TestIntegerMixedSizeAndMemberCeilings(t *testing.T) {
	for _, a := range [][]Object{{{Format: "csv", Size: 6_000_000_000}}, {{Format: "parquet", Size: 1_000_000_000}}, {{Format: "csv", Size: 3_000_000_000}, {Format: "parquet", Size: 500_000_000}}} {
		if e := AdmitSize(a); e != nil {
			t.Fatal("boundary refused", e)
		}
		a[len(a)-1].Size++
		if AdmitSize(a) == nil {
			t.Fatal("one byte beyond shared size allowed")
		}
	}
	if AdmitSize([]Object{{Format: "zip", Size: 1}}) == nil {
		t.Fatal("unsupported format admitted")
	}
	a := make([]Object, MaxMembers)
	for i := range a {
		a[i] = Object{Format: "csv", Size: 1}
	}
	if e := AdmitSize(a); e != nil {
		t.Fatal(e)
	}
	if AdmitSize(append(a, Object{Format: "csv"})) == nil {
		t.Fatal("17034 admitted")
	}
	if WorstReportSize(MaxMembers) != 2097115 || WorstReportSize(MaxMembers+1) <= MaxReport {
		t.Fatal("worst body calculation")
	}
}
func TestActualSerializedReportBounds(t *testing.T) {
	f := newFixture(t)
	j := f.job(t, 1, "scan")
	s, e := Bootstrap(ctx, f.h.Config, f.h.Ledger, f.secrets, f.backend, f.at)
	if e != nil {
		t.Fatal(e)
	}
	digests := make([]string, MaxMembers)
	for i := range digests {
		digests[i] = strings.Repeat("a", 64)
	}
	// Build a canonical document exactly at the decoded cap, including signature.
	d := map[string]any{"padding": ""}
	body, e := encodeReport(s, j, "scan", d, digests)
	if e != nil {
		t.Fatal(e)
	}
	var env map[string]any
	json.Unmarshal(body, &env)
	raw, _ := wire.DecodeDocument(env["document_b64"].(string), wire.MaxScanDocument)
	d = map[string]any{"padding": strings.Repeat("a", wire.MaxScanDocument-len(raw))}
	body, e = encodeReport(s, j, "scan", d, digests)
	if e != nil || len(body) != WorstReportSize(MaxMembers) {
		t.Fatal("actual worst body", len(body), e)
	}
	d["padding"] = d["padding"].(string) + "a"
	if _, e = encodeReport(s, j, "scan", d, digests); e == nil {
		t.Fatal("decoded document cap")
	}
	if _, e = encodeReport(s, j, "scan", map[string]any{}, append(digests, strings.Repeat("b", 64))); e == nil {
		t.Fatal("member ceiling")
	}
	r := Record{Job: j, Pickup: f.at.Unix()}
	if f.h.Ledger.Commit(ctx, r, bytes.Repeat([]byte{'x'}, MaxReport+1), f.at) == nil {
		t.Fatal("outbox body cap")
	}
}
