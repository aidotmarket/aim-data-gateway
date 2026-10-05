package awsverification

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	core "github.com/aidotmarket/aim-data-gateway/verification"
)

func resignWork(t *testing.T, token string, edit func(map[string]any)) string {
	t.Helper()
	raw, _ := wire.DecodeDocument(strings.Split(token, ".")[1], 64<<10)
	v, e := core.ParseCanonical(raw)
	if e != nil {
		t.Fatal(e)
	}
	m := v.(map[string]any)
	edit(m)
	token, e = signJWS(platformPrivate, platformKey.KID, "aim-scan-spec+jwt", m)
	if e != nil {
		t.Fatal(e)
	}
	return token
}
func editPayload(m map[string]any, edit func(map[string]any)) {
	raw, _ := wire.DecodeDocument(m["payload_b64"].(string), 40<<10)
	v, _ := core.ParseCanonical(raw)
	p := v.(map[string]any)
	edit(p)
	raw, _ = core.Canonical(p)
	m["payload_b64"] = base64.RawURLEncoding.EncodeToString(raw)
	m["spec_hash"] = wire.Digest(raw)
}
func TestAuthenticConsentAndPolicyRefusalsBeforeHEAD(t *testing.T) {
	for name, edit := range map[string]func(map[string]any){
		"unsigned_consent": func(m map[string]any) {
			delete(m, "owner_authorization_id")
		},
		"unknown": func(m map[string]any) {
			m["url"] = "RAW_MARKER"
		},
		"null_consent": func(m map[string]any) {
			m["owner_authorization_id"] = nil
		},
		"wrong_source": func(m map[string]any) {
			m["source_kind"] = "gateway_listing"
		},
		"wrong_runner": func(m map[string]any) {
			m["runner_id"] = connectionID
		},
		"nonce": func(m map[string]any) {
			m["nonce"] = "not-a-nonce"
		},
		"policy": func(m map[string]any) {
			m["minimum_aggregate_occupancy"] = 1
		},
		"cancellation": func(m map[string]any) {
			m["cancellation_signal"] = map[string]any{"kind": "signed_spec_flag", "cancelled": true}
		},
		"accepted_after_issue": func(m map[string]any) {
			m["accepted_at_utc"] = "2099-01-01T00:00:00Z"
		},
		"wrong_platform": func(m map[string]any) {
			m["platform_key_id"] = "other-key"
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.job(t, 1, "scan")
			f.backend.work = resignWork(t, f.backend.work, func(m map[string]any) {
				editPayload(m, edit)
			})
			if f.h.Invoke(ctx) == nil {
				t.Fatal("accepted bad consent")
			}
			if len(f.s3.heads) > 0 || len(f.s3.requests) > 0 {
				t.Fatal("bad consent read")
			}
		})
	}
}
func TestWorkClockSkewAndLifetimeBoundaries(t *testing.T) {
	f := newFixture(t)
	f.job(t, 1, "probe")
	keys := map[string]ed25519.PublicKey{platformKey.KID: platformPrivate.Public().(ed25519.PublicKey)}
	for _, delta := range []time.Duration{-300 * time.Second, 300 * time.Second} {
		if _, e := VerifyWork(f.backend.work, keys, runnerID, runnerID, f.h.Config.Version, f.at.Add(delta)); e != nil {
			t.Fatal("clock boundary", delta, e)
		}
	}
	if _, e := VerifyWork(f.backend.work, keys, runnerID, runnerID, f.h.Config.Version, f.at.Add(-301*time.Second)); e == nil {
		t.Fatal("future issue outside skew")
	}
	for _, hours := range []int{24, 25} {
		token := resignWork(t, f.backend.work, func(m map[string]any) {
			editPayload(m, func(p map[string]any) {
				p["expires_at_utc"] = timestamp(f.at.Add(time.Duration(hours) * time.Hour))
			})
		})
		_, e := VerifyWork(token, keys, runnerID, runnerID, f.h.Config.Version, f.at)
		if (e == nil) != (hours == 24) {
			t.Fatal("lifetime", hours, e)
		}
	}
}
func TestTenthEleventhConcurrentAndAcceptanceDay(t *testing.T) {
	f := newFixture(t)
	for i := 1; i <= 9; i++ {
		j := f.job(t, i, "probe")
		j.Accepted = f.at.Add(-24 * time.Hour)
		if _, e := f.h.Ledger.Admit(ctx, j, f.at); e != nil {
			t.Fatal(e)
		}
		r, _, _ := f.h.Ledger.record(ctx, j.Text("spec_id"))
		if e := f.h.Ledger.Settle(ctx, r, f.at, "reported"); e != nil {
			t.Fatal(e)
		}
	}
	a, b := f.job(t, 10, "scan"), f.job(t, 11, "probe")
	var wg sync.WaitGroup
	var won atomic.Int32
	for _, j := range []wire.ScanJob{a, b} {
		wg.Add(1)
		go func(j wire.ScanJob) {
			defer wg.Done()
			fresh, e := f.h.Ledger.Admit(ctx, j, f.at)
			if fresh && e == nil {
				won.Add(1)
			}
		}(j)
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Fatal("10th/11th race", won.Load())
	}
	f.db.mu.Lock()
	defer f.db.mu.Unlock()
	if _, ok := f.db.items["daily#"+a.Text("listing_id")+"#"+f.at.UTC().Format("2006-01-02")]; !ok {
		t.Fatal("quota used signed consent date")
	}
}
