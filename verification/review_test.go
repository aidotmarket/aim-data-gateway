package verification

import (
	"bytes"
	"context"
	"math"
	"math/big"
	"reflect"
	"strings"
	"testing"
)

func TestHLLEstimateBeyondInt64(t *testing.T) {
	// Python round(0.7213/(1+1.079/128)*128*128/sum(2**-r for 128 registers)).
	for rank, want := range map[uint8]string{40: "100665372716626", 57: "13194411732713590784", 58: "26388823465427181568"} {
		a := newAggregate("integer", 0, testPolicy())
		for i := range a.hll {
			a.hll[i] = rank
		}
		if got := a.estimate().String(); got != want {
			t.Fatalf("rank %d: %s, want %s", rank, got, want)
		}
		for i := 0; i < 10; i++ {
			a.exact[strings.Repeat("x", i)] = struct{}{}
		}
		o := finish([]string{"n"}, []*aggregate{a}, 100)
		raw, e := canonical(o)
		if e != nil || !bytes.Contains(raw, []byte(`"estimate":`+want)) {
			t.Fatalf("estimate canonicalization: %s error=%v", raw, e)
		}
		if _, e = fingerprint(Facts{Objects: []Object{o}}, testPolicy()); e != nil {
			t.Fatal(e)
		}
	}
}

func TestDistinctSuppressionWithoutOverflow(t *testing.T) {
	values := []int64{0, 1, 9, 10, 11, 10000000000000, math.MaxInt64}
	for i := int64(0); i < 100; i++ {
		values = append(values, i)
	}
	for _, e := range values {
		first := new(big.Int).Mul(big.NewInt(e), big.NewInt(908076))
		first.Add(first, big.NewInt(999999)).Quo(first, big.NewInt(1000000))
		last := new(big.Int).Mul(big.NewInt(e), big.NewInt(1091924))
		last.Quo(last, big.NewInt(1000000))
		if last.Cmp(big.NewInt(9)) > 0 {
			last.SetInt64(9)
		}
		want := e > 0 && first.Cmp(last) <= 0
		if ambiguousDistinct(e) != want {
			t.Fatalf("estimate %d suppression differs from arbitrary-precision calculation", e)
		}
	}
}

func TestProbeAllFields(t *testing.T) {
	src := sourceFor([]byte("n\n1\n2\n"), "csv")
	extra := sourceFor([]byte("opaque"), "unsupported")
	extra.members[0].Identity = strings.Repeat("2", 64)
	src.members = append(src.members, extra.members[0])
	src.data[extra.members[0].Identity] = []byte("opaque")
	got, e := Probe(context.Background(), src, testPolicy())
	want := ProbeResult{
		ObjectsDiscovered:       2,
		SizeClass:               "small",
		EstimatedMaxInputTokens: 600,
		SupportedCapabilities:   []string{"complete_traversal", "deterministic_object_order", "fixed_bucket_aggregates", "exact_or_declared_estimated_row_counts"},
	}
	if e != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("Probe = %+v, error=%v; want %+v", got, e, want)
	}
}
