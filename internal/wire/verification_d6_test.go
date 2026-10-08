package wire

import (
	"encoding/json"
	"os"
	"testing"

	core "github.com/aidotmarket/aim-data-gateway/verification"
)

// Closure spec section 4 and GATE2 :395: exercise the shared hostile corpus
// already byte-pinned by verification/fixtures_test.go at the Go D6 boundary.
func TestValidateD6SharedHostileCorpus(t *testing.T) {
	type d6Case struct {
		Name  string         `json:"name"`
		Value map[string]any `json:"value"`
		valid bool
	}
	raw, err := os.ReadFile("../../verification/testdata/s1590/hostile_d6.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []d6Case `json:"cases"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Cases) == 0 {
		t.Fatal("shared hostile D6 corpus is empty")
	}

	// Use the existing valid scan vector as a control, including the permitted
	// empty-array boundary, so a validator that rejects everything cannot pass.
	v := vector(t, "scan_spec")
	d6, ok := v.Input["d6_b64"].(string)
	if !ok {
		t.Fatal("scan vector is missing d6_b64")
	}
	controlRaw, err := DecodeDocument(d6, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var control, emptyTags map[string]any
	if err := json.Unmarshal(controlRaw, &control); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(controlRaw, &emptyTags); err != nil {
		t.Fatal(err)
	}
	emptyTags["intended_use_tags"] = []any{}
	emptyTags["known_limitation_tags"] = []any{}
	cases := append(corpus.Cases,
		d6Case{Name: "valid_scan_vector", Value: control, valid: true},
		d6Case{Name: "valid_empty_tags", Value: emptyTags, valid: true},
	)
	seen := make(map[string]bool)
	for _, tc := range cases {
		if tc.Name == "" || seen[tc.Name] {
			t.Fatalf("missing or duplicate D6 case name: %q", tc.Name)
		}
		seen[tc.Name] = true
		t.Run(tc.Name, func(t *testing.T) {
			// ValidateD6 requires canonical wire bytes; preserve the corpus values
			// while removing incidental fixture indentation and key ordering.
			raw, err := core.Canonical(tc.Value)
			if err != nil {
				t.Fatal(err)
			}
			_, err = ValidateD6(raw)
			if tc.valid && err != nil {
				t.Fatalf("valid D6 control rejected: %v", err)
			}
			if !tc.valid && err == nil {
				t.Fatal("hostile D6 case accepted")
			}
		})
	}
}
