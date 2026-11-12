package verification

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Assemble synthetic detector inputs at runtime so source never contains a token.
func fixtureAccessID() string { return "AKIA" + strings.Repeat("A1B2", 4) }
func fixtureSecret() string   { return strings.Repeat("aB3cD4eF5gH6iJ7k", 3) }

func inspectChunks(b []byte, name string, n int) fileFinding {
	f := newFileInspection(name)
	for start := 0; start < len(b); start += n {
		f.Write(b[start:min(len(b), start+n)])
	}
	return f.finish()
}
func TestDetectorsBoundaryAndShortReadDeterminism(t *testing.T) {
	data := []byte(strings.Repeat("prefix words ", 200) + "\ncontact test@example.org +1-555-0100 " + fixtureAccessID() + " secret=" + fixtureSecret() + "\nMIT License\n" + strings.Repeat(" words", 200))
	want := inspectChunks(data, "x.py", len(data))
	for _, value := range []string{fixtureAccessID(), fixtureSecret()} {
		if strings.Contains(fmt.Sprintf("%+v", want), value) {
			t.Fatal("synthetic credential escaped into detector output")
		}
	}
	if want.hits != [3]int64{1, 1, 2} || !want.licences["mit"] {
		t.Fatalf("planted counts: %+v", want)
	}
	for _, n := range []int{1, 3, 17, 511, 512, 513, 4096, 65536, 1 << 20} {
		got := inspectChunks(data, "x.py", n)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("chunk %d hits=%v want=%v", n, got.hits, want.hits)
		}
	}
}
func TestPhoneExclusionsAndFalsePositives(t *testing.T) {
	negatives := []string{"12345678", "0x1234567890abcdef", "2026-11-07T12:34:56", "550e8400-e29b-41d4-a716-446655440000", "version 10.20.300.400", "int value_12345678 = 42;", "var hex = 0x1234abcd;"}
	hits := int64(0)
	for _, s := range negatives {
		f := inspectChunks([]byte(s), "x.cpp", 1)
		hits += f.hits[1]
	}
	if hits != 0 {
		t.Fatalf("code false positives %d/%d", hits, len(negatives))
	}
	t.Logf("phone code false positives: %d/%d", hits, len(negatives))
	for _, s := range []string{"+15550100", "+44 20 7946 0958", "(020) 7946-0958", "555-012-3456"} {
		f := inspectChunks([]byte(s), "x", 1)
		if f.hits[1] != 1 {
			t.Fatal(s, f.hits)
		}
	}
}
func TestFrozenLicenceFamilies(t *testing.T) {
	samples := []string{"MIT License", "Apache License Version 2.0", "BSD-3-Clause", "GNU GENERAL PUBLIC LICENSE", "GNU LESSER GENERAL PUBLIC LICENSE", "GNU AFFERO GENERAL PUBLIC LICENSE", "Mozilla Public License", "CC-BY-4.0", "CC-BY-SA-4.0", "CC-BY-NC-4.0", "CC0", "Unlicense", "all rights reserved", "copyright unknown"}
	for i, s := range samples {
		f := inspectChunks([]byte(s), "x", 1)
		if !f.licences[licencePatterns[i].family] {
			t.Fatal(s, f.licences)
		}
	}
}
func TestEncodingAndScripts(t *testing.T) {
	for _, tc := range []struct{ s, encoding, script string }{{"hello", "utf8", "latin"}, {"\ufeffhello", "utf8_bom", "latin"}, {"\xff\xfeh\x00i\x00", "utf16", "latin"}, {"Привет", "utf8", "cyrillic"}, {"你好", "utf8", "cjk"}, {"مرحبا", "utf8", "arabic"}, {"\x00\x01", "binary", "non_text"}} {
		f := inspectChunks([]byte(tc.s), "x", 1)
		if f.encoding != tc.encoding || f.script != tc.script {
			t.Fatal(tc, f)
		}
	}
}
func TestRehearsalPlantedTruthShapes(t *testing.T) {
	// Generated from the read-only authority's recorded counts: 30 planted files
	// and 16 exact pairs. One credential plant contains an access ID and a secret,
	// so it contributes two matches but one files_with_hits observation.
	var agg inspection
	for i := 0; i < 15360; i++ {
		body := fmt.Sprintf("generated distinct body %d\n", i)
		if i%512 == 11 {
			k := i / 512
			body += fmt.Sprintf("contact tester%03d@example.%s phone +1-555-01%02d %s secret=%s%04d\n", k, []string{"org", "com"}[k%2], k%100, fixtureAccessID(), fixtureSecret(), k)
		}
		if i%1000 == 7 {
			body = fmt.Sprintf("generated distinct body %d\n", i-1)
		}
		agg.addFile(inspectChunks([]byte(body), "x.txt", 17))
	}
	if agg.hitFiles != [3]int64{30, 30, 30} || agg.hits != [3]int64{30, 30, 60} {
		t.Fatal(agg.hitFiles, agg.hits)
	}

}

// The prefilter is an optimisation only; the frozen regexes decide matches.
func TestLicencePrefilterMatchesFrozenPatterns(t *testing.T) {
	for _, sample := range []string{
		"Permission is hereby granted free of charge", "MIT Licenſe", "Apache License Version 2.0",
		"redistribution and use in source and binary forms", "BSD-2-Clause", "GNU GENERAL PUBLIC LICENSE",
		"GNU LESSER GENERAL PUBLIC LICENSE", "GNU AFFERO GENERAL PUBLIC LICENSE", "Mozilla Public License",
		"CC-BY-4.0", "Creative Commons Attribution 4", "CC-BY-SA", "Attribution-ShareAlike",
		"CC-BY-NC", "Attribution-NonCommercial", "CC0", "Unlicense",
		"free and unencumbered software released into the public domain", "ALL RIGHTS RESERVED",
		"confidential and proprietary", "copyright", "license", "licence", "unrelated text",
		"SPDX-License-Identifier: GPL-3.0", "SPDX-License-Identifier: LGPL-3.0",
		"SPDX-License-Identifier: AGPL-3.0", "SPDX-License-Identifier: MPL-2.0",
	} {
		for _, body := range []string{sample, strings.ToUpper(sample), "prefix\xff " + sample + " suffix"} {
			f := newFileInspection("x")
			f.patterns([]byte(body), 0, len(body))
			for _, pattern := range licencePatterns {
				if got, want := f.licences[pattern.family], pattern.pattern.MatchString(body); got != want {
					t.Fatalf("%s in %q: got %t want %t", pattern.family, body, got, want)
				}
			}
		}
	}
}

func TestEmailPrefilterMatchesFrozenPattern(t *testing.T) {
	for _, body := range []string{"simple@example.org", "two@example.org next@example.com", "a@K.org", "ſ@example.org", strings.Repeat("K", 64) + "@" + strings.Repeat("K", 178) + ".org", "no email here"} {
		if got, want := emailLocations([]byte(body)), emailPattern.FindAllIndex([]byte(body), -1); !reflect.DeepEqual(got, want) {
			t.Fatalf("%q: got %v want %v", body, got, want)
		}
		want := inspectChunks([]byte(body), "x.txt", len(body))
		for _, n := range []int{1, 3, 17, 511, 512, 513, 1024} {
			if got := inspectChunks([]byte(body), "x.txt", n); !reflect.DeepEqual(got, want) {
				t.Fatalf("chunk %d in %q", n, body)
			}
		}
	}
}
