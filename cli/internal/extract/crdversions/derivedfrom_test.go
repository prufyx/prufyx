// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"fmt"
	"testing"
)

func targetWithFloor(minFrom, derivedFrom string) []byte {
	extra := ""
	if derivedFrom != "" {
		extra = fmt.Sprintf(`"derivedFrom":%q,`, derivedFrom)
	}
	return []byte(fmt.Sprintf(`{"schema":%q,"target":{"project":"p","name":"P","repo":"github.com/o/p","component":"pkg:github/o/p","factProject":"p","tagPrefixes":["v"],"minFrom":%q,%s"paths":[{"path":"crds/a.yaml"}],"exclude":[]}}`, TargetSchema, minFrom, extra))
}

// derivedFrom is an explicit optional field: absent it equals minFrom and is
// not marked set; present it may equal or lie below minFrom, never above.
func TestDerivedFromField(t *testing.T) {
	tg, err := LoadTarget("target-p.json", targetWithFloor("1.9", ""))
	if err != nil || tg.DerivedFrom != tg.MinFrom || tg.DerivedFromSet {
		t.Fatalf("absent: %+v %v", tg, err)
	}
	tg, err = LoadTarget("target-p.json", targetWithFloor("1.9", "1.4"))
	if err != nil || tg.DerivedFrom != [2]int{1, 4} || !tg.DerivedFromSet || tg.MinFrom != [2]int{1, 9} {
		t.Fatalf("lower: %+v %v", tg, err)
	}
	if tg, err = LoadTarget("target-p.json", targetWithFloor("1.9", "1.9")); err != nil || !tg.DerivedFromSet {
		t.Fatalf("equal: %+v %v", tg, err)
	}
	if tg, err = LoadTarget("target-p.json", targetWithFloor("2.0", "1.30")); err != nil || tg.DerivedFrom != [2]int{1, 30} {
		t.Fatalf("across a major: %+v %v", tg, err)
	}
	for name, c := range map[string][2]string{
		"above minFrom":      {"1.9", "1.10"},
		"above across major": {"1.9", "2.0"},
		"not a line":         {"1.9", "1.x"},
		"padded":             {"1.9", "1.09"},
		"three parts":        {"1.9", "1.4.1"},
	} {
		if _, err := LoadTarget("target-p.json", targetWithFloor(c[0], c[1])); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	// derivedFrom is never read as an attestation: the loader's only
	// products are the two lines, and a target with a lower derivedFrom
	// attests no more than one without (Attest is its own flag).
	tg, _ = LoadTarget("target-p.json", targetWithFloor("1.9", "1.4"))
	if tg.Attest {
		t.Fatal("derivedFrom switched attestation on")
	}
}
