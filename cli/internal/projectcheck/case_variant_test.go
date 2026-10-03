// SPDX-License-Identifier: AGPL-3.0-only

package projectcheck

import (
	"bytes"
	"testing"
)

// TestPackRefusesCaseVariantMembers: an entry member repeated, or spelt
// twice with different letter case, has two readings; admission refuses it.
func TestPackRefusesCaseVariantMembers(t *testing.T) {
	registry, err := packaged.ReadFile("data/projects.json")
	if err != nil {
		t.Fatal(err)
	}
	pack, err := packaged.ReadFile("data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CheckPackFiles(registry, pack); err != nil {
		t.Fatalf("the shipped pack is refused: %v", err)
	}
	for name, edit := range map[string]func([]byte) []byte{
		"Description": func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`"description":`), []byte(`"Description": "x", "description":`), 1)
		},
		"repeated project": func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`"project":`), []byte(`"project": "x", "project":`), 1)
		},
	} {
		variant := edit(pack)
		if bytes.Equal(variant, pack) {
			t.Fatalf("%s: no edit made", name)
		}
		if _, err := CheckPackFiles(registry, variant); err == nil {
			t.Fatalf("%s: admitted", name)
		}
		if _, _, err := AdmittedPackView(variant); err == nil {
			t.Fatalf("%s: AdmittedPackView accepted it", name)
		}
	}
	members, entries, err := AdmittedPackView(pack)
	if err != nil || len(entries) == 0 || members["revision"] == nil || members["entries"] != nil {
		t.Fatalf("view: %v %d %v", err, len(entries), members)
	}
}
