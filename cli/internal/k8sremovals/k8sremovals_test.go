// SPDX-License-Identifier: AGPL-3.0-only

package k8sremovals

import "testing"

// RemovedVersions lists the table plus the 1.32 flow-control removal,
// ordered by numeric line (1.9 before 1.10 would be a text order bug).
func TestRemovedVersionsOrderAndContent(t *testing.T) {
	list := RemovedVersions()
	count := 1
	for _, removals := range ByTargetMinor() {
		count += len(removals)
	}
	if len(list) != count {
		t.Fatalf("%d entries, want %d", len(list), count)
	}
	var has132 bool
	for i, r := range list {
		if r.Line == "1.32" && r.Group == "flowcontrol.apiserver.k8s.io" && r.Version == "v1beta3" {
			has132 = true
		}
		if i > 0 && lineLess(r.Line, list[i-1].Line) {
			t.Fatalf("%s sorts after %s", r.Line, list[i-1].Line)
		}
	}
	if !has132 {
		t.Fatal("the 1.32 flow-control removal is missing")
	}
	if !lineLess("1.9", "1.10") || lineLess("1.10", "1.9") || lineLess("1.10", "1.10") {
		t.Fatal("lines are not ordered numerically")
	}
}

// The accessor hands out a copy: changing it cannot change the table.
func TestByTargetMinorReturnsCopy(t *testing.T) {
	first := ByTargetMinor()
	first["1.22"][0].Kinds[0] = "Tampered"
	first["1.22"][0].Removed = "v9"
	delete(first, "1.25")
	second := ByTargetMinor()
	if second["1.22"][0].Kinds[0] == "Tampered" || second["1.22"][0].Removed == "v9" || len(second["1.25"]) == 0 {
		t.Fatal("a change to the returned table reached the shared table")
	}
}

// The admission list adds the 1.16 removals and leaves RemovedVersions alone.
func TestAdmissionRemovedVersionsAddsPreV122(t *testing.T) {
	base, adm := RemovedVersions(), AdmissionRemovedVersions()
	if len(adm) != len(base)+len(preV122Removals) {
		t.Fatalf("%d admission entries, want %d", len(adm), len(base)+len(preV122Removals))
	}
	for _, r := range base {
		if lineLess(r.Line, "1.22") {
			t.Fatalf("RemovedVersions holds the pre-1.22 line %s", r.Line)
		}
	}
	if adm[0].Line != "1.16" {
		t.Fatalf("first admission entry is line %s", adm[0].Line)
	}
}
