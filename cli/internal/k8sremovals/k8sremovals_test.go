// SPDX-License-Identifier: AGPL-3.0-only

package k8sremovals

import "testing"

// RemovedVersions lists the table plus the 1.32 flow-control removal,
// ordered by numeric line (1.9 before 1.10 would be a text order bug).
func TestRemovedVersionsOrderAndContent(t *testing.T) {
	list := RemovedVersions()
	count := 1
	for _, removals := range ByTargetMinor {
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
