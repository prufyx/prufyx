// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/customresources"
)

// A definition of a group or kind the reviewed table records as owned by no
// project (a fixture group, the kinds of a product the table does not list)
// is left out like one of another project: a file of such definitions only
// does not block, whatever directory it lies in, and the scan names them.
func TestScanLeavesOutUnownedRecordDefinitions(t *testing.T) {
	for _, tc := range []struct{ name, path, group, kind, plural string }{
		{"fixture group in a default directory", "test/fixtures/example.yaml", "example.io", "Example", "examples"},
		{"fixture group in a documentation directory", "docs/example.yaml", "example.io", "Example", "examples"},
		{"workflows kind", "examples/workflow-crd.yaml", "argoproj.io", "Workflow", "workflows"},
		{"workflows kind, last of the list", "test/data/wft.yaml", "argoproj.io", "WorkflowTemplate", "workflowtemplates"},
	} {
		_, proof, f := quietPair(t, tc.path, foreignCRD(tc.group, tc.kind, tc.plural))
		if proof.To.Scan == nil || !proof.To.Scan.Clean() || (f != nil && f.blocks()) {
			t.Errorf("%s: scan %+v finding %+v", tc.name, proof.To.Scan, f)
			continue
		}
		fc := proof.To.Scan.ForeignCopies
		if len(fc) != 1 || fc[0].Path != tc.path || len(fc[0].Definitions) != 1 || fc[0].Definitions[0] != tc.plural+"."+tc.group {
			t.Errorf("%s: the left-out definition is not recorded: %+v", tc.name, fc)
		}
	}
}

// Nothing near a record is left out: a kind the record does not list, a
// lookalike group, a record group next to an unattributed definition. Each
// stays an extra definition and blocks.
func TestScanKeepsDefinitionsNearUnownedRecords(t *testing.T) {
	for _, tc := range []struct{ name, group, kind, plural string }{
		{"argoproj.io fixture kind", "argoproj.io", "Dummy", "dummies"},
		{"argoproj.io kind in another case (upper)", "argoproj.io", "WORKFLOW", "workflows"},
		{"argoproj.io kind with a suffix", "argoproj.io", "WorkflowTemplates", "workflowtemplatess"},
		{"subdomain of the fixture group", "stable.example.io", "Example", "examples"},
		{"suffixed fixture group", "example.io.evil.example", "Example", "examples"},
		{"prefixed fixture group", "myexample.io", "Example", "examples"},
		{"documentation domain", "example.com", "Example", "examples"},
	} {
		_, proof, f := quietPair(t, "test/fixtures/x.yaml", foreignCRD(tc.group, tc.kind, tc.plural))
		if f == nil || f.Class != ClassExtra || !f.blocks() || proof.To.Scan.Clean() || len(f.Foreign) != 0 {
			t.Errorf("%s: finding %+v", tc.name, f)
		}
	}
	// One unattributed definition next to a record's keeps the file extra.
	both := foreignCRD("example.io", "Example", "examples") + "---\n" + foreignCRD("argoproj.io", "Dummy", "dummies")
	_, proof, f := quietPair(t, "test/e2e/testdata/crd.yaml", both)
	if f == nil || f.Class != ClassExtra || !f.blocks() || proof.To.Scan.Clean() || len(f.Foreign) != 1 || len(f.CRDs) != 1 {
		t.Fatalf("mixed file: finding %+v", f)
	}
}

// The scan reads the records only through the index it holds, and only for a
// definition the complete inventory does not hold: an index without records
// leaves the definition in, a record never overrides a project listing, and
// the target's own definitions are never left out.
func TestUnownedRecordsApplyOnlyOutsideTheInventory(t *testing.T) {
	records := []customresources.UnownedGroup{
		{Name: "fixture.example.io"},
		{Name: "shared.example.io", Kinds: []string{"Beta"}},
	}
	listed := []customresources.Project{{Slug: "pa", Groups: []customresources.Group{{Name: "shared.example.io", Kinds: []string{"Alpha"}}}}}
	complete := &Inventory{Complete: true, CRDs: []CRD{}}
	def := func(group, kind string) CRD {
		return CRD{Name: strings.ToLower(kind) + "s." + group, Group: group, Kind: kind}
	}
	at := attribution{"pa", customresources.NewIndex(listed).WithUnowned(records)}
	for _, tc := range []struct {
		name string
		at   attribution
		c    CRD
		inv  *Inventory
		want bool
	}{
		{"fixture group", at, def("fixture.example.io", "Anything"), complete, true},
		{"unowned kind of a shared group", at, def("shared.example.io", "Beta"), complete, true},
		{"kind a project lists", at, def("shared.example.io", "Alpha"), complete, false},
		{"kind nobody lists", at, def("shared.example.io", "Gamma"), complete, false},
		{"group without a record", at, def("other.example.io", "Anything"), complete, false},
		{"no inventory", at, def("fixture.example.io", "Anything"), nil, false},
		{"incomplete inventory", at, def("fixture.example.io", "Anything"), &Inventory{CRDs: []CRD{}}, false},
		{"inventory holds the name", at, def("fixture.example.io", "Anything"), &Inventory{Complete: true, CRDs: []CRD{def("fixture.example.io", "Anything")}}, false},
		{"inventory holds the group and kind", at, def("fixture.example.io", "Anything"), &Inventory{Complete: true, CRDs: []CRD{{Name: "other.fixture.example.io", Group: "fixture.example.io", Kind: "Anything"}}}, false},
		{"channel holds the name", at, def("fixture.example.io", "Anything"), &Inventory{Complete: true, CRDs: []CRD{}, Channels: []ChannelInventory{{CRDs: []CRD{def("fixture.example.io", "Anything")}}}}, false},
		{"index without records", attribution{"pa", customresources.NewIndex(listed)}, def("fixture.example.io", "Anything"), complete, false},
	} {
		if got := tc.at.unowned(tc.c, tc.inv); got != tc.want {
			t.Errorf("%s: unowned = %v, want %v", tc.name, got, tc.want)
		}
	}
	// The table-based rule is unchanged: a record is never a table owner.
	if at.foreign("fixture.example.io", "Anything") || at.foreign("shared.example.io", "Beta") || !(attribution{"pb", at.index}).foreign("shared.example.io", "Alpha") {
		t.Error("the table-owner rule changed")
	}
}

// A definition the inventory holds is compared as before, record or not: a
// copy of a listed definition stays a plain copy of it.
func TestCompareKeepsInventoryDefinitionsOfAnUnownedGroup(t *testing.T) {
	c := CRD{Name: "examples.example.io", Group: "example.io", Kind: "Example", Versions: []CRDVersion{{Name: "v1", Served: true}}}
	at := attribution{"pa", customresources.DefaultIndex()}
	inv := &Inventory{Complete: true, CRDs: []CRD{c}}
	fd := compareDefinitions(Finding{}, []CRD{c}, inv, at, false)
	if fd.Class != ClassCopy || len(fd.Foreign) != 0 {
		t.Fatalf("copy of an inventory definition: %+v", fd)
	}
	fd = compareDefinitions(Finding{}, []CRD{c}, &Inventory{Complete: true, CRDs: []CRD{}}, at, false)
	if fd.Class != ClassCopy || len(fd.Foreign) != 1 {
		t.Fatalf("definition outside the inventory: %+v", fd)
	}
	fd = compareDefinitions(Finding{}, []CRD{c}, &Inventory{CRDs: []CRD{}}, at, false)
	if fd.Class != ClassExtra || len(fd.Foreign) != 0 {
		t.Fatalf("incomplete inventory: %+v", fd)
	}
}

// The embedded records name the groups the design asks for and nothing else.
func TestEmbeddedUnownedRecords(t *testing.T) {
	var names []string
	for _, u := range customresources.UnownedGroups() {
		names = append(names, u.Name)
		if !strings.HasPrefix(u.Source, "https://github.com/") {
			t.Errorf("%s: source %q", u.Name, u.Source)
		}
	}
	if got := strings.Join(names, ","); got != "argoproj.io,example.io" {
		t.Fatalf("records %s", got)
	}
}
