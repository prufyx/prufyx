// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/customresources"
)

func kindIndex(listings ...customresources.Project) *customresources.Index {
	x := customresources.NewIndex(listings)
	return &x
}

func listing(slug string, kinds []string) customresources.Project {
	return customresources.Project{Slug: slug, Groups: []customresources.Group{{Name: "widgets.example.test", Kinds: kinds}}}
}

func kindOwnRun(t *testing.T, idx *customresources.Index) (*Result, error) {
	t.Helper()
	in := ipInput(ipSource(nil), ipRules(t, `[`+ipEntry+`]`))
	in.Index = idx
	return Generate(in)
}

// A kind no project lists, in a group the others list kind by kind, passes
// and the report carries the kinds-only row decision; the row lists only the
// kinds read.
func TestKindOwnershipSharedGroupAllowedKinds(t *testing.T) {
	idx := kindIndex(listing("other", []string{"Gamma", "Delta"}))
	res, err := kindOwnRun(t, idx)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !hasDecision(res.Report, RuleKindsOnlyRow, "widgets.example.test") {
		t.Fatalf("no kinds-only-row decision: %+v", res.Report.Decisions)
	}
	got := shapeOf(t, res.TableRow).Groups["widgets.example.test"]
	if strings.Join(got, ",") != "Alpha,Beta" {
		t.Fatalf("row kinds %v", got)
	}
}

// A kind another project lists stops and names the owner; so does a kind
// listed by two projects.
func TestKindOwnershipForeignKindStops(t *testing.T) {
	_, err := kindOwnRun(t, kindIndex(listing("other", []string{"Beta", "Gamma"})))
	wantStop(t, err, StopGroupOwnedElsewhere)
	if !strings.Contains(err.Error(), "other") || !strings.Contains(err.Error(), "widgets.example.test/Beta") {
		t.Fatalf("stop does not name the kind and owner: %v", err)
	}
	_, err = kindOwnRun(t, kindIndex(listing("o1", []string{"Beta"}), listing("o2", []string{"Beta"})))
	wantStop(t, err, StopGroupOwnedElsewhere)
}

// A group another project lists whole is not shared: every kind stops.
func TestKindOwnershipWholeGroupStillStops(t *testing.T) {
	_, err := kindOwnRun(t, kindIndex(listing("other", nil)))
	wantStop(t, err, StopGroupOwnedElsewhere)
	// Mixed: one project lists kinds, another lists the whole group.
	_, err = kindOwnRun(t, kindIndex(listing("o1", []string{"Gamma"}), listing("o2", nil)))
	wantStop(t, err, StopGroupOwnedElsewhere)
}

// Without a shared group nothing changes: no listing, or the project's own
// listing, passes with no kinds-only-row decision.
func TestKindOwnershipUnsharedUnchanged(t *testing.T) {
	for name, idx := range map[string]*customresources.Index{
		"none": kindIndex(),
		"own":  kindIndex(listing("widgets", []string{"Alpha", "Beta"})),
	} {
		res, err := kindOwnRun(t, idx)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if hasDecision(res.Report, RuleKindsOnlyRow, "widgets.example.test") {
			t.Fatalf("%s: unexpected kinds-only-row decision", name)
		}
	}
}
