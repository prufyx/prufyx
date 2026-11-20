// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"strings"
	"testing"
)

// formsFixture: kubernetes (fleet, window set): one pair decided only by the
// served-API family, one gap. alpha (fleet): one pair bounded by a CRD
// family and the served-API family together. comm (community): one exact-pair
// rule, one listed pair. Fleet pairs: 3.
func formsFixture() Report {
	r := Report{Fleet: Totals{Projects: 2, Pairs: 3}, CommunityCatalog: &Totals{Projects: 1, Pairs: 2}}
	r.Projects = []Project{
		{Project: "kubernetes", Window: []string{"1.30", "1.31", "1.32"}, Covered: true, Pairs: []Pair{
			{From: "1.30", To: "1.31", Status: StatusA, Families: []string{FamilyServedAPI}},
			{From: "1.31", To: "1.32", Status: StatusG},
		}},
		{Project: "alpha", Covered: true, Pairs: []Pair{
			{From: "1", To: "2", Status: StatusB, Families: []string{"crd.custom_resource_versions", FamilyServedAPI}},
		}},
		{Project: "comm", Catalog: CatalogCommunity, Pairs: []Pair{
			{From: "1", To: "2", Status: StatusS},
			{From: "2", To: "3", Status: StatusG, Changelog: true},
		}},
	}
	return r
}

func TestFormOfFailsClosed(t *testing.T) {
	t.Parallel()
	for name, p := range map[string]Pair{
		"unknown status":         {From: "1", To: "2", Status: "X"},
		"empty status":           {From: "1", To: "2"},
		"changelog mark on A":    {From: "1", To: "2", Status: StatusA, Changelog: true},
		"changelog mark on B":    {From: "1", To: "2", Status: StatusB, Changelog: true},
		"changelog mark on S":    {From: "1", To: "2", Status: StatusS, Changelog: true},
		"lowercase status A":     {From: "1", To: "2", Status: "a"},
		"status with whitespace": {From: "1", To: "2", Status: "A "},
	} {
		if f, err := FormOf(p); err == nil {
			t.Errorf("%s: classified as %q", name, f)
		}
	}
	r := Report{Projects: []Project{{Project: "x", Pairs: []Pair{{From: "1", To: "2", Status: "Z"}}}}}
	if _, err := FormsOf(r); err == nil {
		t.Error("a report with an unknown status produced a table")
	}
	for _, name := range []string{"", "a|b", "a\nb"} {
		if _, err := FormsOf(Report{Projects: []Project{{Project: name}}}); err == nil {
			t.Errorf("project name %q accepted", name)
		}
	}
}

// L is listed, not judged: never decided, never a PASS, and a changelog pair
// is not also counted as a gap or as decided.
func TestListedIsNeverDecided(t *testing.T) {
	t.Parallel()
	if f, err := FormOf(Pair{From: "1", To: "2", Status: StatusG, Changelog: true}); err != nil || f != "l" {
		t.Fatalf("changelog pair: %q, %v", f, err)
	}
	tab, err := FormsOf(formsFixture())
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range tab.Rows {
		if row.Project == "comm" && (row.L != 1 || row.AB != 0 || row.G != 0) {
			t.Errorf("comm row: %+v", row)
		}
	}
	header := strings.SplitN(renderFormsTable(tab), "\n", 2)[0]
	for _, cell := range strings.Split(header, "|") {
		if strings.HasPrefix(strings.TrimSpace(cell), "L ") {
			low := strings.ToLower(cell)
			if strings.Contains(low, "decided") || strings.Contains(low, "pass") || !strings.Contains(low, "not judged") {
				t.Errorf("L column header %q", cell)
			}
		}
		if c := strings.ToLower(cell); strings.Contains(c, "decided") && !strings.Contains(c, "a/b") {
			t.Errorf("only the A/B column may be called decided, got %q", cell)
		}
	}
}

// Every pair is counted once, under its strongest form.
func TestPairCountedOnce(t *testing.T) {
	t.Parallel()
	tab, err := FormsOf(formsFixture())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Forms{
		"kubernetes": {K8s: 1, G: 1},
		"alpha":      {AB: 1}, // served-API together with another family stays A/B
		"comm":       {S: 1, L: 1},
	}
	for _, row := range tab.Rows {
		if row.Forms != want[row.Project] {
			t.Errorf("%s: %+v, want %+v", row.Project, row.Forms, want[row.Project])
		}
		if row.Forms.total() != row.Pairs {
			t.Errorf("%s: forms add up to %d, pairs %d", row.Project, row.Forms.total(), row.Pairs)
		}
	}
	if tab.Fleet.Pairs != 3 || tab.Fleet.Projects != 2 || tab.Fleet.ProjectsWithAnswer != 2 {
		t.Errorf("fleet group %+v", tab.Fleet)
	}
	if tab.Community.Pairs != 2 || tab.Community.Projects != 1 || tab.Community.ProjectsWithAnswer != 1 || tab.Community.L != 1 {
		t.Errorf("community group %+v", tab.Community)
	}
	if tab.Fleet.total()+tab.Community.total() != tab.Fleet.Pairs+tab.Community.Pairs {
		t.Error("a pair is counted twice or not at all")
	}
}

func TestProjectOnlyListedHasAnAnswerOrNot(t *testing.T) {
	t.Parallel()
	r := Report{Projects: []Project{
		{Project: "gaponly", Pairs: []Pair{{From: "1", To: "2", Status: StatusG}}},
		{Project: "listed", Pairs: []Pair{{From: "1", To: "2", Status: StatusG, Changelog: true}}},
	}}
	tab, err := FormsOf(r)
	if err != nil {
		t.Fatal(err)
	}
	if tab.Fleet.ProjectsWithAnswer != 1 {
		t.Errorf("projects with an answer: %d, want 1 (a gap is not an answer)", tab.Fleet.ProjectsWithAnswer)
	}
	if tab.Rows[0].GapReason != GapReasonNoRule || tab.Rows[1].GapReason != "" {
		t.Errorf("reasons: %q %q", tab.Rows[0].GapReason, tab.Rows[1].GapReason)
	}
}

// The block has one row per project, no total row and no summed headline.
func TestReadmeBlockHasNoSummedTotal(t *testing.T) {
	t.Parallel()
	block, err := readmeFixture(formsFixture())
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"Decided for the whole release-line pair", "| Share |", "Gap, no valid rule"} {
		if strings.Contains(block, banned) {
			t.Errorf("the block still has the summed row %q", banned)
		}
	}
	rows := 0
	for _, line := range strings.Split(block, "\n") {
		if !strings.HasPrefix(line, "| ") || !strings.Contains(line, "release-line fleet |") {
			continue
		}
		first := strings.ToLower(strings.TrimSpace(strings.Split(line, "|")[1]))
		for _, bad := range []string{"total", "sum", "all ", "fleet", "overall"} {
			if strings.HasPrefix(first, bad) {
				t.Errorf("a total-like row: %q", line)
			}
		}
		rows++
	}
	if rows != 3 {
		t.Errorf("%d table rows, want one per project (3)", rows)
	}
	for _, want := range []string{"<details>", "</details>", "A/B decided, then k8s served-API, then S, then L, then G", "Only A/B is called decided", "never PASS"} {
		if !strings.Contains(block, want) {
			t.Errorf("block lacks %q", want)
		}
	}
	if strings.Contains(block, "435") {
		t.Error("an internal number is printed")
	}
}

// A fleet total that disagrees with the rows refuses to render.
func TestReadmeBlockRefusesInconsistentFleet(t *testing.T) {
	t.Parallel()
	r := formsFixture()
	r.Fleet.Pairs = 4
	if _, err := readmeFixture(r); err == nil {
		t.Error("a table not matching fleet.pairs was rendered")
	}
}
