// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The floors hold the published README numbers from below: a published number
// may be above its floor (a data change raises it without touching the
// baseline) but never below it, except by what a named withdrawal allows. The
// ratchet itself lives elsewhere: CI (TestBaselineNotLowered) refuses a lowered
// floor against the base branch, and the knowledge gate holds the recomputed
// numbers of a change against the floor of the BASE tree. A stale floor
// therefore cannot hide a drop.
const baselineUpdateHint = "restore the coverage, or add a named withdrawal with a reason to testdata/readme-baseline.json (the floor itself is never lowered)"

// parseCount reads the count of the README table row with the given label
// (the labels are the generator's own constants). It fails closed when the row
// is missing or appears more than once. If the generator wording changes
// without the label constant, update the label, not this parser.
func parseCount(block, label string) (int, error) {
	re := regexp.MustCompile(`(?m)^\| ` + regexp.QuoteMeta(label) + ` \| (\d+) \|`)
	m := re.FindAllStringSubmatch(block, -1)
	if len(m) != 1 {
		return 0, fmt.Errorf("README coverage block: want exactly one %q row, found %d (if the generator wording changed, update the label constant in readme.go)", label, len(m))
	}
	return strconv.Atoi(m[0][1])
}

// checkFloorVsPublished fails when the published number is below the floor
// minus the allowance of the named withdrawals. Above or equal passes.
func checkFloorVsPublished(name string, floor, published, allowance int) error {
	if published < floor-allowance {
		return fmt.Errorf("published README %s %d is below the baseline floor %d (named withdrawals allow %d); %s", name, published, floor, allowance, baselineUpdateHint)
	}
	return nil
}

func TestParseCount(t *testing.T) {
	row := "| " + readmeDecidedLabel + " | 49 | 12.5% |\n"
	for _, tc := range []struct {
		name, block string
		want        int
		fail        bool
	}{
		{"one row", "x\n" + row, 49, false},
		{"row missing", "x\n", 0, true},
		{"row duplicated", row + row, 0, true},
		{"label altered", strings.Replace(row, "bounded", "limited", 1), 0, true},
	} {
		got, err := parseCount(tc.block, readmeDecidedLabel)
		if (err != nil) != tc.fail || got != tc.want {
			t.Errorf("%s: got %d, %v", tc.name, got, err)
		}
	}
}

func TestCheckFloorVsPublished(t *testing.T) {
	for _, tc := range []struct {
		name            string
		floor, pub, all int
		fail            bool
	}{
		{"equal", 49, 49, 0, false},
		{"published raised above floor", 49, 63, 0, false},
		{"published dropped below floor", 49, 48, 0, true},
		{"drop with stale high floor", 63, 53, 0, true},
		{"drop covered by withdrawal", 49, 46, 3, false},
		{"drop beyond withdrawal", 49, 45, 3, true},
	} {
		err := checkFloorVsPublished("decidedPairs", tc.floor, tc.pub, tc.all)
		if (err != nil) != tc.fail {
			t.Errorf("%s: %v", tc.name, err)
		}
		if err != nil && !strings.Contains(err.Error(), "withdrawal") {
			t.Errorf("%s: message lacks the update hint: %v", tc.name, err)
		}
	}
}

func TestBaselineTiedToPublishedNumbers(t *testing.T) {
	raw, err := os.ReadFile("../../../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	begin, end := strings.Index(doc, READMEBegin), strings.Index(doc, READMEEnd)
	if begin < 0 || end < begin {
		t.Fatal("README coverage block markers missing or out of order")
	}
	block := doc[begin:end]
	braw, err := os.ReadFile("testdata/readme-baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseBaseline(braw)
	if err != nil {
		t.Fatal(err)
	}
	allowPairs, allowCRD := 0, 0
	for _, w := range b.Withdrawals {
		allowPairs += w.DecidedPairs
		allowCRD += w.CRDProjects
	}
	for _, c := range []struct {
		label, name      string
		floor, allowance int
	}{
		{readmeDecidedLabel, "decidedPairs", b.DecidedPairs, allowPairs},
		{readmeCRDLabel, "crdPublishedProjects", b.CRDProjects, allowCRD},
	} {
		pub, err := parseCount(block, c.label)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkFloorVsPublished(c.name, c.floor, pub, c.allowance); err != nil {
			t.Error(err)
		}
	}
}
