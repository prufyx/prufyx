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

// The floors are a ratchet with zero slack: each must equal the number the
// README prints. A legitimate drop goes through a named withdrawal.
const baselineUpdateHint = "update testdata/readme-baseline.json deliberately, in the pull request that changes the README numbers (set the floor to the published value; a legitimate drop needs a named withdrawal with a reason)"

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

func checkFloorVsPublished(name string, floor, published int) error {
	if floor != published {
		return fmt.Errorf("baseline %s floor %d differs from the published README number %d; %s", name, floor, published, baselineUpdateHint)
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
		name       string
		floor, pub int
		fail       bool
	}{
		{"equal", 49, 49, false},
		{"floor above published", 50, 49, true},
		{"floor below published", 46, 49, true},
	} {
		err := checkFloorVsPublished("decidedPairs", tc.floor, tc.pub)
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
	for _, c := range []struct {
		label, name string
		floor       int
	}{
		{readmeDecidedLabel, "decidedPairs", b.DecidedPairs},
		{readmeCRDLabel, "crdPublishedProjects", b.CRDProjects},
	} {
		pub, err := parseCount(block, c.label)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkFloorVsPublished(c.name, c.floor, pub); err != nil {
			t.Error(err)
		}
	}
}
