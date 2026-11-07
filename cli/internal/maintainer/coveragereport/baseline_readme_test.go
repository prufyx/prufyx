// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The floor is a ratchet, so it must stay close under the published numbers.
// Slack is how far below the README numbers a floor may sit before it counts
// as stale. It is small on purpose: a floor that trails the README by more
// than this no longer protects what was published.
const (
	baselineSlackPairs    = 3
	baselineSlackProjects = 1
)

const baselineUpdateHint = "update testdata/readme-baseline.json deliberately, in the pull request that changes the README numbers (raise the floor to the published value; lowering needs a named withdrawal with a reason)"

var (
	readmeDecidedRow = regexp.MustCompile(`(?m)^\| Decided for the whole release-line pair \(A attested, B bounded\) \| (\d+) \|`)
	readmeCRDRow     = regexp.MustCompile(`(?m)^\| Projects with a published CRD rule or line attestation \| (\d+) \|`)
)

// publishedCount reads one number from the generated README block; it fails
// closed when the row is missing or appears more than once.
func publishedCount(t *testing.T, doc string, re *regexp.Regexp, what string) int {
	t.Helper()
	m := re.FindAllStringSubmatch(doc, -1)
	if len(m) != 1 {
		t.Fatalf("README coverage block: want exactly one %q row, found %d", what, len(m))
	}
	n, err := strconv.Atoi(m[0][1])
	if err != nil {
		t.Fatalf("README coverage block: %q: %v", what, err)
	}
	return n
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
	pairs := publishedCount(t, block, readmeDecidedRow, "decided pairs")
	crd := publishedCount(t, block, readmeCRDRow, "published CRD projects")

	braw, err := os.ReadFile("testdata/readme-baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseBaseline(braw)
	if err != nil {
		t.Fatal(err)
	}
	check := func(name string, floor, published, slack int) {
		if floor > published {
			t.Errorf("baseline %s floor %d is above the published README number %d; %s", name, floor, published, baselineUpdateHint)
		}
		if floor < published-slack {
			t.Errorf("baseline %s floor %d is more than %d below the published README number %d (stale floor); %s", name, floor, slack, published, baselineUpdateHint)
		}
	}
	check("decidedPairs", b.DecidedPairs, pairs, baselineSlackPairs)
	check("crdPublishedProjects", b.CRDProjects, crd, baselineSlackProjects)
}
