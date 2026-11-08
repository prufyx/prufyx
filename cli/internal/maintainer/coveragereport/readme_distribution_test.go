// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

const (
	distHeading = "## Kubernetes distributions"
	distBegin   = "<!-- distribution-lifecycle:begin -->"
	distEnd     = "<!-- distribution-lifecycle:end -->"
	distState   = "reference/planned: no published facts yet"
)

// distRows are the table rows the README section must carry, each exactly once.
var distRows = []string{"EKS", "GKE", "AKS", "k3s", "kind", "Upstream"}

// forbiddenDistPhrases must never appear in the section: they would claim
// production support, a guarantee, or a comparison the evidence does not back.
var forbiddenDistPhrases = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bproduction[- ](supported|grade|ready|fidelity)\b`),
	regexp.MustCompile(`(?i)\bvalidated against\b`),
	regexp.MustCompile(`(?i)\b(verified|tested|certified) (against|on)\b`),
	regexp.MustCompile(`(?i)\bguarantee[sd]?\b`),
	regexp.MustCompile(`(?i)\bfirst\b`),
	regexp.MustCompile(`(?i)\bonly\b`),
	regexp.MustCompile(`(?i)\bunique(ly)?\b`),
	regexp.MustCompile(`(?i)\b(fully|officially) supported\b`),
	regexp.MustCompile(`(?i)\b(full|complete) coverage\b`),
	regexp.MustCompile(`(?i)\bbetter than\b`),
	regexp.MustCompile(`(?i)\b(factory|vkr)\b|/opt/`),
}

// checkDistSection fails closed: markers, rows, states and wording.
func checkDistSection(doc string) error {
	b, e := strings.Index(doc, distBegin), strings.Index(doc, distEnd)
	if b < 0 || e < b || strings.Count(doc, distBegin) != 1 || strings.Count(doc, distEnd) != 1 {
		return fmt.Errorf("distribution section markers missing, repeated or out of order")
	}
	sec := doc[b+len(distBegin) : e]
	// the wording lint covers the whole section: heading to the next "## "
	h := strings.LastIndex(doc[:b], distHeading)
	if h < 0 || strings.Contains(doc[h+len(distHeading):b], "\n## ") {
		return fmt.Errorf("distribution section heading %q missing before the table", distHeading)
	}
	whole := doc[h:]
	if n := strings.Index(whole[len(distHeading):], "\n## "); n >= 0 {
		whole = whole[:len(distHeading)+n]
	}
	for _, p := range forbiddenDistPhrases {
		if m := p.FindString(whole); m != "" {
			return fmt.Errorf("distribution section contains forbidden phrase %q", m)
		}
	}
	for _, name := range distRows {
		re := regexp.MustCompile(`(?m)^\| ` + regexp.QuoteMeta(name) + ` \|.*\|$`)
		rows := re.FindAllString(sec, -1)
		if len(rows) != 1 {
			return fmt.Errorf("distribution section: want exactly one %q row, found %d", name, len(rows))
		}
		if !strings.Contains(rows[0], distState) {
			return fmt.Errorf("distribution row %q does not state %q", name, distState)
		}
	}
	if n := strings.Count(sec, "\n| "); n != len(distRows)+2 { // header, separator rows counted as table lines
		return fmt.Errorf("distribution table has %d lines, want %d: an unlisted row needs a reviewed state", n, len(distRows)+2)
	}
	return nil
}

func TestCheckDistSection(t *testing.T) {
	good := "## Kubernetes distributions\n\nintro\n\n" + distBegin + "\n| Distribution | State |\n| --- | --- |\n"
	for _, n := range distRows {
		good += "| " + n + " | " + distState + " |\n"
	}
	good += distEnd + "\n\nProse after the table.\n\n## Next section\n\nmore\n"
	if err := checkDistSection(good); err != nil {
		t.Fatalf("good section rejected: %v", err)
	}
	// text after the next heading is outside the section
	if err := checkDistSection(strings.Replace(good, "more", "the only one", 1)); err != nil {
		t.Fatalf("text of the next section was linted: %v", err)
	}
	for _, tc := range []struct{ name, doc string }{
		{"no markers", "x"},
		{"production supported", strings.Replace(good, distEnd, "It is production-supported.\n"+distEnd, 1)},
		{"validated against", strings.Replace(good, distEnd, "validated against EKS\n"+distEnd, 1)},
		{"guaranteed", strings.Replace(good, distEnd, "Guaranteed.\n"+distEnd, 1)},
		{"first", strings.Replace(good, distEnd, "The first.\n"+distEnd, 1)},
		{"only", strings.Replace(good, distEnd, "the only one\n"+distEnd, 1)},
		{"unique", strings.Replace(good, distEnd, "Unique.\n"+distEnd, 1)},
		{"private word", strings.Replace(good, distEnd, "see the factory\n"+distEnd, 1)},
		{"prose after table claims support", strings.Replace(good, "Prose after the table.", "All of these are production-supported.", 1)},
		{"prose after table guarantees", strings.Replace(good, "Prose after the table.", "Guaranteed to work.", 1)},
		{"prose before table", strings.Replace(good, "intro", "the first", 1)},
		{"capitalised only", strings.Replace(good, distEnd, "ONLY these\n"+distEnd, 1)},
		{"capitalised validated", strings.Replace(good, distEnd, "Validated Against EKS\n"+distEnd, 1)},
		{"row missing", strings.Replace(good, "| kind | "+distState+" |\n", "", 1)},
		{"state altered", strings.Replace(good, "| EKS | "+distState, "| EKS | supported", 1)},
		{"extra row", strings.Replace(good, distEnd, "| RKE2 | "+distState+" |\n"+distEnd, 1)},
		{"duplicate row", strings.Replace(good, distEnd, "| EKS | "+distState+" |\n"+distEnd, 1)},
	} {
		if err := checkDistSection(tc.doc); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
}

func TestReadmeDistributionSection(t *testing.T) {
	raw, err := os.ReadFile("../../../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	if err := checkDistSection(string(raw)); err != nil {
		t.Fatal(err)
	}
}
