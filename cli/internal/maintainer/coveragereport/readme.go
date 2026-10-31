// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// The README coverage block: markers, and the pinned snapshot of release
// lines the block is measured against. The snapshot is pinned here, in code,
// so that a change of the data cannot also move what it is measured against;
// moving the pin is a code change.
const (
	READMEBegin = "<!-- coverage:begin -->"
	READMEEnd   = "<!-- coverage:end -->"
	// PinnedLinesPath is the repository path of the pinned lines snapshot.
	PinnedLinesPath = "cli/internal/maintainer/coveragereport/testdata/lines-2026-10-31.json"
)

// readmeInventoryCounts are the support-inventory counts the block prints.
var readmeInventoryCounts = []string{
	"cncfSourceRules", "cncfRuleProjects", "cncfSourceRulesWithdrawn",
	"communityProjectSourceRules", "communityProjectRuleProjects",
	"executableProjects", "selectedSourceProjects", "selectedSourceOnlyProjects",
}

// readmePct is the share a/b as the block prints it: floored to one decimal.
func readmePct(a, b int) string {
	if b == 0 {
		return "0%"
	}
	return strconv.FormatFloat(float64(a*1000/b)/10, 'f', -1, 64) + "%"
}

// RenderREADMEBlock renders the text between the README markers from a
// report and the generated support inventory. now only supplies the date.
// The result ends with one newline. Nothing in it is typed by hand.
func RenderREADMEBlock(r Report, inventoryJSON []byte, now time.Time) (string, error) {
	var inv struct {
		Counts map[string]int `json:"counts"`
	}
	if err := json.Unmarshal(inventoryJSON, &inv); err != nil {
		return "", fmt.Errorf("support inventory: %w", err)
	}
	for _, k := range readmeInventoryCounts {
		if _, ok := inv.Counts[k]; !ok {
			return "", fmt.Errorf("support inventory: counts.%s is missing", k)
		}
	}
	c := inv.Counts
	var k *Project
	for i := range r.Projects {
		if r.Projects[i].Project == "kubernetes" {
			k = &r.Projects[i]
		}
	}
	if k == nil || len(k.Window) == 0 {
		return "", fmt.Errorf("report: the kubernetes row or its window is missing")
	}
	f := r.Fleet
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	w("Generated on %s by `scripts/readme-coverage.sh` (do not edit this block by hand).\n\n", now.UTC().Format("2006-01-02"))
	w("| Executable rules | Count |\n| --- | --- |\n")
	w("| CNCF source rules, active | %d across %d projects (%d withdrawn, not used) |\n", c["cncfSourceRules"], c["cncfRuleProjects"], c["cncfSourceRulesWithdrawn"])
	w("| Rules for further, non-CNCF projects | %d across %d projects |\n", c["communityProjectSourceRules"], c["communityProjectRuleProjects"])
	w("| Projects with at least one executable check (a rule, a named check or a profile; says nothing about which upgrades it decides) | %d |\n", c["executableProjects"])
	w("| Projects with a rule or attestation that decides at least one of their last five minor upgrades (A, B or S below) | %d of %d |\n", r.withPairs, f.Projects)
	w("| Projects catalogued with retained public sources | %d (%d of them source-only, no check) |\n", c["selectedSourceProjects"], c["selectedSourceOnlyProjects"])
	w("| Projects with reviewed CRD targets (a reviewed `crd.custom_resource_versions` target) | %d |\n", r.CRDVersionProjects)
	w("| Projects with a published CRD rule or line attestation | %d |\n\n", r.CRDPublishedProjects)
	w("Version-coverage depth, measured over the last five minor upgrades of each of the %d projects with a release-line snapshot (%d upgrades between consecutive release lines):\n\n", f.Projects, f.Pairs)
	w("| Status | Upgrades | Share |\n| --- | --- | --- |\n")
	w("| Decided for the whole release-line pair (A attested, B bounded) | %d | %s |\n", f.A+f.B, readmePct(f.A+f.B, f.Pairs))
	w("| Rule for one exact version pair only (S) | %d | %s |\n", f.S, readmePct(f.S, f.Pairs))
	w("| Gap, no valid rule (G) | %d | %s |\n\n", f.G, readmePct(f.G, f.Pairs))
	w("Kubernetes: %d valid rules, but %d fall in its window %s to %s; %d of %d upgrades in that window are gaps.\n\n", k.ValidRules, k.RulesInWindow, k.Window[0], k.Window[len(k.Window)-1], k.G, k.A+k.B+k.S+k.G)
	w("Decided means a valid rule or attestation covers every version of both release lines. It never means a whole-upgrade PASS. %s An exact-pair rule decides only the versions it names. The metric is defined in the [coverage report guide](cli/docs/coverage-report.md); it is not a statement that any upgrade is safe.\n", decidedSplitSentence(r.split, f.A+f.B))
	return b.String(), nil
}

// decidedSplitSentence says, from the report, how many decided upgrades can
// end in BLOCKED and how many cannot: an attestation that lists no rule can
// produce only a family-scoped PASS ("PASS within <family> only" in the scan
// output), never BLOCKED. total is the decided count the table prints; the
// split must add up to it.
func decidedSplitSentence(d decidedSplit, total int) string {
	if d.total() != total {
		return fmt.Sprintf("(the split of the %d decided upgrades is unavailable)", total)
	}
	if len(d.noBlock) == 0 {
		return fmt.Sprintf("All %d decided upgrades are decided by a rule, or by an attestation that lists rules, so the answer for them can be BLOCKED or UNKNOWN.", total)
	}
	var parts []string
	rest := 0
	for _, f := range d.noBlock {
		parts = append(parts, fmt.Sprintf("%d by `%s`", f.pairs, f.families))
		rest += f.pairs
	}
	return fmt.Sprintf("Only %d of the %d decided upgrades are decided by a rule, or by an attestation that lists rules, so the answer for them can be BLOCKED or UNKNOWN. The other %d are decided only by line attestations that list no rule (%s): for them an attestation can only give a family-scoped PASS (`scan` prints \"PASS within <family> only\"), never BLOCKED.", d.canBlock, total, rest, strings.Join(parts, ", "))
}

// SpliceBlock returns doc with the lines between the begin and end marker
// lines replaced by block. Each marker must occur exactly once in doc, as a
// whole line, begin before end; otherwise it is an error. Every byte outside
// the replaced lines is kept. block is empty or ends with a newline and
// holds neither marker.
func SpliceBlock(doc []byte, begin, end, block string) ([]byte, error) {
	if block != "" && !strings.HasSuffix(block, "\n") {
		return nil, fmt.Errorf("the block does not end with a newline")
	}
	if strings.Contains(block, begin) || strings.Contains(block, end) {
		return nil, fmt.Errorf("the block holds a marker")
	}
	if n := bytes.Count(doc, []byte(begin)); n != 1 {
		return nil, fmt.Errorf("the begin marker occurs %d times, want once", n)
	}
	if n := bytes.Count(doc, []byte(end)); n != 1 {
		return nil, fmt.Errorf("the end marker occurs %d times, want once", n)
	}
	bi := bytes.Index(doc, []byte(begin))
	ei := bytes.Index(doc, []byte(end))
	if bi > 0 && doc[bi-1] != '\n' {
		return nil, fmt.Errorf("the begin marker is not a whole line")
	}
	after := bi + len(begin)
	if after >= len(doc) || doc[after] != '\n' {
		return nil, fmt.Errorf("the begin marker is not a whole line")
	}
	start := after + 1
	if ei > 0 && doc[ei-1] != '\n' {
		return nil, fmt.Errorf("the end marker is not a whole line")
	}
	if tail := ei + len(end); tail < len(doc) && doc[tail] != '\n' {
		return nil, fmt.Errorf("the end marker is not a whole line")
	}
	if ei < start {
		return nil, fmt.Errorf("the end marker comes before the begin marker")
	}
	out := make([]byte, 0, len(doc)+len(block))
	out = append(out, doc[:start]...)
	out = append(out, block...)
	out = append(out, doc[ei:]...)
	return out, nil
}

// RenderCRDCatalogue renders the text between the crd-catalogue markers
// from a report: how many projects have a reviewed custom-resource target,
// and how many community-catalog ones have published CRD knowledge. It ends
// with one newline.
func RenderCRDCatalogue(r Report) (string, error) {
	c := r.crd
	if c.cncf+c.community == 0 {
		return "", fmt.Errorf("report: no reviewed CRD version target")
	}
	return fmt.Sprintf("A project is catalogued when it has a reviewed custom-resource target (%d projects: %d of the CNCF landscape catalog, %d of the community catalog). It is decided only for the upgrades that a rule or line attestation covers for the whole release-line pair (A or B in the table below). Of the %d community-catalog projects, %d hold a published rule or current line attestation for the CRD version family and %d hold none.\n", c.cncf+c.community, c.cncf, c.community, c.community, c.communityPublished, c.community-c.communityPublished), nil
}
