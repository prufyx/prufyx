// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"flag"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract/supersedeids"
	"github.com/prufyx/prufyx/cli/internal/goldenfile"
	"github.com/prufyx/prufyx/cli/internal/testclock"
)

var updateAgeGoldens = flag.Bool("update-age", false, "rewrite the knowledge age golden files")

// ageClocks are evaluation instants before, inside and after the last
// 30 days of the embedded knowledge's rules, derived from the pack.
var ageClocks = func() []struct{ name, now string } {
	before, inside, after := supersedeids.AgeClocks()
	return []struct{ name, now string }{
		{"before", before.Format(time.RFC3339)},
		{"inside", inside.Format(time.RFC3339)},
		{"after", after.Format(time.RFC3339)},
	}
}()

// batchAgeClocks are the age instants of the one rule the golden batch plan
// evaluates (a Thanos rule): 31, 17 days before and 3 days after the day its
// evidence ends, the same offsets as supersedeids.AgeClocks has for the
// earliest end of the whole pack. The plan's verdict follows that rule's own
// end, not the pack's earliest one, which a renewal of other rules moves.
var batchAgeClocks = ruleAgeClocks("thanos.receive-store-flags-removed.0-42")

// cncfAgeClocks are the same instants for the one rule the golden check cncf
// run evaluates (a Kyverno rule): the verdict follows that rule's own end, not
// the pack's earliest one, which a renewal of other rules moves.
var cncfAgeClocks = ruleAgeClocks(kyvernoReportsChunkSizeRuleID)

// ruleAgeClocks gives the before, inside and after instants of one rule: 31, 17
// days before and 3 days after the day its evidence ends.
func ruleAgeClocks(ruleID string) map[string]string {
	_, until := testclock.RuleEvidence(ruleID)
	end, err := time.Parse(time.RFC3339, until)
	if err != nil {
		panic(err)
	}
	inside := end.UTC().Truncate(24*time.Hour).AddDate(0, 0, -supersedeids.AgeWindowDays)
	return map[string]string{
		"before": inside.AddDate(0, 0, -14).Format(time.RFC3339),
		"inside": inside.Format(time.RFC3339),
		"after":  inside.AddDate(0, 0, 20).Format(time.RFC3339),
	}
}

// maskBatchClocks replaces the batch plan's own age instants with the
// placeholders the pack-wide age instants get (testclock.MaskClocks; the inside
// instant is the shared test clock there), so the
// batch goldens are the same text whichever rule fixes the instants.
func maskBatchClocks(got []byte, clocks map[string]string) []byte {
	for name, placeholder := range map[string]string{"before": "2001-02-01T00:00:00Z", "inside": "2001-01-01T00:00:00Z", "after": "2001-04-01T00:00:00Z"} {
		got = bytes.ReplaceAll(got, []byte(clocks[name]), []byte(placeholder))
	}
	return got
}

// humanSourceLine is a cited source in a human report: the pinned revision, the
// line range and the content digest, which a renewal of the rule's evidence
// moves; the file and the number of sources stay.
var humanSourceLine = regexp.MustCompile(`(source: \S+ @ )[0-9a-f]{12}(, lines )[0-9]+-[0-9]+(, sha256:)[0-9a-f]{12}`)

// expiredOnDate is the day a stale rule's review ended, as a report words it:
// the end date of the rule's evidence, which a renewal moves.
var expiredOnDate = regexp.MustCompile(`(expired on )20[0-9]{2}-[0-9]{2}-[0-9]{2}`)

// jsonSource holds the pinned-source fields of a JSON report's claim source:
// the same rule data, never a verdict.
var (
	jsonSourceID       = regexp.MustCompile(`"id":"source-[0-9a-f]{12}-[0-9]+"`)
	jsonSourceURL      = regexp.MustCompile(`"url":"(https://github\.com/[^"]*/blob/)[0-9a-f]{40}/[^"]*"`)
	jsonSourceRevision = regexp.MustCompile(`"revision":"[0-9a-f]{40}"`)
	jsonSourceDigest   = regexp.MustCompile(`"contentDigest":"sha256:[0-9a-f]{64}"`)
	jsonSourceLines    = regexp.MustCompile(`"(startLine|endLine)":[0-9]+`)
)

// maskSources replaces the pinned-source details a renewal of a rule's
// evidence moves with fixed placeholders.
func maskSources(got []byte) []byte {
	got = expiredOnDate.ReplaceAll(got, []byte("${1}2001-08-01"))
	got = humanSourceLine.ReplaceAll(got, []byte("${1}000000000000${2}0-0${3}000000000000"))
	got = jsonSourceID.ReplaceAll(got, []byte(`"id":"source-000000000000-0"`))
	got = jsonSourceURL.ReplaceAll(got, []byte(`"url":"${1}0000000000000000000000000000000000000000/source"`))
	got = jsonSourceRevision.ReplaceAll(got, []byte(`"revision":"0000000000000000000000000000000000000000"`))
	got = jsonSourceDigest.ReplaceAll(got, []byte(`"contentDigest":"sha256:`+strings.Repeat("0", 64)+`"`))
	return jsonSourceLines.ReplaceAll(got, []byte(`"$1":0`))
}

func ageGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	if strings.HasPrefix(name, "check-batch-") {
		got = maskBatchClocks(got, batchAgeClocks)
	} else if strings.HasPrefix(name, "check-cncf-") {
		got = maskBatchClocks(got, cncfAgeClocks)
	}
	masked := maskSources(maskPack(t, got))
	goldenfile.Check(t, filepath.Join("testdata", "knowledge-age", name), masked, *updateAgeGoldens, "")
}

// TestCheckOutputUnchangedNearExpiry: stdout and the exit code of check cncf
// and check batch with embedded knowledge do not depend on how close the
// knowledge is to its end. The golden files were written before the age note
// existed; only the clock they record differs between them.
func TestCheckOutputUnchangedNearExpiry(t *testing.T) {
	t.Parallel()
	input := writeCNCFFile(t, "input.json", []byte(kyvernoInputTrue), 0o600)
	root, plan := writeEmbeddedCLIBatch(t)
	for _, clock := range ageClocks {
		for _, format := range []string{"human", "json"} {
			code, stdout, _ := runCNCFCLI(t, "check", "cncf", "--project", "kyverno", "--input", input, "--now", cncfAgeClocks[clock.name], "--format", format)
			ageGolden(t, fmt.Sprintf("check-cncf-%s.%s", clock.name, format), []byte(fmt.Sprintf("%s\nexit %d\n", stdout, code)))
			code, stdout, _ = runCNCFCLI(t, "check", "batch", "--plan", plan, "--root", root, "--now", batchAgeClocks[clock.name], "--format", format)
			ageGolden(t, fmt.Sprintf("check-batch-%s.%s", clock.name, format), []byte(fmt.Sprintf("%s\nexit %d\n", stdout, code)))
		}
	}
}
