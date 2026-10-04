// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/buildidentity"
	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// testdata is the package's testdata directory, fixed before any test
// changes the working directory.
var testdata = func() string {
	dir, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	return filepath.Join(dir, "testdata")
}()

const (
	testNow       = "2026-10-04T00:00:00Z"
	kubernetesKey = "pkg:github/kubernetes/kubernetes"
)

// testBuild is a fixed build identity so goldens do not depend on the
// toolchain that runs the tests.
var testBuild = buildidentity.Identity{
	Version: "development", ReleaseState: "development", SourceRevision: "development", SourceTreeDigest: "development",
	AllowlistDigest: "development", BuildProfile: "development", BuildEpoch: "development", GoVersion: "test", TrustRootDigest: "unpinned",
}

// testKnowledge is the embedded knowledge with line reviews and an upgrade
// path policy added for tests. Rules and their evaluation are the published
// ones; only the two lookups are replaced.
type testKnowledge struct {
	*cncfcheck.ScanKnowledge
	attestations lineattest.Index
	policies     upgradepath.Index
}

func (k testKnowledge) AttestationsFor(component, line, family string, now time.Time) []lineattest.Status {
	return k.attestations.AttestationsFor(component, line, family, now)
}

func (k testKnowledge) PathPolicyFor(component string, now time.Time) upgradepath.Status {
	return k.policies.Lookup(component, now)
}

// knowledgeOptions select the added reviews.
type knowledgeOptions struct {
	// lines are attested current; stale lines are attested with an expired
	// review.
	lines, stale []string
	// policy is "" (no record), "current" or "stale" sequential_minor.
	policy string
	// unchecked skips the admission check of the attestations, to model an
	// index built without it.
	unchecked bool
	// extraRuleIDs lists rule ids to add to a line's review regardless of
	// the pack.
	extraRuleIDs map[string][]string
}

const testSource = `{"id":"kubernetes-website-v125-cronjob-v1beta1","url":"https://github.com/kubernetes/website/blob/9f1af2971c32124bff0a1f42255ba5a2f3c8a16f/content/en/docs/reference/using-api/deprecation-guide.md","revision":"9f1af2971c32124bff0a1f42255ba5a2f3c8a16f","contentDigest":"sha256:96f34a49cbdd7bd53008cc7b7cc8aff58c373ad323e64eef0155cbbc44494f61","startLine":87,"endLine":93}`

func newKnowledge(t testing.TB, options knowledgeOptions) Knowledge {
	t.Helper()
	base, err := cncfcheck.LoadScanKnowledge()
	if err != nil {
		t.Fatal(err)
	}
	rules := packRules(t)
	byScope, _, err := lineattest.RulesByScope(rules)
	if err != nil {
		t.Fatal(err)
	}
	type entry struct {
		line   string
		window [2]string
	}
	var entries []entry
	for _, line := range options.lines {
		entries = append(entries, entry{line, [2]string{"2026-09-23T00:00:00Z", "2026-12-20T00:00:00Z"}})
	}
	for _, line := range options.stale {
		entries = append(entries, entry{line, [2]string{"2026-06-01T00:00:00Z", "2026-08-01T00:00:00Z"}})
	}
	sort.Slice(entries, func(i, j int) bool { return lineattest.LineLess(entries[i].line, entries[j].line) })
	var docs []string
	for _, e := range entries {
		ids := byScope[lineattest.Key{Component: kubernetesKey, Line: e.line, Family: lineattest.FamilyKubernetesRemovedServedGVK}]
		ids = append(append([]string{}, ids...), options.extraRuleIDs[e.line]...)
		sort.Strings(ids)
		encoded, _ := json.Marshal(ids)
		if ids == nil {
			encoded = []byte("[]")
		}
		docs = append(docs, fmt.Sprintf(`{"component":%q,"line":%q,"factFamily":%q,"completeness":"COMPLETE_REVIEWED_RULES_FOR_LINE","ruleIds":%s,"evidence":{"basis":"reviewed","reviewedAt":%q,"validUntil":%q,"sources":[%s]}}`,
			kubernetesKey, e.line, lineattest.FamilyKubernetesRemovedServedGVK, encoded, e.window[0], e.window[1], testSource))
	}
	index := lineattest.NewIndex(nil)
	if len(docs) > 0 {
		atts, err := lineattest.Parse([]byte("[" + strings.Join(docs, ",") + "]"))
		if err != nil {
			t.Fatal(err)
		}
		if !options.unchecked {
			problems, err := lineattest.CheckRuleSets(atts, rules)
			if err != nil || len(problems) > 0 {
				t.Fatalf("test attestations are not admissible: %v %+v", err, problems)
			}
		}
		index = lineattest.NewIndex(atts)
	}
	policies := upgradepath.NewIndex(nil)
	if options.policy != "" {
		window := [2]string{"2026-09-23T00:00:00Z", "2026-12-20T00:00:00Z"}
		if options.policy == "stale" {
			window = [2]string{"2026-06-01T00:00:00Z", "2026-08-01T00:00:00Z"}
		}
		records, err := upgradepath.Parse([]byte(fmt.Sprintf(`[{"component":%q,"policy":"sequential_minor","evidence":{"state":"active","reviewedAt":%q,"validUntil":%q,"sources":[%s]}}]`, kubernetesKey, window[0], window[1], testSource)))
		if err != nil {
			t.Fatal(err)
		}
		policies = upgradepath.NewIndex(records)
	}
	return testKnowledge{ScanKnowledge: base, attestations: index, policies: policies}
}

// packRules are the raw rules of the embedded pack.
func packRules(t testing.TB) []json.RawMessage {
	t.Helper()
	catalogue, err := cncfcheck.Catalog(false, "")
	if err != nil {
		t.Fatal(err)
	}
	var rules []json.RawMessage
	for _, project := range catalogue.Projects {
		for _, entry := range project.Checks {
			rules = append(rules, entry.Rule)
		}
	}
	return rules
}

// allLines attests every line from 1.25 to 1.30.
var allLines = []string{"1.25", "1.26", "1.27", "1.28", "1.29", "1.30"}

func without(lines []string, drop ...string) []string {
	var out []string
	for _, line := range lines {
		keep := true
		for _, d := range drop {
			keep = keep && line != d
		}
		if keep {
			out = append(out, line)
		}
	}
	return out
}

// scan parses args and runs a scan.
func scan(t testing.TB, knowledge Knowledge, args ...string) (Result, error) {
	t.Helper()
	request, err := ParseArgs(args)
	if err != nil {
		return Result{}, err
	}
	return Run(request, Options{Knowledge: knowledge, Build: &testBuild})
}

// mustScan runs a scan that must be accepted.
func mustScan(t testing.TB, knowledge Knowledge, args ...string) Result {
	t.Helper()
	result, err := scan(t, knowledge, args...)
	if err != nil {
		t.Fatalf("scan %q: %v", args, err)
	}
	checkInvariants(t, result.Report)
	return result
}

// checkInvariants holds for every report: an undecided hop names its gaps,
// PASS has no gap and every hop COVERED, every catalog string is bounded.
func checkInvariants(t testing.TB, report scanreport.Report) {
	t.Helper()
	for _, path := range report.Paths {
		for _, hop := range path.Hops {
			if (hop.Status == scanreport.HopPartial || hop.Status == scanreport.HopNoData) && len(hop.Reasons) == 0 {
				t.Fatalf("hop %d %s is undecided without a named gap", hop.Index, hop.Status)
			}
			if hop.Status == scanreport.HopCovered && len(hop.Reasons) != 0 {
				t.Fatalf("covered hop %d has reasons %v", hop.Index, hop.Reasons)
			}
		}
	}
	if report.Verdict == scanreport.VerdictPass {
		if len(report.Gaps) != 0 || len(report.Findings) != 0 || len(report.Paths) == 0 {
			t.Fatal("PASS with gaps, findings or no path")
		}
	}
	if report.Verdict != scanreport.VerdictBlocked && len(report.Findings) != 0 {
		t.Fatal("findings without BLOCKED")
	}
	for _, gap := range report.Gaps {
		if len(gap.Detail) > scanreport.MaxText || len(gap.Action) > scanreport.MaxText || gap.Detail == "" || gap.Action == "" || strings.Contains(gap.Detail+gap.Action, "%") {
			t.Fatalf("gap text %+v", gap)
		}
	}
}

// files writes manifests into a fresh directory with mode 0600 and returns
// their paths.
func files(t testing.TB, contents map[string]string) (string, []string) {
	t.Helper()
	dir := t.TempDir()
	var paths []string
	for name, content := range contents {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return dir, paths
}

// inDir runs f with the working directory set to dir, so display paths are
// relative and goldens do not depend on the temporary directory.
func inDir(t testing.TB, dir string, f func()) {
	t.Helper()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(previous); err != nil {
			t.Fatal(err)
		}
	}()
	f()
}

// golden compares output with testdata/name, rewriting it with -update.
func golden(t testing.TB, name string, got []byte) {
	t.Helper()
	path := filepath.Join(testdata, name)
	if *update {
		if err := os.MkdirAll(testdata, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s differs from the golden file:\n%s", name, got)
	}
}

func jsonOf(t testing.TB, report scanreport.Report) []byte {
	t.Helper()
	raw, err := scanreport.MarshalJSON(report)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func isUsage(err error) bool {
	var usageErr *UsageError
	return errors.As(err, &usageErr)
}

func gapReasons(report scanreport.Report) []string {
	var out []string
	for _, gap := range report.Gaps {
		hop := ""
		if gap.Hop != nil {
			hop = " " + gap.Hop.From + "->" + gap.Hop.To
		}
		out = append(out, gap.Reason+hop)
	}
	return out
}

// declared are the complete Kubernetes declarations.
var declared = []string{"--distribution", "official_upstream", "--resource-scope-complete", "--target-api-apply-required"}

func args(paths []string, extra ...string) []string {
	return append(append(append([]string{}, paths...), declared...), append([]string{"--now", testNow}, extra...)...)
}

const (
	cronjobV1beta1 = "apiVersion: batch/v1beta1\nkind: CronJob\nmetadata:\n  name: nightly-report\n  namespace: default\nspec:\n  schedule: \"0 2 * * *\"\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: report-settings\n  namespace: default\ndata:\n  mode: nightly\n"
	cronjobV1      = "apiVersion: batch/v1\nkind: CronJob\nmetadata:\n  name: nightly-report\n  namespace: default\nspec:\n  schedule: \"0 2 * * *\"\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: report-settings\n  namespace: default\ndata:\n  mode: nightly\n"
)
