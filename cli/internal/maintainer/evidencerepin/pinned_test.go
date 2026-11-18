// SPDX-License-Identifier: AGPL-3.0-only

package evidencerepin

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

const pinnedBody = "a\ncited line\nc"

// pinnedRules writes a rule pack with the one rule of a lineFixture, on the
// given lease, citing the document pinned at v1.25.0.
func (f *lineFixture) pinnedRules(t *testing.T, lease string) string {
	t.Helper()
	entry := ruleEntry("proj", "proj.rule-1-25-to-1-26",
		source("proj-v1-25-0-doc", "example", "proj", f.commits["v1.25.0"], "doc.md", sourcecorpus.SHA([]byte(pinnedBody)), 2, 2))
	if lease != "" {
		entry["rule"].(map[string]any)["evidence"].(map[string]any)["lease"] = lease
	}
	path := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(path, rulePackJSON(t, entry), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func (f *lineFixture) repinPinned(t *testing.T, rules string, extra ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut strings.Builder
	args := append([]string{"repin", "--rules", rules, "--output", filepath.Join(t.TempDir(), "w.json"), "--pinned-only"}, extra...)
	code = Run(context.Background(), args, &out, &errOut, f.api, f.blobs, fixedNow(), nil)
	return code, out.String(), errOut.String()
}

// A pinned citation unchanged on its release line passes, even though the
// repository's newest release has moved on.
func TestPinnedOnlyPassesAnUnchangedLine(t *testing.T) {
	f := newLineFixture(standardTags, nil, "v1.26.0")
	f.blob("v1.25.0", "doc.md", pinnedBody)
	f.blob("v1.25.3", "doc.md", pinnedBody)
	f.blob("v1.26.0", "doc.md", "a\nREWRITTEN\nc")
	code, stdout, stderr := f.repinPinned(t, f.pinnedRules(t, "pinned"))
	if code != 0 || !strings.Contains(stdout, "pinned-only: 1 pinned citations checked, 0 findings") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

// A later patch release on the same line that changes the cited span is drift:
// a one-byte change is enough, and the check exits non-zero.
func TestPinnedOnlyDetectsADriftedSpanOnTheLine(t *testing.T) {
	f := newLineFixture(standardTags, nil, "v1.26.0")
	f.blob("v1.25.0", "doc.md", pinnedBody)
	f.blob("v1.25.3", "doc.md", "a\ncited linf\nc")
	f.blob("v1.26.0", "doc.md", pinnedBody) // identical on the newest line: must not mask the drift
	code, _, stderr := f.repinPinned(t, f.pinnedRules(t, "pinned"))
	if code != ExitPinnedDrift || !strings.Contains(stderr, "pinned drift: rule proj.rule-1-25-to-1-26 source proj-v1-25-0-doc: "+ClassContentChanged) {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}

// A revision that cannot be fetched is not a pass. When the file changed
// elsewhere on the line, the span is proven from the file at the pinned commit,
// so a missing pinned file fails the check (the same file present proves the
// span unchanged); a missing file at the line's newest release fails it too.
func TestPinnedOnlyFailsOnAnUnreachableRevision(t *testing.T) {
	newer := pinnedBody + "\nappended on the line"
	f := newLineFixture(standardTags, nil, "v1.26.0")
	f.blob("v1.25.3", "doc.md", newer)
	f.blob("v1.25.0", "doc.md", pinnedBody)
	if code, stdout, stderr := f.repinPinned(t, f.pinnedRules(t, "pinned")); code != 0 {
		t.Fatalf("control: the span is unchanged on the line: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}

	missingPinned := newLineFixture(standardTags, nil, "v1.26.0")
	missingPinned.blob("v1.25.3", "doc.md", newer) // the pinned commit's file is missing
	code, _, stderr := missingPinned.repinPinned(t, missingPinned.pinnedRules(t, "pinned"))
	if code != ExitPinnedDrift || !strings.Contains(stderr, "pinned drift:") {
		t.Fatalf("missing pinned file: code=%d stderr=%q", code, stderr)
	}

	missingNewest := newLineFixture(standardTags, nil, "v1.26.0")
	missingNewest.blob("v1.25.0", "doc.md", pinnedBody) // the line's newest release has no such file
	code, _, stderr = missingNewest.repinPinned(t, missingNewest.pinnedRules(t, "pinned"))
	if code != ExitPinnedDrift || !strings.Contains(stderr, "pinned drift:") {
		t.Fatalf("missing newest file: code=%d stderr=%q", code, stderr)
	}
}

// Only the citations of pinned rules are checked.
func TestPinnedOnlyIgnoresTimeLeaseRules(t *testing.T) {
	f := newLineFixture(standardTags, nil, "v1.26.0")
	f.blob("v1.25.0", "doc.md", pinnedBody)
	f.blob("v1.25.3", "doc.md", "a\nthis drifted\nc")
	for _, lease := range []string{"", "time"} {
		code, stdout, stderr := f.repinPinned(t, f.pinnedRules(t, lease))
		if code != 0 || !strings.Contains(stdout, "0 pinned citations checked") {
			t.Fatalf("lease %q: code=%d stdout=%q stderr=%q", lease, code, stdout, stderr)
		}
	}
}

// A partial or latest-release run could read as a pass, so it is refused.
func TestPinnedOnlyRefusesPartialRuns(t *testing.T) {
	f := newLineFixture(standardTags, nil, "v1.26.0")
	rules := f.pinnedRules(t, "pinned")
	for _, extra := range [][]string{{"--baseline", "latest"}, {"--limit", "1"}, {"--project", "proj"}} {
		if code, _, stderr := f.repinPinned(t, rules, extra...); code != 2 || !strings.Contains(stderr, "--pinned-only") {
			t.Fatalf("%v: code=%d stderr=%q", extra, code, stderr)
		}
	}
}

func TestPinnedDriftReportsEveryWayACitationFailsTheCheck(t *testing.T) {
	good := ClassResult{RuleID: "r", SourceID: "s", Class: ClassFileIdentical, Baseline: BaselineReleaseLine, BaselineLine: "1.25", PinnedTag: "v1.25.0"}
	if got := PinnedDrift(Worklist{Citations: []ClassResult{good}}, 1); len(got) != 0 {
		t.Fatalf("a clean citation: %v", got)
	}
	tagLine := good
	tagLine.Baseline = BaselineTagLine
	if got := PinnedDrift(Worklist{Citations: []ClassResult{tagLine}}, 1); len(got) != 0 {
		t.Fatalf("a tag line is a release line: %v", got)
	}
	for name, mutate := range map[string]func(*ClassResult){
		"changed":          func(c *ClassResult) { c.Class = ClassContentChanged },
		"moved":            func(c *ClassResult) { c.Class = ClassSpanMoved },
		"path gone":        func(c *ClassResult) { c.Class = ClassPathGone },
		"pending":          func(c *ClassResult) { c.Class = ClassPending },
		"no baseline":      func(c *ClassResult) { c.Class = ClassNoReleaseBaseline },
		"digest mismatch":  func(c *ClassResult) { c.Class = ClassCorpusDigestMismatch },
		"latest baseline":  func(c *ClassResult) { c.Baseline = BaselineLatest },
		"no baseline kind": func(c *ClassResult) { c.Baseline = "" },
		"owner choice":     func(c *ClassResult) { c.Baseline = BaselineOwnerChoice },
		"no line":          func(c *ClassResult) { c.BaselineLine = "" },
		"no pinned tag":    func(c *ClassResult) { c.PinnedTag = "" },
		"stale":            func(c *ClassResult) { c.Stale = true },
		"tags list only":   func(c *ClassResult) { c.Resolution = resolutionTagFallback },
	} {
		bad := good
		mutate(&bad)
		if got := PinnedDrift(Worklist{Citations: []ClassResult{bad}}, 1); len(got) != 1 {
			t.Errorf("%s: %v", name, got)
		}
	}
	if got := PinnedDrift(Worklist{}, 1); len(got) != 1 {
		t.Fatalf("a missing result must not read as a pass: %v", got)
	}
	if got := PinnedDrift(Worklist{Citations: []ClassResult{good, good}}, 1); len(got) != 1 {
		t.Fatalf("an unexpected extra result: %v", got)
	}
}
