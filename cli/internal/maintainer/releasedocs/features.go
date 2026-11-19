// SPDX-License-Identifier: AGPL-3.0-only

package releasedocs

import (
	"bufio"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/maintainer/releasenotes"
)

// SmokeTestPath is the test that runs every binary entry of the smoke list
// against the built binary in the ordinary CI test job. The gate requires the
// file to exist; CODEOWNERS covers it.
const SmokeTestPath = "cli/cmd/prufyx-community/release_features_smoke_test.go"

// FeaturePhrases are claims that only a works feature may make. They are
// matched case-insensitively in the notes, the CHANGELOG sections under check
// and the README, after the rendered lines of the works features are taken
// out. They are a backstop: the notes may only carry sentences the generator
// wrote (see NotesFixedLines).
var FeaturePhrases = []string{"self-onboard", "onboard your project yourself", "tested on kubernetes", "every version tested", "confirmed"}

var (
	decidedWord = regexp.MustCompile(`(?i)\bdecided\b`)
	listedForm  = regexp.MustCompile(`\bL\b|(?i:\blisted,? not judged\b|\bchange lists?\b)`)
	summedA     = regexp.MustCompile(`(?i)\bA\s*\+\s*B\b`)
	summedB     = regexp.MustCompile(`(?i)\b(?:total|sum|overall|combined|altogether)\b.{0,60}\b(?:decided|covered|coverage|pairs|A/B|S|L|G)\b|\b(?:decided|covered|coverage|pairs)\b.{0,40}\b(?:in total|altogether|combined|summed)\b`)
	segmentEnd  = regexp.MustCompile(`[.;!?]\s+|\n|\|`)
	jobKey      = regexp.MustCompile(`^  ([A-Za-z0-9_-]+):\s*$`)
	evidenceRef = regexp.MustCompile(`^(file|check):(.+)$`)
)

// checkFeatures verifies the feature file of the tree and everything its
// "works" statements rest on: the evidence exists and the demo is on the CI
// smoke list. It returns the file, or nil when it cannot be used.
func (c *checker) checkFeatures() *releasenotes.Features {
	raw, err := c.readRoot(releasenotes.FeaturesPath)
	if err != nil {
		c.fail(CodeFeatures, "%s: %v", releasenotes.FeaturesPath, err)
		return nil
	}
	f, err := releasenotes.LoadFeatures(raw)
	if err != nil {
		c.fail(CodeFeatures, "%v", err)
		return nil
	}
	var works []releasenotes.Feature
	for _, x := range f.Features {
		if x.State == releasenotes.StateWorks {
			works = append(works, x)
		}
	}
	for _, x := range works {
		if msg := c.evidenceProblem(x.Evidence); msg != "" {
			c.fail(CodeFeatures, "feature %s: evidence %q: %s", x.ID, x.Evidence, msg)
		}
	}
	if len(works) == 0 {
		return f
	}
	sraw, err := c.readRoot(releasenotes.SmokePath)
	if err != nil {
		c.fail(CodeFeatures, "%s: %v", releasenotes.SmokePath, err)
		return f
	}
	smoke, err := releasenotes.LoadSmoke(sraw)
	if err != nil {
		c.fail(CodeFeatures, "%v", err)
		return f
	}
	if _, err := c.readRoot(SmokeTestPath); err != nil {
		c.fail(CodeFeatures, "%s: the test that runs the smoke list is missing: %v", SmokeTestPath, err)
	}
	byDemo := map[string]bool{}
	for _, e := range smoke.Entries {
		byDemo[e.Demo] = true
	}
	for _, x := range works {
		if !byDemo[x.Demo] {
			c.fail(CodeFeatures, "feature %s: the demo command is not on the CI smoke list (%s)", x.ID, releasenotes.SmokePath)
			continue
		}
	}
	return f
}

// evidenceProblem verifies "file:<repo path>" (a regular file in the tree) or
// "check:<workflow file>:<job id>" (a job of that workflow).
func (c *checker) evidenceProblem(ref string) string {
	m := evidenceRef.FindStringSubmatch(ref)
	if m == nil {
		return "must be file:<path> or check:<workflow>:<job>"
	}
	if m[1] == "file" {
		if !filepath.IsLocal(m[2]) || strings.Contains(m[2], `\`) {
			return "the path is not a local repository path"
		}
		if _, err := c.readRoot(m[2]); err != nil {
			return "no such file in the tree"
		}
		return ""
	}
	parts := strings.Split(m[2], ":")
	if len(parts) != 2 || !workflowFile(parts[0]) || !jobKey.MatchString("  "+parts[1]+":") {
		return "a check is <workflow file>:<job id>"
	}
	raw, err := c.readRoot(".github/workflows/" + parts[0])
	if err != nil {
		return "no such workflow"
	}
	if !hasJob(string(raw), parts[1]) {
		return "the workflow has no such job"
	}
	return ""
}

func workflowFile(n string) bool {
	return regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml$`).MatchString(n)
}

func hasJob(workflow, job string) bool {
	in := false
	sc := bufio.NewScanner(strings.NewReader(workflow))
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		l := strings.TrimRight(sc.Text(), " \r")
		if l == "jobs:" {
			in = true
			continue
		}
		if !in {
			continue
		}
		if l != "" && l[0] != ' ' && l[0] != '#' {
			in = false
			continue
		}
		if m := jobKey.FindStringSubmatch(l); m != nil && m[1] == job {
			return true
		}
	}
	return false
}

// segments splits text into the units the form rules read: a sentence, a
// table cell or a line.
func segments(text string) []string { return segmentEnd.Split(text, -1) }

// formClaims applies the rules on how the forms may be spoken of: "decided"
// is never said of L, and no coverage figure is a sum of forms.
func (c *checker) formClaims(name, text string) {
	for _, seg := range segments(text) {
		if decidedWord.MatchString(seg) && listedForm.MatchString(seg) {
			c.fail(CodeDeny, "%s: \"decided\" is said of the listed-not-judged form: %s", name, clip(seg, 0))
		}
		if summedA.MatchString(seg) || summedB.MatchString(seg) {
			c.fail(CodeDeny, "%s: a summed coverage figure is not allowed: %s", name, clip(seg, 0))
		}
	}
}

// NotesFixedLines are the only hand-written lines a notes file may carry
// outside its generated block, besides blank lines, the title and the two
// section headings (NotesHeadings). They are the standing disclaimer and the
// known limitations; anything else is prose, and prose is refused: every
// claim the notes make is generated. Changing this list changes the gate.
var NotesFixedLines = []string{
	"This prerelease is for testing. A passing",
	"claim covers only the rules and declared inputs evaluated; it does not establish",
	"that a whole upgrade is safe.",
	"- Results depend on the selected knowledge, its validity, and the completeness",
	"  of the supplied inputs. Missing evidence remains unknown.",
	"- Declared-state plans describe caller-supplied reference states. They do not",
	"  establish that an upgrade or remediation was executed.",
	"- Application ordering and runtime behavior require separate evidence.",
	"- The MariaDB Operator project check uses embedded knowledge by default. An",
	"  explicit local knowledge store may be selected for supported rules.",
}

// NotesHeadings are the section headings a notes file may carry.
var NotesHeadings = []string{"## Known limitations", "## What changed in this release"}

var notesTitle = regexp.MustCompile(`^# Prufyx(?: Community)? v[0-9A-Za-z.+-]+$`)

// proseOutside refuses, in the text outside the generated block of a notes
// file, every line that is not blank, the title, a fixed heading or a fixed
// line. There is no keyword test: a reworded claim is prose and fails.
func (c *checker) proseOutside(name string, outside []string) {
	ok := map[string]bool{}
	for _, l := range NotesFixedLines {
		ok[l] = true
	}
	for _, h := range NotesHeadings {
		ok[h] = true
	}
	for _, l := range outside {
		t := strings.TrimRight(l, " \r")
		if strings.TrimSpace(t) == "" || ok[t] || notesTitle.MatchString(t) {
			continue
		}
		c.fail(CodeProse, "%s: prose outside the generated block (the notes carry only generated sentences and the fixed disclaimer lines): %s", name, clip(t, 0))
	}
}

// withoutOwned removes the rendered lines of the works features: only those
// may carry a feature phrase.
func withoutOwned(text string, owned map[string]bool) string {
	var keep []string
	for _, l := range strings.Split(text, "\n") {
		if owned[strings.TrimRight(l, " \r")] {
			continue
		}
		keep = append(keep, l)
	}
	return strings.Join(keep, "\n")
}

func (c *checker) featurePhrases(name, whole string) {
	lower := strings.ToLower(withoutOwned(whole, c.owned))
	for _, p := range FeaturePhrases {
		if strings.Contains(lower, p) {
			c.fail(CodeDeny, "%s: the phrase %q is only allowed in a works feature that owns it", name, p)
		}
	}
}

// taggedHistory refuses a CHANGELOG whose section of a published release
// differs from the section committed at that tag.
func (c *checker) taggedHistory(changelog string) {
	out, err := c.git("tag", "--list", "v*")
	if err != nil {
		c.fail(CodeChangelog, "cannot list the tags: %v", err)
		return
	}
	var tags []string
	for _, t := range strings.Fields(out) {
		if tagGrammar.MatchString(t) {
			tags = append(tags, t)
		}
	}
	sort.Strings(tags)
	for _, t := range tags {
		old, err := c.git("show", "refs/tags/"+t+":CHANGELOG.md")
		if err != nil {
			continue // the file did not exist at that tag
		}
		version := strings.TrimPrefix(t, "v")
		was, ok := changelogSection(old+"\n", version)
		if !ok {
			continue
		}
		now, ok := changelogSection(changelog, version)
		if !ok || strings.TrimRight(now, "\n") != strings.TrimRight(was, "\n") {
			c.fail(CodeChangelog, "CHANGELOG.md [%s]: the section of a published release differs from the section committed at %s", version, t)
		}
	}
}
