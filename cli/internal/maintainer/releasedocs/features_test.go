// SPDX-License-Identifier: AGPL-3.0-only

package releasedocs

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/releasenotes"
)

const wf = "name: t\non: push\njobs:\n  proof:\n    runs-on: x\n  other:\n    runs-on: x\n"

func featuresWith(demoEvidence string) string {
	return `{"schema":"prufyx.io/release-features/v1","features":[
{"id":"demo-check","title":"A check that works","state":"works","demo":"prufyx demo --flag","evidence":"` + demoEvidence + `","notYet":""},
{"id":"later","title":"A later thing","state":"not-yet","demo":"","evidence":"","notYet":"It is not built."}]}`
}

func notYetWith(reason string) string {
	return `{"schema":"prufyx.io/release-features/v1","features":[
{"id":"demo-check","title":"A check that works","state":"works","demo":"prufyx demo --flag","evidence":"file:README.md","notYet":""},
{"id":"later","title":"A later thing","state":"not-yet","demo":"","evidence":"","notYet":"` + reason + `"}]}`
}

func TestGoodFeaturesPassInEveryMode(t *testing.T) {
	e := build(t, rig{tagCurrent: true})
	wantPass(t, check(t, e.opts(ModeUnreleased)))
	wantPass(t, check(t, withDeny(t, e.opts(ModeRelease))))
}

func TestNotesRenderTheFeatureLists(t *testing.T) {
	e := build(t, rig{})
	notes := readFile(t, e.root, "cli/docs/release-notes-"+curTag+".md")
	for _, want := range []string{"### Works in this release", "- A check that works. Run: `prufyx demo --flag`", "### Not yet", "- A later thing: It is not built.", "from the knowledge pack revision `"} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes lack %q", want)
		}
	}
}

func TestNotesWithoutTheFeatureListsFail(t *testing.T) {
	// A notes file generated before the lists existed differs from its regeneration.
	e := build(t, rig{notes: func(s string) string {
		i := strings.Index(s, "### Works in this release")
		j := strings.Index(s, "### Not yet")
		k := strings.Index(s[j:], "\n### ") + j
		return s[:i] + s[k+1:]
	}})
	wantFail(t, check(t, e.opts(ModeUnreleased)), CodeNotes, "differs from its regeneration")
}

func TestFeatureListEditedByHandFails(t *testing.T) {
	e := build(t, rig{notes: replaceIn("- A later thing: It is not built.", "- A later thing: It is built.")})
	wantFail(t, check(t, e.opts(ModeUnreleased)), CodeNotes, "differs from its regeneration")
	e = build(t, rig{notes: replaceIn("- A later thing: It is not built.", "- A later thing: It is not built.\n- An extra thing: works well.")})
	wantFail(t, check(t, e.opts(ModeUnreleased)), CodeNotes, "differs from its regeneration")
}

func TestFeatureFileProblemsFail(t *testing.T) {
	cases := map[string]map[string]string{
		"missing file":        {releasenotes.FeaturesPath: ""},
		"invalid json":        {releasenotes.FeaturesPath: "{"},
		"unknown field":       {releasenotes.FeaturesPath: strings.Replace(goodFeatures, `"state": "works"`, `"state": "works", "extra": 1`, 1)},
		"unknown state":       {releasenotes.FeaturesPath: strings.Replace(goodFeatures, `"state": "works"`, `"state": "partial"`, 1)},
		"works without demo":  {releasenotes.FeaturesPath: strings.Replace(goodFeatures, `"demo": "prufyx demo --flag"`, `"demo": ""`, 1)},
		"reserved kind works": {releasenotes.FeaturesPath: strings.Replace(goodFeatures, `"id": "demo-check"`, `"id": "kind-per-version"`, 1)},
		"reserved cite works": {releasenotes.FeaturesPath: strings.Replace(goodFeatures, `"id": "demo-check"`, `"id": "source-citations"`, 1)},
	}
	for name, files := range cases {
		e := build(t, rig{files: files})
		res := check(t, e.opts(ModeUnreleased))
		if res.ExitCode() == 0 {
			t.Errorf("%s: accepted", name)
			continue
		}
		wantFail(t, res, CodeFeatures, "")
	}
}

func TestWorksNeedsExistingEvidence(t *testing.T) {
	bad := map[string]string{
		"no such file":      "file:docs/nothing.md",
		"traversal":         "file:../outside.md",
		"absolute":          "file:/etc/passwd",
		"no scheme":         "README.md",
		"unknown scheme":    "url:README.md",
		"no such workflow":  "check:absent.yml:proof",
		"no such job":       "check:ci.yml:ghost",
		"job as free text":  "check:ci.yml:name",
		"missing job":       "check:ci.yml",
		"too many parts":    "check:ci.yml:proof:extra",
		"workflow traverse": "check:../ci.yml:proof",
	}
	for name, ev := range bad {
		e := build(t, rig{features: featuresWith(ev), files: map[string]string{".github/workflows/ci.yml": wf}})
		wantFail(t, check(t, e.opts(ModeUnreleased)), CodeFeatures, "evidence")
		_ = name
	}
	for _, ev := range []string{"file:README.md", "check:ci.yml:proof", "check:ci.yml:other"} {
		e := build(t, rig{features: featuresWith(ev), files: map[string]string{".github/workflows/ci.yml": wf}})
		wantPass(t, check(t, e.opts(ModeUnreleased)))
	}
}

func TestEvidenceJobMustBeUnderJobs(t *testing.T) {
	// A two-space key under another top-level key is not a job.
	other := "name: t\nenv:\n  proof: x\njobs:\n  real:\n    runs-on: x\n"
	e := build(t, rig{features: featuresWith("check:ci.yml:proof"), files: map[string]string{".github/workflows/ci.yml": other}})
	wantFail(t, check(t, e.opts(ModeUnreleased)), CodeFeatures, "no such job")
}

func TestEvidenceSymlinkIsRefused(t *testing.T) {
	e := build(t, rig{features: featuresWith("file:link.md")})
	must(t, osSymlink(e.root, "README.md", "link.md"))
	git(t, e.root, "add", "-A")
	git(t, e.root, "commit", "-q", "-m", "link")
	wantFail(t, check(t, e.opts(ModeUnreleased)), CodeFeatures, "no such file")
}

func TestWorksDemoMustBeOnTheSmokeList(t *testing.T) {
	// The demo changes, the list does not.
	e := build(t, rig{features: strings.Replace(goodFeatures, "prufyx demo --flag", "prufyx other", 1)})
	wantFail(t, check(t, e.opts(ModeUnreleased)), CodeFeatures, "not on the CI smoke list")
	// The list is missing, invalid or empty.
	for name, text := range map[string]string{"missing": "", "invalid": "{", "empty": `{"schema":"prufyx.io/release-features-smoke/v1","entries":[]}`} {
		e := build(t, rig{files: map[string]string{releasenotes.SmokePath: text}})
		res := check(t, e.opts(ModeUnreleased))
		if res.ExitCode() != CodeFeatures {
			t.Errorf("%s: exit %d", name, res.ExitCode())
		}
	}
	// The test that runs the list is gone.
	e = build(t, rig{files: map[string]string{SmokeTestPath: ""}})
	wantFail(t, check(t, e.opts(ModeUnreleased)), CodeFeatures, "smoke list is missing")
}

func TestWorkflowSmokeEntries(t *testing.T) {
	smoke := func(workflow, contains string) string {
		return `{"schema":"prufyx.io/release-features-smoke/v1","entries":[{"demo":"prufyx demo --flag","kind":"workflow","workflow":"` + workflow + `","contains":"` + contains + `"}]}`
	}
	ok := build(t, rig{files: map[string]string{releasenotes.SmokePath: smoke("ci.yml", "verify --all"), ".github/workflows/ci.yml": wf + "      - run: prufyx verify --all\n"}})
	wantPass(t, check(t, ok.opts(ModeUnreleased)))
	noText := build(t, rig{files: map[string]string{releasenotes.SmokePath: smoke("ci.yml", "verify --all"), ".github/workflows/ci.yml": wf}})
	wantFail(t, check(t, noText.opts(ModeUnreleased)), CodeFeatures, "does not contain")
	noFile := build(t, rig{files: map[string]string{releasenotes.SmokePath: smoke("absent.yml", "x")}})
	wantFail(t, check(t, noFile.opts(ModeUnreleased)), CodeFeatures, "no such workflow")
}

func TestOnlyAWorksFeatureOwnsAFeaturePhrase(t *testing.T) {
	for _, p := range FeaturePhrases {
		// In a not-yet reason (generated into the notes): refused.
		e := build(t, rig{features: notYetWith("Maintainers will " + p + " later.")})
		wantFail(t, check(t, e.opts(ModeUnreleased)), CodeDeny, p)
		// In the hand-written text: refused.
		e = build(t, rig{notes: replaceIn("Hand written text.", "Hand written text. We say "+p+".")})
		wantFail(t, check(t, e.opts(ModeUnreleased)), CodeDeny, p)
		// In the CHANGELOG: refused.
		e = build(t, rig{changelog: replaceIn("- A hand written entry, exits 2 on failure.", "- Entry that says "+p+".")})
		wantFail(t, check(t, e.opts(ModeUnreleased)), CodeDeny, p)
		// In the README: refused.
		e = build(t, rig{readme: replaceIn("Tail text.", "We say "+p+".")})
		wantFail(t, check(t, e.opts(ModeUnreleased)), CodeDeny, p)
		// In a works feature that owns it (its rendered line): accepted.
		own := strings.Replace(goodFeatures, "A check that works", "A check that says "+p, 1)
		e = build(t, rig{features: own})
		wantPass(t, check(t, e.opts(ModeUnreleased)))
	}
	// The phrase list is pinned.
	want := "self-onboard|onboard your project yourself|tested on kubernetes|every version tested|confirmed"
	if strings.Join(FeaturePhrases, "|") != want {
		t.Fatalf("phrases = %v", FeaturePhrases)
	}
}

func TestFeaturePhraseIsCaseInsensitive(t *testing.T) {
	e := build(t, rig{notes: replaceIn("Hand written text.", "Hand written text. Tested On Kubernetes 1.30.")})
	wantFail(t, check(t, e.opts(ModeUnreleased)), CodeDeny, "tested on kubernetes")
}

func TestNotesCarryNoFreeClaims(t *testing.T) {
	// Reworded claims that no deny phrase lists still use a claim word.
	for _, text := range []string{
		"Every project is catalogued and attested.",
		"Coverage is broad.",
		"The pairs are decided.",
		"Most upgrades were tested.",
		"Nearly all CNCF projects are handled.",
		"Rules cover 90% of releases.",
	} {
		e := build(t, rig{notes: replaceIn("Hand written text.", "Hand written text. "+text)})
		wantFail(t, check(t, e.opts(ModeUnreleased)), CodeProse, "outside the generated block")
	}
	// Plain hand-written text without a claim word is fine.
	e := build(t, rig{notes: replaceIn("Hand written text.", "Hand written text. This build is for testing.")})
	wantPass(t, check(t, e.opts(ModeUnreleased)))
}

func TestDecidedIsNeverSaidOfL(t *testing.T) {
	for _, text := range []string{
		"L pairs are decided.",
		"The decided L pairs rose.",
		"Pairs that are listed, not judged count as decided.",
		"A change list is a decided answer.",
	} {
		e := build(t, rig{changelog: replaceIn("- A hand written entry, exits 2 on failure.", "- "+text)})
		wantFail(t, check(t, e.opts(ModeUnreleased)), CodeDeny, "decided")
		e = build(t, rig{notes: replaceIn("Hand written text.", "Hand written text. "+text)})
		wantFail(t, check(t, e.opts(ModeUnreleased)), CodeDeny, "decided")
	}
	// The README hand-written text too.
	e := build(t, rig{readme: replaceIn("Tail text.", "L is decided.")})
	wantFail(t, check(t, e.opts(ModeUnreleased)), CodeDeny, "decided")
	// Separate sentences, and the generated README block (which defines the forms), pass.
	e = build(t, rig{readme: replaceIn("generated text 5", "A/B is decided, then L is listed, not judged")})
	wantPass(t, check(t, e.opts(ModeUnreleased)))
	e = build(t, rig{changelog: replaceIn("- A hand written entry, exits 2 on failure.", "- Only A/B is called decided. L is something else.")})
	wantPass(t, check(t, e.opts(ModeUnreleased)))
}

func TestNoSummedCoverageNumber(t *testing.T) {
	for _, text := range []string{
		"A+B decided went up.",
		"a + b was 12.",
		"Total decided pairs went up.",
		"The overall coverage rose.",
		"Decided pairs in total went up.",
		"Combined A/B and S pairs rose.",
	} {
		e := build(t, rig{changelog: replaceIn("- A hand written entry, exits 2 on failure.", "- "+text)})
		wantFail(t, check(t, e.opts(ModeUnreleased)), CodeDeny, "summed")
		e = build(t, rig{notes: replaceIn("Hand written text.", "Hand written text. "+text)})
		wantFail(t, check(t, e.opts(ModeUnreleased)), CodeDeny, "summed")
	}
	e := build(t, rig{readme: replaceIn("Tail text.", "A+B is the old total.")})
	wantFail(t, check(t, e.opts(ModeUnreleased)), CodeDeny, "summed")
}

func TestPerFormTableRowsAreNotASum(t *testing.T) {
	// The generated per-form rows stay clean: the fixture notes pass.
	e := build(t, rig{})
	wantPass(t, check(t, e.opts(ModeUnreleased)))
}

func TestCountsHandEditStillFails(t *testing.T) {
	e := build(t, rig{})
	o := e.opts(ModeUnreleased)
	o.Regenerate = fakeRegen{counts: []byte("{}")}
	wantFail(t, check(t, o), CodeCounts, "differs from its regeneration")
}

func TestNotesCarryPackRevisionAndDigest(t *testing.T) {
	e := build(t, rig{})
	notes := readFile(t, e.root, "cli/docs/release-notes-"+curTag+".md")
	counts := readFile(t, e.root, releasenotes.CountsPath)
	if !strings.Contains(counts, `"revision"`) {
		t.Fatal("fixture counts have no pack revision")
	}
	// A notes file with the revision removed from the sentence no longer matches.
	i := strings.Index(notes, "knowledge pack revision `")
	if i < 0 {
		t.Fatal("notes do not state the revision")
	}
	bad := notes[:i] + "knowledge pack revision `x" + notes[i+len("knowledge pack revision `"):]
	e2 := build(t, rig{notes: func(string) string { return bad }})
	wantFail(t, check(t, e2.opts(ModeUnreleased)), CodeNotes, "differs from its regeneration")
}

// ---- CHANGELOG: one entry per version, tagged history ----

func TestDuplicateVersionSectionFailsTheCut(t *testing.T) {
	dup := func(s string) string { return s + "\n## [1.1.0] - 2026-01-02\n\nSecond section.\n" }
	e := build(t, rig{changelog: dup})
	wantFail(t, check(t, e.opts(ModeUnreleased)), CodeChangelog, "exactly one")
	e = build(t, rig{tagCurrent: true, changelog: dup})
	wantFail(t, check(t, withDeny(t, e.opts(ModeRelease))), CodeChangelog, "exactly one")
	o := withDeny(t, e.opts(ModeCut))
	o.SiteCounts = siteCopy(t, e)
	wantFail(t, check(t, o), CodeChangelog, "exactly one")
}

func TestUntaggedDatedSectionPlusCutHeadingFails(t *testing.T) {
	// The shape of the old untagged entry: a dated section of the version next to the generated one.
	dup := func(s string) string {
		return strings.Replace(s, "## [1.0.0]", "## [1.1.0] - 2026-11-04\n\nEarlier untagged text.\n\n## [1.0.0]", 1)
	}
	e := build(t, rig{tagCurrent: true, changelog: dup})
	o := withDeny(t, e.opts(ModeCut))
	o.SiteCounts = siteCopy(t, e)
	wantFail(t, check(t, o), CodeChangelog, "exactly one")
}

func TestInternalHistoryHeadingIsNotAVersion(t *testing.T) {
	// The generated entry sits under [Unreleased]; a non-version heading
	// carries the older hand-written entries. CI (unreleased) passes it, the
	// cut does not until the heading is renamed to the version.
	cl := "# Changelog\n\n## [Unreleased]\n\n" + releasenotes.MarkerBegin + "\n" + releasenotes.MarkerEnd + "\n\n## Internal history (pre-1.1.0 development)\n\n### Added\n\n- A hand written entry, exits 2 on failure.\n\n## [1.0.0] - 2025-12-01\n\n- Old entry with 99 things.\n"
	e := build(t, rig{tagCurrent: true, changelog: func(old string) string {
		i := strings.Index(old, "## [1.1.0]")
		j := strings.Index(old, "## [1.0.0]")
		section := old[i:j]
		b := strings.Index(section, releasenotes.MarkerBegin)
		en := strings.Index(section, releasenotes.MarkerEnd) + len(releasenotes.MarkerEnd)
		return strings.Replace(cl, releasenotes.MarkerBegin+"\n"+releasenotes.MarkerEnd, section[b:en], 1)
	}})
	wantPass(t, check(t, e.opts(ModeUnreleased)))
	wantFail(t, check(t, withDeny(t, e.opts(ModeRelease))), CodeChangelog, "exactly one")
}

func TestUnreleasedEntryMustMatchTheGenerator(t *testing.T) {
	cl := func(old string) string {
		i := strings.Index(old, "## [1.1.0]")
		j := strings.Index(old, "## [1.0.0]")
		return old[:i] + old[j:]
	}
	// No [1.1.0] heading and an empty [Unreleased] block: the entry is missing.
	e := build(t, rig{changelog: cl})
	wantFail(t, check(t, e.opts(ModeUnreleased)), CodeChangelog, "regeneration")
	// No [Unreleased] heading either.
	e = build(t, rig{changelog: func(old string) string { return strings.Replace(cl(old), "## [Unreleased]", "## Notes", 1) }})
	wantFail(t, check(t, e.opts(ModeUnreleased)), CodeChangelog, "[Unreleased]")
}

func TestTaggedHistoryMustNotBeRewritten(t *testing.T) {
	e := build(t, rig{})
	wantPass(t, check(t, e.opts(ModeUnreleased)))
	// The section of the published 1.0.0 changed.
	e = build(t, rig{changelog: replaceIn("Old entry with 99 things.", "Old entry, reworded.")})
	wantFail(t, check(t, e.opts(ModeUnreleased)), CodeChangelog, "published release")
	// The section is gone.
	e = build(t, rig{changelog: func(s string) string { return strings.Replace(s, "## [1.0.0]", "## Older", 1) }})
	wantFail(t, check(t, e.opts(ModeUnreleased)), CodeChangelog, "published release")
	// The heading of the published release was renamed.
	e = build(t, rig{changelog: replaceIn("## [1.0.0] - 2025-12-01", "## [1.0.0] - 2025-12-02")})
	wantFail(t, check(t, e.opts(ModeUnreleased)), CodeChangelog, "published release")
}
