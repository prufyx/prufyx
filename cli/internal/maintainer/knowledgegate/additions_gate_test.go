// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/coveragereport"
)

const addTags = "refs/tags/v1.1.0\nrefs/tags/v1.2.0\nrefs/tags/v1.2.1\nrefs/tags/v1.3.0\n"

func addPath(tr Tree) string {
	return filepath.Join(tr.Root, filepath.FromSlash(coveragereport.PinnedAdditionsPath))
}

func tagPath(tr Tree, slug string) string {
	return filepath.Join(tr.Root, filepath.FromSlash(coveragereport.PinnedTagsDir), coveragereport.TagFileName(slug))
}

// putAdditions writes an additions file with one entry per slug (each from
// addTags, captured on the given date) and the tag files.
func putAdditions(t *testing.T, tr Tree, on string, slugs ...string) {
	t.Helper()
	entries := map[string]coveragereport.AdditionEntry{}
	for _, s := range slugs {
		e, err := coveragereport.SealAddition(s, []byte(addTags), on, false, "")
		if err != nil {
			t.Fatal(err)
		}
		entries[s] = e
		writeFile(t, tagPath(tr, s), []byte(addTags))
	}
	raw, err := coveragereport.MarshalAdditions(coveragereport.AdditionsFile{Additions: entries})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, addPath(tr), raw)
}

func mustFail(t *testing.T, name string, base, head Tree, want string) {
	t.Helper()
	c := shippedFloorCheck(base, head)
	if c.OK || !strings.Contains(c.Detail, want) {
		t.Errorf("%s: want a refusal containing %q, got %+v", name, want, c)
	}
}

func mustPass(t *testing.T, name string, base, head Tree) {
	t.Helper()
	if c := shippedFloorCheck(base, head); !c.OK {
		t.Errorf("%s: refused: %s", name, c.Detail)
	}
}

func TestAdditionsAbsentOnBothSidesChangeNothing(t *testing.T) {
	t.Parallel()
	base, head := shippedSlice(t), shippedSlice(t)
	mustPass(t, "absent", base, head)
	writeFile(t, addPath(head), nil)
	mustPass(t, "empty head file", base, head)
	before := decidedPairs(t, base)
	if after := decidedPairs(t, head); after != before {
		t.Errorf("an empty additions file moved decided pairs %d -> %d", before, after)
	}
}

// The pinned snapshot is held byte-identical between base and head.
func TestPinnedLinesByteIdentity(t *testing.T) {
	t.Parallel()
	base, head := shippedSlice(t), shippedSlice(t)
	p := filepath.Join(head.Root, filepath.FromSlash(coveragereport.PinnedLinesPath))
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, p, append(raw, '\n')) // a whitespace-only change
	mustFail(t, "one byte added", base, head, "differs from the base branch")
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	mustFail(t, "file removed", base, head, "no readable pinned lines snapshot")
}

func TestAdditionsBootstrapBaseAbsent(t *testing.T) {
	t.Parallel()
	base, head := shippedSlice(t), shippedSlice(t)
	putAdditions(t, head, "2026-11-07", "zz-new")
	mustPass(t, "base absent, head introduces", base, head)
	// ...but every head key is validated: a head entry without its tag file.
	if err := os.Remove(tagPath(head, "zz-new")); err != nil {
		t.Fatal(err)
	}
	mustFail(t, "no tag file", base, head, "has no tag file")
}

func TestAdditionsAreAppendOnly(t *testing.T) {
	t.Parallel()
	mk := func() (Tree, Tree) {
		base, head := shippedSlice(t), shippedSlice(t)
		putAdditions(t, base, "2026-11-07", "zz-one")
		putAdditions(t, head, "2026-11-07", "zz-one")
		return base, head
	}
	base, head := mk()
	mustPass(t, "unchanged", base, head)
	putAdditions(t, head, "2026-11-07", "zz-one", "zz-two")
	mustPass(t, "a new key is appended", base, head)

	_, head = mk()
	if err := os.Remove(addPath(head)); err != nil {
		t.Fatal(err)
	}
	mustFail(t, "head file absent while base present", base, head, "removes or renames the additions file")

	_, head = mk()
	putAdditions(t, head, "2026-11-07") // the file with no key
	if err := os.Remove(tagPath(head, "zz-one")); err != nil {
		t.Fatal(err)
	}
	mustFail(t, "key removed", base, head, "removes or renames the added project zz-one")

	_, head = mk()
	putAdditions(t, head, "2026-11-07", "zz-renamed")
	if err := os.Remove(tagPath(head, "zz-one")); err != nil {
		t.Fatal(err)
	}
	mustFail(t, "key renamed", base, head, "removes or renames the added project zz-one")

	// Delete and re-add the same key with another value (another date): an edit.
	_, head = mk()
	putAdditions(t, head, "2026-11-06", "zz-one")
	mustFail(t, "delete and re-add with a changed value", base, head, "an added entry is immutable")

	// A value edit that keeps its digest valid (re-sealed with another tag set).
	_, head = mk()
	other := addTags + "refs/tags/v1.4.0\n"
	e, err := coveragereport.SealAddition("zz-one", []byte(other), "2026-11-07", false, "")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := coveragereport.MarshalAdditions(coveragereport.AdditionsFile{Additions: map[string]coveragereport.AdditionEntry{"zz-one": e}})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, addPath(head), raw)
	writeFile(t, tagPath(head, "zz-one"), []byte(other))
	mustFail(t, "a resealed edit", base, head, "an added entry is immutable")

	// A base that does not parse fails closed.
	base2, head2 := mk()
	writeFile(t, addPath(base2), []byte("{not json"))
	mustFail(t, "base unparsable", base2, head2, "base additions file")

	// An unparsable head file fails too.
	_, head = mk()
	writeFile(t, addPath(head), []byte("{not json"))
	mustFail(t, "head unparsable", base, head, "change's additions file")
}

func TestAdditionsAreRegeneratedFromTheirTagFiles(t *testing.T) {
	t.Parallel()
	base := shippedSlice(t)
	mk := func() Tree {
		h := shippedSlice(t)
		putAdditions(t, h, "2026-11-07", "zz-new")
		return h
	}
	head := mk()
	writeFile(t, tagPath(head, "zz-new"), []byte(strings.Replace(addTags, "refs/tags/v1.2.1\n", "", 1)))
	mustFail(t, "newest patch omitted from the tag file", base, head, "does not match tagFileSha256")

	head = mk()
	writeFile(t, tagPath(head, "zz-orphan"), []byte(addTags))
	mustFail(t, "a tag file without an entry", base, head, "belongs to no added project")

	// A key that is already a pinned project.
	head = shippedSlice(t)
	var pinned string
	raw, err := os.ReadFile(filepath.Join(head.Root, filepath.FromSlash(coveragereport.PinnedLinesPath)))
	if err != nil {
		t.Fatal(err)
	}
	lf, err := coveragereport.ParseLines(raw)
	if err != nil {
		t.Fatal(err)
	}
	for s := range lf.Projects {
		pinned = s
		break
	}
	putAdditions(t, head, "2026-11-07", pinned)
	mustFail(t, "key also pinned", base, head, "never overrides")

	// capturedOn after the gate's date.
	head = shippedSlice(t)
	putAdditions(t, head, "2999-01-01", "zz-future")
	mustFail(t, "captured in the future", base, head, "after the gate's date")
}

// An addition moves the clock to its capture date, and the numbers follow the
// union; the base floor still holds for every old project.
func TestAdditionsMoveTheClockAndAddProjects(t *testing.T) {
	t.Parallel()
	base, head := shippedSlice(t), shippedSlice(t)
	_, _, before, err := coverageReportOf(head)
	if err != nil {
		t.Fatal(err)
	}
	putAdditions(t, head, "2026-11-10", "zz-new")
	r, _, after, err := coverageReportOf(head)
	if err != nil {
		t.Fatal(err)
	}
	if !after.After(before) || after.Format("2006-01-02") != "2026-11-10" {
		t.Fatalf("clock %v -> %v", before, after)
	}
	if r.Additions == nil || r.Additions.Entries != 1 {
		t.Fatalf("report %+v", r.Additions)
	}
	// The moved clock is gate-checked on the shipped data: a failure here
	// would mean an old attestation expires under the 11-10 clock.
	mustPass(t, "clock moved by an addition", base, head)
	rb, _, _, _ := coverageReportOf(base)
	if r.Fleet.Projects != rb.Fleet.Projects+1 {
		t.Errorf("projects %d -> %d", rb.Fleet.Projects, r.Fleet.Projects)
	}
}

// R3: the additions file and the tag files are allowed in a batch and an
// onboarding change, only as <slug>.tags, never the baseline, never in
// AutoMergePaths.
func TestAdditionsPathsAreAllowedButNotMechanical(t *testing.T) {
	t.Parallel()
	layout := DefaultLayout()
	base, head := shippedSlice(t), shippedSlice(t)
	putAdditions(t, head, "2026-11-07", "zz-new")
	writeFile(t, filepath.Join(head.Root, filepath.FromSlash(coveragereport.PinnedTagsDir), "Bad_Name.tags"), []byte("x"))
	// Bad_Name.tags is in the head, so the directory must read; it is not allowed.
	tagRel := coveragereport.PinnedTagsDir + "/" + coveragereport.TagFileName("zz-new")
	st := &onboardingState{layout: layout, baseTree: base, headTree: head}
	for name, allowed := range map[string]map[string]bool{
		"batch":      batchAllowedPaths(layout, base, head, "batch.json"),
		"onboarding": st.allowedPaths(OnboardingRecord{}, "batch.json"),
	} {
		if !allowed[coveragereport.PinnedAdditionsPath] || !allowed[tagRel] {
			t.Errorf("%s: the additions file or its tag file is not allowed", name)
		}
		if allowed[coveragereport.PinnedTagsDir+"/Bad_Name.tags"] || allowed[coveragereport.PinnedTagsDir+"/other.txt"] {
			t.Errorf("%s: a tag path outside <slug>.tags is allowed", name)
		}
		if allowed[coveragereport.BaselinePath] || allowed[coveragereport.PinnedLinesPath] {
			t.Errorf("%s: the baseline or the pinned snapshot is allowed (bots never write them)", name)
		}
	}
	for _, rel := range []string{coveragereport.PinnedAdditionsPath, tagRel, coveragereport.BaselinePath, coveragereport.PinnedLinesPath} {
		if layout.autoMergePath(rel) {
			t.Errorf("%s is an auto-merge path", rel)
		}
	}
	for _, g := range layout.GeneratedBlocks {
		if g.Path == coveragereport.PinnedAdditionsPath {
			t.Error("the additions file is a generated block")
		}
	}
}

// A change to the additions file is never eligible for an automatic merge, and
// the reason names it as outside the knowledge files. Control: the same trees
// without the addition carry no such reason.
func TestAdditionsChangeIsNotEligibleForAutoMerge(t *testing.T) {
	t.Parallel()
	outside := func(r *Report) string {
		for _, reason := range r.AutoMerge.Reasons {
			if strings.Contains(reason, "outside the knowledge files") {
				return reason
			}
		}
		return ""
	}
	base, head, _ := floorTrees(t)
	if got := outside(runGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin})); got != "" {
		t.Fatalf("control: the trees without an addition already touch outside files: %s", got)
	}
	putAdditions(t, head, "2026-11-07", "zz-new")
	r := runGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin})
	if r.AutoMerge.Eligible {
		t.Fatal("a change to the additions file is eligible for automatic merging")
	}
	got := outside(r)
	if !strings.Contains(got, coveragereport.PinnedAdditionsPath) {
		t.Fatalf("the refusal does not name the additions file: %q", got)
	}
}

// The shipped-tree helpers copy the additions file and the tag files when the
// source tree has them, so the shipped-tree tests follow the README block.
func TestShippedSliceIncludesAdditionsWhenPresent(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	got, err := additionFilesIn(root)
	if err != nil || len(got) != 0 {
		t.Fatalf("an empty tree lists %v (%v)", got, err)
	}
	writeFile(t, filepath.Join(root, filepath.FromSlash(coveragereport.PinnedAdditionsPath)), []byte("{}"))
	writeFile(t, filepath.Join(root, filepath.FromSlash(coveragereport.PinnedTagsDir), "zz.tags"), []byte("v1.0.0\n"))
	got, err = additionFilesIn(root)
	want := []string{coveragereport.PinnedAdditionsPath, coveragereport.PinnedTagsDir + "/zz.tags"}
	if err != nil || strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("listed %v (%v), want %v", got, err, want)
	}
	// And the slice of the real tree holds whatever the repository has.
	slice := shippedSlice(t)
	real, err := additionFiles()
	if err != nil {
		t.Fatal(err)
	}
	for _, rel := range real {
		if !slice.Exists(rel) {
			t.Errorf("the shipped slice lacks %s", rel)
		}
	}
}
