// SPDX-License-Identifier: AGPL-3.0-only

package changelogattest

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	ce "github.com/prufyx/prufyx/cli/internal/extract/changelogentries"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// changeItem is the [CHANGE] item of 3.5.0.
func changeItem(t *testing.T, r extract.PinnedReader) ce.Item {
	t.Helper()
	for _, it := range entry(t, r, "3.5.0").Items {
		if it.Marker == "CHANGE" {
			return it
		}
	}
	t.Fatal("no CHANGE item")
	return ce.Item{}
}

// ruleMark binds the CHANGE item of 3.5.0 to rule id.
func ruleMark(t *testing.T, r extract.PinnedReader, id string) Mark {
	it := changeItem(t, r)
	return Mark{ItemDigest: it.Digest, Occurrence: it.Occurrence, Tag: "v3.5.0", Kind: KindRule, RuleID: id,
		State: StateReviewed, ReviewedAt: "2026-11-01T00:00:00Z", ProposedBy: ProposedByPerson}
}

func citingRule(t *testing.T, r extract.PinnedReader, id string, shift int) []byte {
	e := entry(t, r, "3.5.0")
	it := changeItem(t, r)
	return ruleJSON(id, "3.5.0", "3.5.0", "active", commit(3), e.Source.FileDigest, it.StartLine+shift, it.EndLine+shift)
}

func TestAttestsAWindow(t *testing.T) {
	r := newReader(nil)
	rule := citingRule(t, r, "prom.change.b", 0)
	marks := append(marksFor(t, r, "v3.5.0#"+fmt.Sprint(changeItem(t, r).StartLine)), ruleMark(t, r, "prom.change.b"))
	res, err := attest(t, r, dispositions(marks), [][]byte{rule}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := res.Candidate
	if c.Basis != extract.BasisMechanical || c.Component != component || c.Line != "3.5" || c.FactFamily != lineattest.FamilyChangelogAttestedEntries {
		t.Fatalf("%+v", c)
	}
	if !slices.Equal(c.RuleIDs, []string{"prom.change.b"}) {
		t.Fatalf("rule ids %v", c.RuleIDs)
	}
	wantFrom := []lineattest.Release{{Version: "3.4.0", Commit: commit(1)}, {Version: "3.4.1", Commit: commit(2)}}
	wantTo := []lineattest.Release{{Version: "3.5.0", Commit: commit(3)}, {Version: "3.5.1", Commit: commit(4)}}
	if !reflect.DeepEqual(c.Releases.From, wantFrom) || !reflect.DeepEqual(c.Releases.To, wantTo) {
		t.Fatalf("releases %+v", c.Releases)
	}
	// One source per window tag, at that tag's commit, whole section; Lf.0 is not a source.
	if len(c.Sources) != 3 {
		t.Fatalf("sources %+v", c.Sources)
	}
	for i, ver := range []string{"3.4.1", "3.5.0", "3.5.1"} {
		e := entry(t, r, ver)
		s := c.Sources[i]
		if s.ID != "changelog-"+ver || s.Commit != e.TagCommit || s.Path != "CHANGELOG.md" || s.Repo != repo ||
			s.StartLine != e.Section.StartLine || s.EndLine != e.Section.EndLine {
			t.Fatalf("source %d: %+v vs %+v", i, s, e.Section)
		}
	}
	text, ok := ScopeText(res.Proof)
	want := "according to the upstream changelog entries of tags v3.4.1..v3.5.1, each read in full at its own tag: every item is either covered by a listed rule or is not a breaking change, removal, rename, deprecation, storage/API format change or minimum-version change as the changelog words and files it; not anything the changelog omits, not behaviour, defaults or performance, not charts or dependencies unless the entry names them"
	if !ok || text != want {
		t.Fatalf("scope text %q", text)
	}
	// The member table stays empty.
	f, _ := lineattest.LookupFamily(lineattest.FamilyChangelogAttestedEntries)
	if len(f.Components()) != 0 {
		t.Fatalf("members %v", f.Components())
	}
	// Deterministic.
	again, err := attest(t, newReader(nil), dispositions(marks), [][]byte{rule}, nil)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(res)
	b, _ := json.Marshal(again)
	if string(a) != string(b) {
		t.Fatal("two derivations differ")
	}
}

func TestLfZeroIsNotRead(t *testing.T) {
	// The entry of 3.4.0 is broken (no such heading): it must not matter, and
	// its commit must never be read.
	r := newReader(nil)
	r.files[commit(1)+":CHANGELOG.md"] = "garbage"
	marks := marksFor(t, r)
	if _, err := attest(t, r, dispositions(marks), nil, nil); err != nil {
		t.Fatal(err)
	}
	if r.readAt(commit(1)) {
		t.Fatal("the commit of Lf.0 was read")
	}
}

func TestQuietWindowHasAnEmptyRuleList(t *testing.T) {
	r := newReader(nil)
	res, err := attest(t, r, dispositions(marksFor(t, r)), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Candidate.RuleIDs == nil || len(res.Candidate.RuleIDs) != 0 {
		t.Fatalf("%#v", res.Candidate.RuleIDs)
	}
	for _, d := range res.Proof.Dispositions {
		if !strings.HasPrefix(d.Disposition, "reviewed-neutral:") {
			t.Fatalf("%+v", d)
		}
	}
}

func TestEveryItemNeedsADisposition(t *testing.T) {
	r := newReader(nil)
	all := marksFor(t, r)
	for i := range all {
		without := append(append([]Mark{}, all[:i]...), all[i+1:]...)
		_, err := attest(t, r, dispositions(without), nil, nil)
		wantCode(t, err, ce.ItemUnresolved)
	}
	// No dispositions at all, and no classifier: nothing is mechanical-neutral.
	_, err := attest(t, r, dispositions(nil), nil, nil)
	wantCode(t, err, ce.ItemUnresolved)
}

func TestMarkWithWrongDigest(t *testing.T) {
	r := newReader(nil)
	all := marksFor(t, r)
	// The right mark is replaced by one with another digest: the item is unresolved.
	bad := append([]Mark{}, all...)
	bad[0].ItemDigest = strings.Repeat("a", 64)
	_, err := attest(t, r, dispositions(bad), nil, nil)
	wantCode(t, err, ce.ItemUnresolved)
	// An extra mark for a tag of the window that matches no item is refused too.
	extra := append(append([]Mark{}, all...), all[0])
	extra[len(extra)-1].ItemDigest = strings.Repeat("b", 64)
	_, err = attest(t, r, dispositions(extra), nil, nil)
	wantCode(t, err, ce.ItemUnresolved)
	// A right digest under another tag is not accepted.
	moved := append([]Mark{}, all...)
	moved[0].Tag = "v3.5.1"
	_, err = attest(t, r, dispositions(moved), nil, nil)
	wantCode(t, err, ce.ItemUnresolved)
	// An item edited after review no longer has its mark.
	edited := newReader(map[string]string{"3.5.1": "* [BUGFIX] Fix a different crash. #51\n"})
	_, err = attest(t, edited, dispositions(all), nil, nil)
	wantCode(t, err, ce.ItemUnresolved)
}

func TestRuleCitationMustLieInsideTheItem(t *testing.T) {
	r := newReader(nil)
	item := changeItem(t, r)
	skip := "v3.5.0#" + fmt.Sprint(item.StartLine)
	marks := append(marksFor(t, r, skip), ruleMark(t, r, "prom.change.b"))
	ok := citingRule(t, r, "prom.change.b", 0)
	if _, err := attest(t, r, dispositions(marks), [][]byte{ok}, nil); err != nil {
		t.Fatal(err)
	}
	e := entry(t, r, "3.5.0")
	other := commit(9)
	cases := map[string][]byte{
		"above the item":     citingRule(t, r, "prom.change.b", -(item.StartLine-e.Section.StartLine)-1),
		"below the item":     citingRule(t, r, "prom.change.b", item.EndLine-item.StartLine+1),
		"one line too long":  ruleJSON("prom.change.b", "3.5.0", "3.5.0", "active", commit(3), e.Source.FileDigest, item.StartLine, item.EndLine+1),
		"another digest":     ruleJSON("prom.change.b", "3.5.0", "3.5.0", "active", commit(3), strings.Repeat("c", 64), item.StartLine, item.EndLine),
		"another commit":     ruleJSON("prom.change.b", "3.5.0", "3.5.0", "active", other, e.Source.FileDigest, item.StartLine, item.EndLine),
		"withdrawn rule":     ruleJSON("prom.change.b", "3.5.0", "3.5.0", "withdrawn", commit(3), e.Source.FileDigest, item.StartLine, item.EndLine),
		"expired rule state": ruleJSON("prom.change.b", "3.5.0", "3.5.0", "expired", commit(3), e.Source.FileDigest, item.StartLine, item.EndLine),
	}
	for name, rule := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := attest(t, r, dispositions(marks), [][]byte{rule}, nil)
			wantCode(t, err, ce.ItemUnresolved)
		})
	}
	// A mark that names a rule the pack does not hold, or one of another component.
	_, err := attest(t, r, dispositions(marks), nil, nil)
	wantCode(t, err, ce.ItemUnresolved)
	foreign := strings.Replace(string(ok), `"component":"prometheus"`, `"component":"other"`, 1)
	_, err = attest(t, r, dispositions(marks), [][]byte{[]byte(foreign)}, nil)
	wantCode(t, err, ce.ItemUnresolved)
}

func TestPatchReleaseOperatorItem(t *testing.T) {
	r := newReader(nil)
	patch := entry(t, r, "3.5.1").Items[0]
	// A rule mark on an item of a patch release has no rule shape.
	rule := ruleJSON("prom.patch", "3.5.0", "3.5.0", "active", commit(4), entry(t, r, "3.5.1").Source.FileDigest, patch.StartLine, patch.EndLine)
	m := Mark{ItemDigest: patch.Digest, Occurrence: 1, Tag: "v3.5.1", Kind: KindRule, RuleID: "prom.patch",
		State: StateReviewed, ReviewedAt: "2026-11-01T00:00:00Z", ProposedBy: ProposedByPerson}
	var marks []Mark
	for _, x := range marksFor(t, r) {
		if x.ItemDigest != patch.Digest {
			marks = append(marks, x)
		}
	}
	_, err := attest(t, r, dispositions(append(marks, m)), [][]byte{rule}, nil)
	wantCode(t, err, ce.ItemRuleShapeUnsupported)
	// The same item with no mark is unresolved.
	_, err = attest(t, r, dispositions(marks), nil, nil)
	wantCode(t, err, ce.ItemUnresolved)
}

func TestEveryRuleOfTheLineIsListedAndLineWide(t *testing.T) {
	r := newReader(nil)
	marks := marksFor(t, r)
	e := entry(t, r, "3.5.0")
	it := e.Items[0]
	quiet := ruleJSON("prom.quiet", "3.5.0", "3.5.0", "active", commit(3), e.Source.FileDigest, it.StartLine, it.EndLine)
	otherLine := []byte(strings.Replace(string(quiet), `"to":"3.5.0"`, `"to":"3.6.0"`, 1))
	otherLine = []byte(strings.Replace(string(otherLine), `"id":"prom.quiet"`, `"id":"prom.next"`, 1))
	foreign := []byte(strings.Replace(strings.Replace(string(quiet), `"component":"prometheus"`, `"component":"other"`, 1), "prom.quiet", "other.1", 1))
	res, err := attest(t, r, dispositions(marks), [][]byte{quiet, otherLine, foreign}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Listed though no item cites it; the rule of another line and the rule
	// of another component are not.
	if !slices.Equal(res.Candidate.RuleIDs, []string{"prom.quiet"}) {
		t.Fatalf("%v", res.Candidate.RuleIDs)
	}
	// Not line-wide: a crossing at 3.5.1, an anchor pair, a short from region.
	late := []byte(strings.Replace(string(quiet), `"version":"3.5.0"`, `"version":"3.5.1"`, 1))
	anchor := []byte(fmt.Sprintf(`{"id":"prom.anchor","subject":{"component":%q,"from":"3.4.0","to":"3.5.0"}}`, component))
	short := []byte(strings.Replace(string(quiet), `"version":"3.5.0"`, `"version":"3.4.5"`, 1))
	for name, bad := range map[string][]byte{"late change": late, "anchor": anchor, "short from": short} {
		t.Run(name, func(t *testing.T) {
			_, err := attest(t, r, dispositions(marks), [][]byte{bad}, nil)
			wantCode(t, err, ce.RuleNotLineWide)
		})
	}
}

func TestNotPreviousMinorAndTagVoids(t *testing.T) {
	r := newReader(nil)
	marks := dispositions(marksFor(t, r))
	cfg := Config{Target: target, Dispositions: marks}
	skip := pair
	skip.From, skip.FromTag, skip.FromCommit = "3.3.0", "v3.3.0", commit(0)
	_, err := Attest(r, cfg, tags(), skip)
	wantCode(t, err, ce.NotPreviousMinor)

	// A tag index that tags 3.5.1 at two commits.
	moved := append(tags(), extract.Tag{Name: "3.5.1", Commit: commit(7)})
	_, err = Attest(r, cfg, moved, pair)
	wantCode(t, err, ce.TagMoved)
	// The pair names a commit the index does not hold.
	bad := pair
	bad.ToCommit = commit(8)
	_, err = Attest(r, cfg, tags(), bad)
	wantCode(t, err, ce.TagMoved)
}

func TestNewTagAndMovedTagChangeTheRecord(t *testing.T) {
	r := newReader(nil)
	marks := dispositions(marksFor(t, r))
	cfg := Config{Target: target, Dispositions: marks}
	base, err := Attest(r, cfg, tags(), pair)
	if err != nil {
		t.Fatal(err)
	}
	old := lineattest.LineAttestation{FactFamily: lineattest.FamilyChangelogAttestedEntries, Releases: base.Candidate.Releases}
	if !old.CoversReleases("3.4.1", "3.5.1") {
		t.Fatal("the record covers its own releases")
	}
	// A new final tag on the to line: the old record does not cover it, and a
	// new derivation is another record (it needs a disposition for its entry).
	if old.CoversReleases("3.4.1", "3.5.2") {
		t.Fatal("a release published after the derivation is covered")
	}
	fresh := newReader(nil)
	fresh.files[commit(5)+":CHANGELOG.md"] = "# Changelog\n\n## 3.5.2 / 2025-02-01\n\n* [BUGFIX] New. #60\n\n" + fileUpTo("3.5.1", nil)[len("# Changelog\n\n## main / unreleased\n\n"):]
	more := append(tags(), extract.Tag{Name: "v3.5.2", Commit: commit(5)})
	_, err = Attest(fresh, cfg, more, pair)
	wantCode(t, err, ce.ItemUnresolved) // the new entry's item has no mark
	// A moved tag: 3.5.1 at another commit is another release record.
	movedTags := tags()
	movedTags[4].Commit = commit(6)
	fresh.files[commit(6)+":CHANGELOG.md"] = fileUpTo("3.5.1", nil)
	res, err := Attest(fresh, cfg, movedTags, pair)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(res.Candidate.Releases, base.Candidate.Releases) {
		t.Fatal("a moved tag left the releases unchanged")
	}
}

func TestFileChangesMoveTheEvidence(t *testing.T) {
	r := newReader(nil)
	a, err := attest(t, r, dispositions(marksFor(t, r)), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// One byte outside every item of 3.5.0 (its section's blank tail grows):
	// the file digest moves though every item and mark still match.
	edited := newReader(nil)
	for c, f := range edited.files {
		edited.files[c] = f + "\n"
	}
	b, err := attest(t, edited, dispositions(marksFor(t, r)), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.Proof.Entries[1].Source.FileDigest == b.Proof.Entries[1].Source.FileDigest {
		t.Fatal("file digest did not move")
	}
}

func TestSourceDriftAndAmendment(t *testing.T) {
	r := newReader(nil)
	marks := dispositions(marksFor(t, r))
	// The newest tag no longer has the file: the pair is withheld.
	gone := newReader(nil)
	delete(gone.files, commit(4)+":CHANGELOG.md")
	_, err := attest(t, gone, marks, nil, nil)
	wantCode(t, err, ce.PathMissingAtTag)
	// The newest tag's file holds an item the tag's own read of 3.5.0 lacks.
	amended := newReader(nil)
	amended.files[commit(4)+":CHANGELOG.md"] = fileUpTo("3.5.1", map[string]string{"3.5.0": bodies["3.5.0"] + "* [CHANGE] Added later. #99\n"})
	_, err = attest(t, amended, marks, nil, nil)
	wantCode(t, err, ce.EntryAmended)
	// An amendment of an older entry at the newest tag counts as well.
	old := newReader(nil)
	old.files[commit(4)+":CHANGELOG.md"] = fileUpTo("3.5.1", map[string]string{"3.4.1": bodies["3.4.1"] + "* [CHANGE] Added later. #98\n"})
	_, err = attest(t, old, marks, nil, nil)
	wantCode(t, err, ce.EntryAmended)
	// The same version missing at the newest tag is source drift.
	lost := newReader(nil)
	lost.files[commit(4)+":CHANGELOG.md"] = "# Changelog\n\n## 3.5.1 / 2025-01-01\n\n" + bodies["3.5.1"]
	_, err = attest(t, lost, marks, nil, nil)
	wantCode(t, err, ce.EntryMissing)
}

type stubClassifier struct {
	neutral func(ClassifyInput) bool
	seen    []ClassifyInput
}

func (s *stubClassifier) MechanicalNeutral(in ClassifyInput) bool {
	s.seen = append(s.seen, in)
	return s.neutral(in)
}

func TestMechanicalNeutralOnlyThroughTheClassifier(t *testing.T) {
	r := newReader(nil)
	all := func(ClassifyInput) bool { return true }
	c := &stubClassifier{neutral: all}
	res, err := attest(t, r, dispositions(nil), nil, c)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range res.Proof.Dispositions {
		if d.Disposition != "mechanical-neutral" {
			t.Fatalf("%+v", d)
		}
	}
	// The classifier saw the item's own text.
	found := false
	for _, in := range c.seen {
		if in.Tag == "v3.5.0" && in.Item.Marker == "CHANGE" && in.Text == "* [CHANGE] Remove flag `--b`. #52\n  continued" {
			found = true
		}
	}
	if !found {
		t.Fatalf("classifier input %+v", c.seen)
	}
	// One item it does not clear stays unresolved.
	c = &stubClassifier{neutral: func(in ClassifyInput) bool { return in.Item.Marker != "CHANGE" }}
	_, err = attest(t, r, dispositions(nil), nil, c)
	wantCode(t, err, ce.ItemUnresolved)
	// A mark wins nothing from a classifier that says no: marks still resolve.
	no := &stubClassifier{neutral: func(ClassifyInput) bool { return false }}
	if _, err := attest(t, r, dispositions(marksFor(t, r)), nil, no); err != nil {
		t.Fatal(err)
	}
}

func TestExtractorPairsAndWithheld(t *testing.T) {
	r := newReader(nil)
	ex, err := New("prometheus", Config{Target: target, Dispositions: dispositions(marksFor(t, r))})
	if err != nil {
		t.Fatal(err)
	}
	pairs := ex.Pairs(extract.ReleaseIndex{Repo: repo, Tags: tags()})
	var found bool
	for _, p := range pairs {
		if p.Key() == "3.4.0->3.5.0" {
			found = true
		}
	}
	if !found {
		t.Fatalf("pairs %+v", pairs)
	}
	got, err := ex.Extract(context.Background(), r, pair)
	if err != nil || len(got.Attestations) != 1 || len(got.Candidates) != 0 {
		t.Fatalf("%+v %v", got, err)
	}
	// An unresolved pair is withheld with its code, never attested.
	bare, _ := New("prometheus", Config{Target: target, Dispositions: dispositions(nil)})
	bare.Pairs(extract.ReleaseIndex{Repo: repo, Tags: tags()})
	_, err = bare.Extract(context.Background(), r, pair)
	w, ok := extract.IsWithheld(err)
	if !ok || !strings.HasPrefix(w.Reason, "ITEM_UNRESOLVED") {
		t.Fatalf("%v", err)
	}
	if _, err := ex.AttestedFamilies(), error(nil); err != nil || ex.AttestedComponent() != component {
		t.Fatal("wiring")
	}
	var _ extract.LineAttester = ex
	var _ extract.ComponentAttester = ex
	var _ extract.CodeSource = ex
}

// Until a reviewed change admits the component to the family, the framework
// refuses every attestation: nothing is attested through Run.
func TestRunRefusesWhileTheMemberTableIsEmpty(t *testing.T) {
	r := newReader(nil)
	ex, err := New("prometheus", Config{Target: target, Dispositions: dispositions(marksFor(t, r))})
	if err != nil {
		t.Fatal(err)
	}
	_, err = extract.Run(context.Background(), ex, r, r, extract.Options{Repo: repo, DerivedAt: mustTime()})
	if err == nil || !strings.Contains(err.Error(), "is not the component of family") {
		t.Fatalf("an attestation of a component outside the family was not refused as such: %v", err)
	}
}

func TestLeaseIsWithinTheAttestationWindow(t *testing.T) {
	if extract.DefaultLease > lineattest.MaxWindow {
		t.Fatal("the default lease exceeds an attestation's window")
	}
}

func TestSourceSetCoversTheReader(t *testing.T) {
	files, err := extract.CodeFiles(extract.FrameworkSource(), SourceSet())
	if err != nil {
		t.Fatal(err)
	}
	var own, reader bool
	for _, f := range files {
		own = own || f.Path == "extract/changelogattest/attest.go"
		reader = reader || f.Path == "extract/changelogattest/changelogentries_locate.go"
		if strings.HasSuffix(f.Path, "_test.go") {
			t.Fatalf("test file %s in the digest", f.Path)
		}
	}
	if !own || !reader {
		t.Fatalf("own %t reader %t", own, reader)
	}
}
