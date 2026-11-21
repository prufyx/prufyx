// SPDX-License-Identifier: AGPL-3.0-only

package changelogattest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	ce "github.com/prufyx/prufyx/cli/internal/extract/changelogentries"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// reviewed returns the real reviewed row of the fixture component: a listed
// attestation is derived only from a row of the shipped table.
func reviewed(t *testing.T) ce.Target {
	t.Helper()
	for _, row := range ce.Reviewed {
		if row.Component == component {
			return row
		}
	}
	t.Fatalf("no reviewed row for %s", component)
	return ce.Target{}
}

// listing serves the fixture and lists any commit's root as empty, which is all
// the pin of the previous line's finals asks of a reader.
type listing struct{ *memReader }

func (l listing) List(extract.RepoRef, string, string) ([]extract.TreeEntry, error) { return nil, nil }

func (l listing) Tags(extract.RepoRef) ([]extract.Tag, error) { return tags(), nil }

func newListing(override map[string]string) listing { return listing{newReader(override)} }

const prometheusPURL = "pkg:github/prometheus/prometheus"

func TestListedAttestsTheWholeToLine(t *testing.T) {
	r := newListing(nil)
	res, err := AttestListed(r, reviewed(t), tags(), pair)
	if err != nil {
		t.Fatal(err)
	}
	c := res.Candidate
	if c.Component != prometheusPURL || c.Line != "3.5" || c.FactFamily != lineattest.FamilyChangelogListedEntries || len(c.RuleIDs) != 0 || c.RuleIDs == nil {
		t.Fatalf("%+v", c)
	}
	if got := res.Proof.Window; len(got) != 2 || got[0] != "v3.5.0" || got[1] != "v3.5.1" {
		t.Fatalf("window %v", got)
	}
	if res.Proof.Items != 3 || len(c.Sources) != 2 {
		t.Fatalf("items %d sources %d", res.Proof.Items, len(c.Sources))
	}
	if len(c.Releases.To) != 2 || len(c.Releases.From) != 2 {
		t.Fatalf("releases %+v", c.Releases)
	}
	// Only the to-line's own tag commits are read; the previous line's
	// entries are not (their finals are pinned, not read).
	for _, n := range []int{1, 2} {
		if r.readAt(commit(n)) {
			t.Fatalf("the entry of the previous line was read at commit %d", n)
		}
	}
	for _, n := range []int{3, 4} {
		if !r.readAt(commit(n)) {
			t.Fatalf("the to-line was not read at commit %d", n)
		}
	}
}

// Every final tag of the to-line must have its own entry: one missing entry
// gives no attestation at all, never a shorter one.
func TestListedPartialToLineAttestsNothing(t *testing.T) {
	r := newListing(nil)
	r.files[commit(4)+":CHANGELOG.md"] = fileUpTo("3.5.0", nil) // v3.5.1 has no section at its own tag
	res, err := AttestListed(r, reviewed(t), tags(), pair)
	if res != nil {
		t.Fatal("a partial to-line was attested")
	}
	wantCode(t, err, ce.EntryMissing)

	// The tag's file missing at its commit: also nothing.
	r = newListing(nil)
	delete(r.files, commit(4)+":CHANGELOG.md")
	if res, err = AttestListed(r, reviewed(t), tags(), pair); res != nil {
		t.Fatal("a missing file was attested")
	}
	wantCode(t, err, ce.PathMissingAtTag)

	// An entry of a neighbouring tag is never taken for the tag's: the
	// section of 3.5.1 exists only in the file of a later commit.
	r = newListing(nil)
	r.files[commit(3)+":CHANGELOG.md"] = fileUpTo("3.5.1", nil) // x.y.0's file already holds 3.5.1
	r.files[commit(4)+":CHANGELOG.md"] = fileUpTo("3.5.0", nil)
	if res, err = AttestListed(r, reviewed(t), tags(), pair); res != nil {
		t.Fatal("an entry of another tag's file was taken")
	}
	wantCode(t, err, ce.EntryMissing)
}

func TestListedNeedsTheFirstReleaseOfTheLine(t *testing.T) {
	r := newListing(nil)
	var ts []extract.Tag
	for _, tg := range tags() {
		if tg.Name != "v3.5.0" {
			ts = append(ts, tg)
		}
	}
	p := pair
	p.To, p.ToTag, p.ToCommit = "3.5.1", "v3.5.1", commit(4)
	res, err := AttestListed(r, reviewed(t), ts, p)
	if res != nil {
		t.Fatal("a line without its x.y.0 was attested")
	}
	wantCode(t, err, ce.EntryMissing)
}

func TestListedRefusesAComponentWithoutARow(t *testing.T) {
	r := newListing(nil)
	// Same data, a component that has no row.
	other := reviewed(t)
	other.Component = "nosuchproject"
	if res, err := AttestListed(r, other, tags(), pair); res != nil || err == nil {
		t.Fatal("a component outside the rows was attested")
	} else {
		wantCode(t, err, ce.NoChangelogTarget)
	}
	if _, err := NewListed(other); err == nil {
		t.Fatal("an extractor was made for a component outside the rows")
	}
	// A row that is altered after loading is not the reviewed row.
	altered := reviewed(t)
	altered.Path = "docs/CHANGELOG.md"
	if res, err := AttestListed(r, altered, tags(), pair); res != nil || err == nil {
		t.Fatal("an altered row was attested")
	}
	if _, err := NewListed(altered); err == nil {
		t.Fatal("an extractor was made for an altered row")
	}
	loose := reviewed(t)
	loose.BoundaryPatterns = append(append([]string{}, loose.BoundaryPatterns...), `^.*$`)
	if _, err := NewListed(loose); err == nil {
		t.Fatal("an extractor was made for a row with an extra boundary")
	}
	// A reviewed row without a GitHub repository has no pack component.
	if _, ok := ce.ComponentPURL(ce.Target{Component: "x", Repo: extract.RepoRef{Key: "gitlab.com/a/b"}}); ok {
		t.Fatal("a non-GitHub row has a component")
	}
}

func TestListedRefusesAMovedTag(t *testing.T) {
	r := newListing(nil)
	ts := append(tags(), extract.Tag{Name: "3.5.1", Commit: commit(7)})
	res, err := AttestListed(r, reviewed(t), ts, pair)
	if res != nil {
		t.Fatal("a release tagged at two commits was attested")
	}
	wantCode(t, err, ce.TagMoved)
}

func TestListedRefusesAHopThatIsNotThePreviousMinor(t *testing.T) {
	r := newListing(nil)
	p := pair
	p.From, p.FromTag, p.FromCommit = "3.3.0", "v3.3.0", commit(0)
	res, err := AttestListed(r, reviewed(t), tags(), p)
	if res != nil {
		t.Fatal("a skipped line was attested")
	}
	wantCode(t, err, ce.NotPreviousMinor)
}

// Rows of forms the reader does not read yield no attestation: a typed
// withheld reason, never a list.
func TestListedUnreadableFormsAreWithheld(t *testing.T) {
	r := newListing(nil)
	for _, row := range ce.Reviewed {
		if row.Form == ce.FormFile || row.Form == ce.FormPerLineFile || row.Form == ce.FormPerVersionFile {
			continue
		}
		x, err := NewListed(row)
		if err != nil {
			t.Fatalf("%s: %v", row.Component, err)
		}
		repoRef := row.Repo
		ix := extract.ReleaseIndex{Repo: repoRef, Tags: tags()}
		pairs := x.Pairs(ix)
		if len(pairs) == 0 {
			t.Fatalf("%s: no pairs", row.Component)
		}
		_, err = x.Extract(context.Background(), r, pairs[0])
		if w, ok := extract.IsWithheld(err); !ok || w.Reason == "" {
			t.Fatalf("%s: %v", row.Component, err)
		}
	}
}

func TestListedExtractorWiring(t *testing.T) {
	x, err := NewListed(reviewed(t))
	if err != nil {
		t.Fatal(err)
	}
	if x.ID() != "changelog.listed.prometheus" || x.AttestedComponent() != prometheusPURL {
		t.Fatalf("%s %s", x.ID(), x.AttestedComponent())
	}
	if fams := x.AttestedFamilies(); len(fams) != 1 || fams[0] != lineattest.FamilyChangelogListedEntries {
		t.Fatalf("%v", fams)
	}
	var _ extract.LineAttester = x
	var _ extract.ComponentAttester = x
	var _ extract.CodeSource = x
	if _, err := x.Extract(context.Background(), newReader(nil), pair); err == nil {
		t.Fatal("Extract before Pairs was accepted")
	}
	dir, files := x.SourceFiles()
	if dir != SourceDir || files == nil {
		t.Fatal("source files")
	}
}

// The positive end to end: a run over the fixture produces one listed
// attestation that passes the pack's own admission check, carries no rule,
// and is re-derived byte for byte; any changed byte of the record is refused.
func TestListedRunVerifyAndTamper(t *testing.T) {
	r := newListing(nil)
	x, _ := NewListed(reviewed(t))
	out, err := extract.Run(context.Background(), x, r, r, extract.Options{Repo: repo, DerivedAt: mustTime()})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Entries) != 0 || len(out.Drafts) != 0 {
		t.Fatalf("a listed run produced %d rules and %d drafts", len(out.Entries), len(out.Drafts))
	}
	// Two hops in the fixture (3.3 -> 3.4 and 3.4 -> 3.5): one record per line.
	if len(out.Attestations) != 2 || out.Attestations[0].Line != "3.4" || out.Attestations[1].Line != "3.5" {
		t.Fatalf("%d attestations", len(out.Attestations))
	}
	a := out.Attestations[1]
	if a.FactFamily != lineattest.FamilyChangelogListedEntries || a.Component != prometheusPURL || len(a.RuleIDs) != 0 {
		t.Fatalf("%+v", a)
	}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "run")
	if err := out.Write(dir); err != nil {
		t.Fatal(err)
	}
	fresh, _ := NewListed(reviewed(t))
	if diff, err := extract.Verify(context.Background(), fresh, r, r, dir, nil); err != nil || len(diff) != 0 {
		t.Fatalf("an untouched run does not verify: %v %v", diff, err)
	}

	// Tampered attestation file: refused.
	p := filepath.Join(dir, extract.FileAttestations)
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(raw), `"3.5"`, `"3.6"`, 1)
	if tampered == string(raw) {
		t.Fatal("fixture: the attestation file does not name line 3.5")
	}
	if err := os.WriteFile(p, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}
	fresh, _ = NewListed(reviewed(t))
	if diff, err := extract.Verify(context.Background(), fresh, r, r, dir, nil); err == nil && len(diff) == 0 {
		t.Fatal("a tampered attestation verified")
	}
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	// Tampered manifest: refused.
	mp := filepath.Join(dir, extract.FileManifest)
	mraw, err := os.ReadFile(mp)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mraw), "3.5.1") {
		t.Fatal("fixture: manifest does not name 3.5.1")
	}
	if err := os.WriteFile(mp, []byte(strings.Replace(string(mraw), "3.5.1", "3.5.9", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	fresh, _ = NewListed(reviewed(t))
	if diff, err := extract.Verify(context.Background(), fresh, r, r, dir, nil); err == nil && len(diff) == 0 {
		t.Fatal("a tampered manifest verified")
	}
}

// A new final release in the line changes the record: the old attestation does
// not cover it (release-scoped), so the pair falls back to a gap.
func TestListedNewTagChangesTheRecord(t *testing.T) {
	r := newListing(nil)
	before, err := AttestListed(r, reviewed(t), tags(), pair)
	if err != nil {
		t.Fatal(err)
	}
	r.files[commit(5)+":CHANGELOG.md"] = "# Changelog\n\n## main / unreleased\n\n## 3.5.2 / 2025-01-01\n\n* [BUGFIX] x. #1\n\n" + strings.SplitN(fileUpTo("3.5.1", nil), "## main / unreleased\n\n", 2)[1]
	ts := append(tags(), extract.Tag{Name: "v3.5.2", Commit: commit(5)})
	after, err := AttestListed(r, reviewed(t), ts, pair)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Candidate.Releases.To) != len(before.Candidate.Releases.To)+1 {
		t.Fatalf("%d -> %d releases", len(before.Candidate.Releases.To), len(after.Candidate.Releases.To))
	}
	// And the new tag without its entry withholds the whole line.
	delete(r.files, commit(5)+":CHANGELOG.md")
	if res, err := AttestListed(r, reviewed(t), ts, pair); res != nil {
		t.Fatalf("a new tag without an entry was attested: %v", err)
	}
}

// The listed family never takes a rule: a record that lists one is refused by
// the record's own check.
func TestListedRecordWithARuleIsInvalid(t *testing.T) {
	r := newListing(nil)
	x, _ := NewListed(reviewed(t))
	out, err := extract.Run(context.Background(), x, r, r, extract.Options{Repo: repo, DerivedAt: mustTime()})
	if err != nil {
		t.Fatal(err)
	}
	a := out.Attestations[0]
	a.RuleIDs = []string{"some.rule.id"}
	if err := a.Validate(); err == nil {
		t.Fatal("a listed record with a rule id validated")
	}
}

// A previous-line final that cannot be pinned is a failure, never a shorter
// attestation: the plain fixture reader has no listing.
func TestListedUnpinnableFromLineAttestsNothing(t *testing.T) {
	res, err := AttestListed(newReader(nil), reviewed(t), tags(), pair)
	if res != nil || err == nil {
		t.Fatal("an attestation was made without pinning the previous line")
	}
}

// manyReader serves a prometheus-shaped changelog whose lines hold the given
// number of final releases each: line 3.(i+3) has counts[i] finals (x.y.0 ..).
// bigCommit is a 40-hex commit id for any n (commit() overflows past 9).
func bigCommit(n int) string { return fmt.Sprintf("%040x", n+1) }

func manyReader(counts []int) (listing, []extract.Tag) {
	m := &memReader{files: map[string]string{}}
	var tgs []extract.Tag
	var vers []string
	n := 0
	for i, c := range counts {
		for p := 0; p < c; p++ {
			vers = append(vers, fmt.Sprintf("3.%d.%d", i+3, p))
		}
	}
	for _, v := range vers {
		tgs = append(tgs, extract.Tag{Name: "v" + v, Commit: bigCommit(n)})
		n++
	}
	for i := range vers {
		var b strings.Builder
		b.WriteString("# Changelog\n\n## main / unreleased\n\n")
		for j := i; j >= 0; j-- {
			fmt.Fprintf(&b, "## %s / 2025-01-01\n\n* [BUGFIX] Fix %s. #%d\n\n", vers[j], vers[j], j+1)
		}
		m.files[bigCommit(i)+":CHANGELOG.md"] = b.String()
	}
	return listing{m}, tgs
}

type taggedListing struct {
	listing
	tg []extract.Tag
}

func (l taggedListing) Tags(extract.RepoRef) ([]extract.Tag, error) { return l.tg, nil }

func runMany(t *testing.T, counts []int) *extract.Output {
	t.Helper()
	r, tgs := manyReader(counts)
	tl := taggedListing{r, tgs}
	x, _ := NewListed(reviewed(t))
	out, err := extract.Run(context.Background(), x, tl, tl, extract.Options{Repo: repo, DerivedAt: mustTime()})
	if err != nil {
		t.Fatalf("a line over the cap aborted the run: %v", err)
	}
	return out
}

func TestListedOverCapLineIsWithheldOthersProceed(t *testing.T) {
	// lines 3.3 (1), 3.4 (2), 3.5 (9 finals, over the cap of 8)
	out := runMany(t, []int{1, 2, 9})
	if len(out.Attestations) != 1 || out.Attestations[0].Line != "3.4" {
		t.Fatalf("want exactly the 3.4 attestation, got %d", len(out.Attestations))
	}
	if err := out.Attestations[0].Validate(); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range out.Manifest.Pairs {
		if p.To == "3.5.0" {
			found = p.Status == extract.PairWithheld && proofCode(p.Proof) == string(ce.LineTooManyFinals) && strings.Contains(p.Reason, "9 final")
		}
	}
	if !found {
		t.Fatal("the over-cap line is not withheld with LINE_TOO_MANY_FINALS")
	}
}

func TestListedExactlyAtCapIsAttested(t *testing.T) {
	out := runMany(t, []int{1, 8})
	if len(out.Attestations) != 1 || out.Attestations[0].Line != "3.4" || len(out.Attestations[0].Releases.To) != 8 {
		t.Fatalf("a line of exactly %d finals must attest", maxListedSources)
	}
	if err := out.Attestations[0].Validate(); err != nil {
		t.Fatalf("the local cap drifted from the record limit: %v", err)
	}
}

func TestListedEveryLineOverCapProducesNothing(t *testing.T) {
	out := runMany(t, []int{9, 9, 9})
	if len(out.Attestations) != 0 {
		t.Fatalf("%d attestations from over-cap lines: %+v %+v", len(out.Attestations), out.Attestations[0].Line, len(out.Manifest.Pairs))
	}
	w := 0
	for _, p := range out.Manifest.Pairs {
		if p.Status == extract.PairWithheld && proofCode(p.Proof) == string(ce.LineTooManyFinals) {
			w++
		}
	}
	if w != 2 {
		t.Fatalf("withheld %d pairs, want 2", w)
	}
}

func proofCode(p any) string {
	if m, ok := p.(map[string]string); ok {
		return m["code"]
	}
	if m, ok := p.(map[string]any); ok {
		s, _ := m["code"].(string)
		return s
	}
	return ""
}
