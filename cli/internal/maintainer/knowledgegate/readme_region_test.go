// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
	"github.com/prufyx/prufyx/cli/internal/maintainer/coveragereport"
)

// The README coverage region counts the community and the CNCF catalog from
// the custom-resource table of the change itself, and the table is judged by
// the onboarding checks, never by the README.

var readmeCountsRE = regexp.MustCompile(`\((\d+) projects: (\d+) of the CNCF landscape catalog, (\d+) of the community catalog\)`)

// readmeCounts returns the CNCF and community counts of a tree's README.
func readmeCounts(t *testing.T, tr Tree) (cncf, community int) {
	t.Helper()
	m := readmeCountsRE.FindStringSubmatch(readREADME(t, tr))
	if m == nil {
		t.Fatal("the README coverage sentence is missing")
	}
	cncf, _ = strconv.Atoi(m[2])
	community, _ = strconv.Atoi(m[3])
	return cncf, community
}

// readmeMatchesHeadTable fails the test unless the README of tr is exactly its
// own regeneration (the README an attacker would supply with a table edit).
func readmeMatchesHeadTable(t *testing.T, tr Tree, ol OnboardingLayout) {
	t.Helper()
	g := DefaultLayout().GeneratedBlocks[0]
	want, err := g.Want(tr, tr, ol)
	if err != nil {
		t.Fatalf("the README of the head cannot be regenerated: %v", err)
	}
	if !bytes.Equal(want, []byte(readREADME(t, tr))) {
		t.Fatal("the README of the head is not the regeneration from its own table")
	}
}

// problemsFor runs the offline onboarding checks over the fixture with rec,
// or with the record of the fixture's current head when rec is nil.
func problemsFor(t *testing.T, f *onboardingFixture, rec *OnboardingRecord) []string {
	t.Helper()
	layout := DefaultLayout()
	cls, err := Classify(layout, f.base, f.head)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := ChangedPaths(f.base, f.head)
	if err != nil {
		t.Fatal(err)
	}
	st, err := newOnboardingState(layout, f.base, f.head, cls, paths)
	if err != nil {
		return []string{"state: " + err.Error()}
	}
	if rec == nil {
		r := OnboardingRecord{Base: st.base.state, Head: st.head.state, BatchID: f.draft.BatchID, CandidateID: f.draft.CandidateID, ChangeSetDigest: st.changeSetDigest, Nonce: obNonce, Projects: f.draft.Projects}
		if r.Sample, err = onboardingSample(r.core()); err != nil {
			t.Fatal(err)
		}
		rec = &r
	}
	return st.check(*rec, layout.Onboarding.Dir+"/"+rec.BatchID+".json")
}

func containsProblem(problems []string, want string) bool {
	for _, p := range problems {
		if strings.Contains(p, want) {
			return true
		}
	}
	return false
}

// The bug: a batch that adds a community project renders the head's counts
// (one more community project), not the base's.
func TestReadmeRegionCountsFollowTheHeadTable(t *testing.T) {
	t.Parallel()
	t.Run("a new community project", func(t *testing.T) {
		t.Parallel()
		f := newCommunityFixture(t, ocDefault)
		bc, bm := readmeCounts(t, f.base)
		hc, hm := readmeCounts(t, f.head)
		if hc != bc || hm != bm+1 {
			t.Fatalf("counts %d/%d -> %d/%d, want the community count to move by one", bc, bm, hc, hm)
		}
		f.sign(t, f.record(t))
		requirePass(t, f.gate(t))
	})
	t.Run("a new CNCF project", func(t *testing.T) {
		t.Parallel()
		f := newOnboardingFixture(t)
		bc, bm := readmeCounts(t, f.base)
		hc, hm := readmeCounts(t, f.head)
		if hc != bc+1 || hm != bm {
			t.Fatalf("counts %d/%d -> %d/%d, want the CNCF count to move by one", bc, bm, hc, hm)
		}
		f.sign(t, f.record(t))
		requirePass(t, f.gate(t))
	})
	t.Run("one new project of each catalog", func(t *testing.T) {
		t.Parallel()
		f := newCommunityFixture(t, ocDefault)
		writeFile(t, filepath.Join(f.upstream, filepath.FromSlash(obRepo), "tags.json"), []byte(`{"v1.0.0": "`+obFrom+`", "v1.1.0": "`+obTo+`"}`))
		writeUpstream(t, f.upstream, obFrom, obCRD, obCRDDoc(obGroup, "v1alpha1", "v1"))
		writeUpstream(t, f.upstream, obTo, obCRD, obCRDDoc(obGroup, "v1"))
		f.onboard(t, obSlug, obTargetJSON, obGroup, obCRD)
		f.draft.Projects = append(f.draft.Projects, f.project(obSlug, OnboardingKindNew, obGroup))
		sort.Slice(f.draft.Projects, func(i, j int) bool { return f.draft.Projects[i].Slug < f.draft.Projects[j].Slug })
		f.refresh()
		bc, bm := readmeCounts(t, f.base)
		hc, hm := readmeCounts(t, f.head)
		if hc != bc+1 || hm != bm+1 {
			t.Fatalf("counts %d/%d -> %d/%d, want both counts to move by one", bc, bm, hc, hm)
		}
		f.sign(t, f.record(t))
		requirePass(t, f.gate(t))
	})
}

// catalogSplitProblems holds the two-sided equality, independently of the
// batch's per-project checks and of the README.
func TestCatalogSplitProblems(t *testing.T) {
	t.Parallel()
	row := func(slug string, c customresources.Catalog, groups ...string) customresources.Project {
		p := customresources.Project{Slug: slug, Catalog: c}
		for _, g := range groups {
			p.Groups = append(p.Groups, customresources.Group{Name: g})
		}
		return p
	}
	cncf, community := customresources.CatalogCNCF, customresources.CatalogCommunity
	base := []customresources.Project{row("a", cncf, "a.example"), row("b", community, "b.example")}
	newProject := func(slug, catalog string) OnboardingProject {
		return OnboardingProject{Slug: slug, Catalog: catalog, Kind: OnboardingKindNew}
	}
	for _, tc := range []struct {
		name  string
		batch []OnboardingProject
		head  []customresources.Project
		want  []string // substrings, each must be in some problem; none: no problem
	}{
		{name: "no change", head: base},
		{name: "a new community row listed as community", batch: []OnboardingProject{newProject("c", "community")}, head: append(slices.Clone(base), row("c", community))},
		{name: "a new CNCF row listed as CNCF", batch: []OnboardingProject{newProject("c", "cncf")}, head: append(slices.Clone(base), row("c", cncf))},
		{name: "one new row of each catalog", batch: []OnboardingProject{newProject("c", "cncf"), newProject("d", "community")}, head: append(slices.Clone(base), row("c", cncf), row("d", community))},
		{name: "a community row the batch does not list", head: append(slices.Clone(base), row("c", community)), want: []string{"the head table has c as a community row"}},
		{name: "a CNCF row the batch does not list", head: append(slices.Clone(base), row("c", cncf)), want: []string{"the head table has c as a cncf row"}},
		{name: "a new CNCF project in the batch, a community row in the table", batch: []OnboardingProject{newProject("c", "cncf")}, head: append(slices.Clone(base), row("c", community)),
			want: []string{"the head table has c as a community row", "the head table lacks c as a cncf row"}},
		{name: "a new community project in the batch, a CNCF row in the table", batch: []OnboardingProject{newProject("c", "community")}, head: append(slices.Clone(base), row("c", cncf)),
			want: []string{"the head table has c as a cncf row", "the head table lacks c as a community row"}},
		{name: "an attest listing is not an addition", batch: []OnboardingProject{{Slug: "c", Catalog: "community", Kind: OnboardingKindAttest}}, head: append(slices.Clone(base), row("c", community)),
			want: []string{"the head table has c as a community row"}},
		{name: "the batch lists a new project the table lacks", batch: []OnboardingProject{newProject("c", "community")}, head: base, want: []string{"the head table lacks c as a community row"}},
		{name: "a CNCF row flipped to community", head: []customresources.Project{row("a", community, "a.example"), base[1]},
			want: []string{"the head table has a as a community row", "the head table lacks a as a cncf row", "the row of a moves from the cncf catalog to the community catalog"}},
		{name: "a community row flipped to CNCF", head: []customresources.Project{base[0], row("b", cncf, "b.example")},
			want: []string{"the head table has b as a cncf row", "the head table lacks b as a community row", "the row of b moves from the community catalog to the cncf catalog"}},
		{name: "a flip and a new row of the same slug batch", batch: []OnboardingProject{newProject("a", "community")}, head: []customresources.Project{row("a", community, "a.example"), base[1]},
			want: []string{"the head table lacks a as a cncf row", "the row of a moves from the cncf catalog to the community catalog"}},
		{name: "a community row removed", head: base[:1], want: []string{"the head table lacks b as a community row"}},
		{name: "a CNCF row removed", head: base[1:], want: []string{"the head table lacks a as a cncf row"}},
		{name: "a row of the base changes its groups", head: []customresources.Project{row("a", cncf, "a.example", "z.example"), base[1]}, want: []string{"the row of a changes its groups"}},
	} {
		got := catalogSplitProblems(OnboardingRecord{Projects: tc.batch}, base, tc.head)
		if len(tc.want) == 0 && len(got) != 0 {
			t.Errorf("%s: problems %v", tc.name, got)
		}
		for _, w := range tc.want {
			if !containsProblem(got, w) {
				t.Errorf("%s: no problem mentions %q: %v", tc.name, w, got)
			}
		}
		for _, p := range got {
			if !strings.HasPrefix(p, "O2: catalog split: ") {
				t.Errorf("%s: problem without its prefix: %q", tc.name, p)
			}
		}
	}
}

// A table the batch does not authorize, with the README that matches it, is
// refused by the table checks themselves: the O2 row checks, the catalog
// split, the signed head state (O3) and the batch's catalog check (O4), each
// observable on its own. A correctly signed but policy-invalid table does not
// fail O3.
func TestReadmeRegionUnauthorizedTableAndMatchingREADME(t *testing.T) {
	t.Parallel()
	// The table of the repository is the base of every case. The rows that
	// are flipped or removed are the first ones for which the edited table
	// still validates, so the head is a table the loader accepts and only the
	// checks of the change can refuse.
	baseRaw, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(defaultTablePath)))
	if err != nil {
		t.Fatal(err)
	}
	baseRows, reserved, err := customresources.LoadTable(baseRaw)
	if err != nil {
		t.Fatal(err)
	}
	loads := func(edit func([]customresources.Project) []customresources.Project) bool {
		rows := edit(append([]customresources.Project(nil), baseRows...))
		raw, err := customresources.CanonicalTable(rows, reserved)
		if err != nil {
			return false
		}
		_, _, err = customresources.LoadTable(raw)
		return err == nil
	}
	// communityOf gives a row the upstream record of a community row whose
	// repository is the one its first group is listed from.
	communityOf := func(p *customresources.Project) {
		repo := p.Groups[0].Source[:strings.Index(p.Groups[0].Source, "/blob/")]
		p.Catalog = customresources.CatalogCommunity
		p.Upstream = customresources.Upstream{Name: "Synthetic", Repository: repo, License: "Apache-2.0", LicenseSource: repo + "/blob/" + ocLicense + "/LICENSE"}
	}
	cncfOf := func(p *customresources.Project) {
		p.Catalog, p.Upstream = customresources.CatalogCNCF, customresources.Upstream{}
	}
	set := func(slug string, edit func(p *customresources.Project)) func([]customresources.Project) []customresources.Project {
		return func(ps []customresources.Project) []customresources.Project {
			for i := range ps {
				if ps[i].Slug == slug {
					ps[i].Groups = append([]customresources.Group(nil), ps[i].Groups...)
					edit(&ps[i])
				}
			}
			return ps
		}
	}
	remove := func(slug string) func([]customresources.Project) []customresources.Project {
		return func(ps []customresources.Project) []customresources.Project {
			var out []customresources.Project
			for _, p := range ps {
				if p.Slug != slug {
					out = append(out, p)
				}
			}
			return out
		}
	}
	// first returns the slug of the first row of catalog for which build's
	// edit validates.
	first := func(catalog customresources.Catalog, build func(slug string) func([]customresources.Project) []customresources.Project) string {
		for _, p := range baseRows {
			if p.Catalog == catalog && loads(build(p.Slug)) {
				return p.Slug
			}
		}
		t.Fatalf("no %s row of the table can be edited that way", catalog)
		return ""
	}
	flipToCommunity := first(customresources.CatalogCNCF, func(s string) func([]customresources.Project) []customresources.Project {
		return set(s, communityOf)
	})
	flipToCNCF := first(customresources.CatalogCommunity, func(s string) func([]customresources.Project) []customresources.Project {
		return set(s, cncfOf)
	})
	removeCommunity := first(customresources.CatalogCommunity, remove)
	removeCNCF := first(customresources.CatalogCNCF, remove)
	cases := []struct {
		name string
		edit func([]customresources.Project) []customresources.Project
		want []string
	}{
		{"a community row the batch does not list", func(ps []customresources.Project) []customresources.Project { return append(ps, ocDefault.row()) },
			[]string{"O2: the table adds a row for " + ocDefault.slug, "O2: catalog split: the head table has " + ocDefault.slug + " as a community row"}},
		{"a CNCF row flipped to community with valid provenance", set(flipToCommunity, communityOf),
			[]string{"O2: the table row of " + flipToCommunity + " changes", "O2: catalog split: the head table has " + flipToCommunity + " as a community row", "O2: catalog split: the row of " + flipToCommunity + " moves from the cncf catalog to the community catalog"}},
		{"a community row flipped to CNCF", set(flipToCNCF, cncfOf),
			[]string{"O2: the table row of " + flipToCNCF + " changes", "O2: catalog split: the head table has " + flipToCNCF + " as a cncf row", "O2: catalog split: the row of " + flipToCNCF + " moves from the community catalog to the cncf catalog"}},
		{"a community row removed", remove(removeCommunity),
			[]string{"O2: the table row of " + removeCommunity + " is removed", "O2: catalog split: the head table lacks " + removeCommunity + " as a community row"}},
		{"a CNCF row removed", remove(removeCNCF),
			[]string{"O2: the table row of " + removeCNCF + " is removed", "O2: catalog split: the head table lacks " + removeCNCF + " as a cncf row"}},
		{"the batch's new CNCF project is a community row in the table", set(obSlug, communityOf),
			[]string{"O4: the batch names another catalog than the table row's", "O2: catalog split: the head table has " + obSlug + " as a community row", "O2: catalog split: the head table lacks " + obSlug + " as a cncf row"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newOnboardingFixture(t)
			pre, ok := f.tryRecord(t)
			if !ok {
				t.Fatal("the control batch is refused")
			}
			f.editTable(t, tc.edit)
			readmeMatchesHeadTable(t, f.head, DefaultLayout().Onboarding)

			// The record is signed for the edited head: the table checks
			// refuse it, O3 does not.
			problems := problemsFor(t, f, nil)
			for _, w := range tc.want {
				if !containsProblem(problems, w) {
					t.Errorf("no problem mentions %q:\n%s", w, strings.Join(problems, "\n"))
				}
			}
			if containsProblem(problems, "O3: the head state differs") {
				t.Errorf("a record signed for the edited head fails O3:\n%s", strings.Join(problems, "\n"))
			}
			// A record signed for the head without the edit: O3 refuses it.
			stale := problemsFor(t, f, &pre)
			if !containsProblem(stale, "O3: the head state differs from the one the batch was signed for") {
				t.Errorf("O3 does not refuse a record of another head:\n%s", strings.Join(stale, "\n"))
			}
			// The whole gate refuses the change.
			rec, _ := f.tryRecord(t)
			f.sign(t, rec)
			r := f.gate(t)
			if r.Passed() {
				t.Fatal("the gate passed an unauthorized table with its matching README")
			}
			if c, ok := check(r, CheckOnboarding); !ok || c.OK {
				t.Fatalf("the onboarding check did not refuse: %+v", c)
			}
		})
	}
	t.Run("the control batch has no table problem", func(t *testing.T) {
		t.Parallel()
		f := newOnboardingFixture(t)
		if problems := problemsFor(t, f, nil); len(problems) != 0 {
			t.Fatalf("problems:\n%s", strings.Join(problems, "\n"))
		}
	})
}

// A table that the gate cannot read exactly, strictly and in its canonical
// spelling admits no README: nothing is rendered from the table embedded in
// the gate, and the generated check fails.
func TestReadmeRegionRefusesUnreadableTables(t *testing.T) {
	t.Parallel()
	ol := defaultOnboardingLayout()
	rewrite := func(edit func(raw []byte) []byte) func(t *testing.T, tr Tree) {
		return func(t *testing.T, tr Tree) {
			path := filepath.Join(tr.Root, filepath.FromSlash(ol.TablePath))
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, path, edit(raw))
		}
	}
	schemaLine := []byte(`"schema": "` + customresources.TableSchema + `",`)
	cases := []struct {
		name string
		edit func(t *testing.T, tr Tree)
		want string
	}{
		{"not JSON", rewrite(func([]byte) []byte { return []byte("{") }), ""},
		{"empty file", rewrite(func([]byte) []byte { return nil }), ""},
		{"a second value", rewrite(func(raw []byte) []byte { return append(raw, []byte("{}")...) }), ""},
		{"an extra final newline", rewrite(func(raw []byte) []byte { return append(raw, '\n') }), "canonical spelling"},
		{"trailing spaces", rewrite(func(raw []byte) []byte { return append(raw, ' ', ' ') }), "canonical spelling"},
		{"a repeated member name", rewrite(func(raw []byte) []byte {
			return bytes.Replace(raw, schemaLine, append(append([]byte(nil), schemaLine...), append([]byte(` `), schemaLine...)...), 1)
		}), "ambiguous"},
		{"a member name repeated in another case", rewrite(func(raw []byte) []byte {
			return bytes.Replace(raw, schemaLine, append(append([]byte(nil), schemaLine...), []byte(` "Schema": "`+customresources.TableSchema+`",`)...), 1)
		}), "ambiguous"},
		{"an unknown member", rewrite(func(raw []byte) []byte {
			return bytes.Replace(raw, schemaLine, append(append([]byte(nil), schemaLine...), []byte(` "extra": 1,`)...), 1)
		}), "does not load"},
		{"an unknown catalog value", rewrite(func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`"catalog": "cncf"`), []byte(`"catalog": "other"`), 1)
		}), "does not load"},
		{"a repeated slug", rewrite(func(raw []byte) []byte {
			var doc struct {
				Schema   string           `json:"schema"`
				Projects []map[string]any `json:"projects"`
				Reserved []any            `json:"reserved"`
			}
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			doc.Projects = append([]map[string]any{doc.Projects[0]}, doc.Projects...)
			out, err := json.MarshalIndent(doc, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			return append(out, '\n')
		}), "does not load"},
		{"no projects", rewrite(func(raw []byte) []byte {
			return []byte(`{"schema": "` + customresources.TableSchema + `", "projects": [], "reserved": []}` + "\n")
		}), "does not load"},
		{"over the size bound", rewrite(func(raw []byte) []byte {
			return append(raw, bytes.Repeat([]byte(" "), int(MaxFileBytes))...)
		}), "exceeds"},
		{"a link", func(t *testing.T, tr Tree) {
			path := filepath.Join(tr.Root, filepath.FromSlash(ol.TablePath))
			real := path + ".real"
			if err := os.Rename(path, real); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Base(real), path); err != nil {
				t.Fatal(err)
			}
		}, ""},
		{"missing", func(t *testing.T, tr Tree) {
			if err := os.Remove(filepath.Join(tr.Root, filepath.FromSlash(ol.TablePath))); err != nil {
				t.Fatal(err)
			}
		}, ""},
	}
	layout := DefaultLayout()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			base, head := trees(t)
			// Control: the README of the head is the base's, which is what
			// a render from the embedded table would give.
			if got := layout.admittedBlocks(base, head, true); !got[readmePath] {
				t.Fatalf("the control head is not admitted: %v", got)
			}
			tc.edit(t, head)
			_, _, _, err := coverageReportOf(head, ol.TablePath)
			if err == nil {
				t.Fatal("the report is computed from an unreadable table")
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q, want %q", err, tc.want)
			}
			for _, mayChange := range []bool{true, false} {
				if got := layout.admittedBlocks(base, head, mayChange); got[readmePath] {
					t.Fatalf("the README is admitted (tableMayChange %v)", mayChange)
				}
			}
			r := &Report{}
			r.blockChecks(Options{Layout: layout, Head: head})
			if c, ok := check(r, "generated/"+readmePath); !ok || c.OK || !strings.Contains(c.Detail, "cannot regenerate") {
				t.Fatalf("the generated check does not fail closed: %+v", c)
			}
		})
	}
}

// Only an onboarding change may move the table. For every other caller a
// table that differs from the base's admits nothing, whatever README follows
// it.
func TestAdmittedBlocksTableMayChange(t *testing.T) {
	t.Parallel()
	layout := DefaultLayout()
	f := newCommunityFixture(t, ocDefault)
	readmeMatchesHeadTable(t, f.head, layout.Onboarding)
	if got := layout.admittedBlocks(f.base, f.head, true); !got[readmePath] {
		t.Fatalf("an onboarding change with the matching README is not admitted: %v", got)
	}
	if got := layout.admittedBlocks(f.base, f.head, false); got[readmePath] {
		t.Fatal("a change that is not an onboarding change carried a table edit with its README")
	}
	// A plain change of the table and the README, in the whole gate.
	r := runGate(t, Options{Base: f.base, Head: f.head, Author: obOwner, Sender: obOwner})
	if r.Passed() {
		t.Fatal("a plain change of the table passed the gate")
	}
	// An unchanged, readable table does not stand in the way.
	base, head := trees(t)
	if got := layout.admittedBlocks(base, head, false); !got[readmePath] {
		t.Fatalf("an unchanged table: %v", got)
	}
	// An unreadable table in either tree admits nothing for those callers.
	for _, side := range []string{"base", "head"} {
		base, head := trees(t)
		tr := map[string]Tree{"base": base, "head": head}[side]
		if err := os.Remove(filepath.Join(tr.Root, filepath.FromSlash(layout.Onboarding.TablePath))); err != nil {
			t.Fatal(err)
		}
		if got := layout.admittedBlocks(base, head, false); got[readmePath] {
			t.Fatalf("the %s has no table and the README is admitted", side)
		}
	}
}

// Every README region and the prose around them are held to the whole-file
// comparison also when the table moved, and a stale README is caught by the
// generated check.
func TestReadmeRegionEditsAndStaleREADME(t *testing.T) {
	t.Parallel()
	layout := DefaultLayout()
	breakers := map[string]func(string) string{"a digit of the CRD region": func(s string) string {
		i := strings.Index(s, coveragereport.READMECRDBegin)
		j := strings.IndexAny(s[i+len(coveragereport.READMECRDBegin):], "0123456789")
		k := i + len(coveragereport.READMECRDBegin) + j
		repl := "7"
		if s[k] == '7' {
			repl = "8"
		}
		return s[:k] + repl + s[k+1:]
	}}
	for name, b := range readmeBreakers {
		breakers[name] = b
	}
	for name, breaker := range breakers {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newCommunityFixture(t, ocDefault)
			editREADME(t, f.head, breaker)
			if got := layout.admittedBlocks(f.base, f.head, true); got[readmePath] {
				t.Fatal("an edited README was admitted with a table change")
			}
		})
	}
	t.Run("the README of the base with the table of the head", func(t *testing.T) {
		t.Parallel()
		f := newCommunityFixture(t, ocDefault)
		baseREADME, err := f.base.Read(readmePath, MaxFileBytes)
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(f.head.Root, readmePath), baseREADME)
		if got := layout.admittedBlocks(f.base, f.head, true); got[readmePath] {
			t.Fatal("a stale README was admitted")
		}
		r := &Report{}
		r.blockChecks(Options{Layout: layout, Head: f.head})
		if c, ok := check(r, "generated/"+readmePath); !ok || c.OK || !strings.Contains(c.Detail, "differs from") {
			t.Fatalf("the generated check does not catch a stale README: %+v", c)
		}
	})
	t.Run("the prose unchanged, the counts of the base", func(t *testing.T) {
		t.Parallel()
		f := newCommunityFixture(t, ocDefault)
		_, bm := readmeCounts(t, f.base)
		_, hm := readmeCounts(t, f.head)
		editREADME(t, f.head, func(s string) string {
			return strings.Replace(s, strconv.Itoa(hm)+" of the community catalog", strconv.Itoa(bm)+" of the community catalog", 1)
		})
		if got := layout.admittedBlocks(f.base, f.head, true); got[readmePath] {
			t.Fatal("a README with the base's community count was admitted")
		}
	})
}

// The table is read at the configured path, in the same way for the report and
// for the checks; a decoy at the default path does not count.
func TestReadmeRegionReadsTheConfiguredTablePath(t *testing.T) {
	t.Parallel()
	const custom = "data/other-table.json"
	f := newCommunityFixture(t, ocDefault)
	def := defaultOnboardingLayout()
	layout := DefaultLayout()
	layout.Onboarding.TablePath = custom
	baseTable, err := f.base.Read(def.TablePath, MaxFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	headTable, err := f.head.Read(def.TablePath, MaxFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	// The default path of the head holds the base's table (a decoy); the
	// configured path holds the head's.
	writeFile(t, filepath.Join(f.base.Root, custom), baseTable)
	writeFile(t, filepath.Join(f.head.Root, custom), headTable)
	writeFile(t, filepath.Join(f.head.Root, filepath.FromSlash(def.TablePath)), baseTable)

	if got := layout.admittedBlocks(f.base, f.head, true); !got[readmePath] {
		t.Fatalf("the README rendered from the configured path is not admitted: %v", got)
	}
	if got := DefaultLayout().admittedBlocks(f.base, f.head, true); got[readmePath] {
		t.Fatal("the README was admitted by rendering from the default path, which holds the decoy")
	}
	if _, _, _, err := coverageReportOf(f.head, "data/no-such-table.json"); err == nil {
		t.Fatal("a missing table path produced a report")
	}
	tr, err := readTableTree(f.head, custom)
	if err != nil || !bytes.Equal(tr.raw, headTable) {
		t.Fatalf("readTableTree: %v", err)
	}
	// The coverage floor reads the configured path too.
	if err := coverageFloor(f.head, f.head, custom); err != nil {
		t.Logf("coverage floor at the configured path: %v", err)
	}
	if err := coverageFloor(f.head, f.head, "data/no-such-table.json"); err == nil {
		t.Fatal("the coverage floor computed numbers without a table")
	}
}

// The table the render reads is the table the checks bound into the signed
// state.
func TestReadmeRegionRenderReadsTheBoundTable(t *testing.T) {
	t.Parallel()
	f := newCommunityFixture(t, ocDefault)
	layout := DefaultLayout()
	cls, err := Classify(layout, f.base, f.head)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := ChangedPaths(f.base, f.head)
	if err != nil {
		t.Fatal(err)
	}
	st, err := newOnboardingState(layout, f.base, f.head, cls, paths)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := readTableTree(f.head, layout.Onboarding.TablePath)
	if err != nil {
		t.Fatal(err)
	}
	if got := CandidateDigest(tr.raw); got != st.head.state.TableDigest {
		t.Fatalf("the render reads table %s, the checks bound %s", got, st.head.state.TableDigest)
	}
}

// withoutRulesDigest decodes the inventory and blanks the digest of the rule
// pack, the one input of the inventory that an onboarding change moves (the
// pack's registryDigest member moves with a new row).
func withoutRulesDigest(t *testing.T, raw []byte) any {
	t.Helper()
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var blank func(v any)
	blank = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				if s, ok := e.(string); ok && k == "rules" && strings.HasPrefix(s, "sha256:") {
					x[k] = ""
					continue
				}
				blank(e)
			}
		case []any:
			for _, e := range x {
				blank(e)
			}
		}
	}
	blank(doc)
	return doc
}

// The support inventory still reads the table embedded in the gate. For every
// change shape an onboarding batch may carry, its regeneration from the head
// equals the one from the base in every count and list, and its text equals
// the base's; only the digest of the rule pack moves, because the pack's
// registryDigest member does. The committed inventory of the head is that
// regeneration. So the generated-file check and the README (which prints the
// inventory) cannot disagree with the head's table.
func TestOnboardingShapesLeaveTheInventoryUnchanged(t *testing.T) {
	t.Parallel()
	layout := DefaultLayout()
	var inv GeneratedPair
	for _, g := range layout.Generated {
		if g.JSONPath == inventoryJSON {
			inv = g
		}
	}
	if inv.Generate == nil {
		t.Fatal("no generated inventory in the layout")
	}
	shapes := map[string]func(t *testing.T) *onboardingFixture{
		"a new CNCF project":      newOnboardingFixture,
		"a new community project": func(t *testing.T) *onboardingFixture { return newCommunityFixture(t, ocDefault) },
		"a CNCF attestation flip": func(t *testing.T) *onboardingFixture { return attestFixture(t, nil) },
		"a community attestation flip": func(t *testing.T) *onboardingFixture {
			return attestFixtureIn(t, crdversions.CatalogCommunity, nil)
		},
		"an amendment of kinds": func(t *testing.T) *onboardingFixture {
			f := newOnboardingFixture(t)
			f.shareWith(t, nil, []string{"Alpha", "Gamma"}, []string{"Beta"})
			return f
		},
	}
	for name, build := range shapes {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := build(t)
			if p := problemsFor(t, f, nil); len(p) != 0 {
				t.Fatalf("the shape is not a permitted onboarding change:\n%s", strings.Join(p, "\n"))
			}
			baseJSON, baseMD, err := inv.Generate(f.base)
			if err != nil {
				t.Fatal(err)
			}
			headJSON, headMD, err := inv.Generate(f.head)
			if err != nil {
				t.Fatal(err)
			}
			if baseMD != headMD {
				t.Fatal("the regenerated support inventory text moves with this change shape")
			}
			if !reflect.DeepEqual(withoutRulesDigest(t, baseJSON), withoutRulesDigest(t, headJSON)) {
				t.Fatal("the regenerated support inventory moves with this change shape in more than the digest of the rule pack")
			}
			committed, err := f.head.Read(inventoryJSON, MaxFileBytes)
			if err != nil || !bytes.Equal(committed, headJSON) {
				t.Fatal("the committed inventory of the head is not its regeneration")
			}
		})
	}
}

// Every block names a head test that exists in this package, and the renderer
// files of the coverage block are among its sources, so a change to one of
// them is judged by the head's own test.
func TestBlockHeadTestsExist(t *testing.T) {
	t.Parallel()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, e.Name(), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range file.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Test") {
				tests[fn.Name.Name] = true
			}
		}
	}
	for _, g := range DefaultLayout().GeneratedBlocks {
		if !tests[g.HeadTest] {
			t.Errorf("the head test %q of %s does not exist", g.HeadTest, g.Path)
		}
		for _, src := range g.Sources {
			if _, err := os.Stat(filepath.Join(repoRoot, filepath.FromSlash(src))); err != nil {
				t.Errorf("source %s of %s: %v", src, g.Path, err)
			}
		}
	}
	coverage := DefaultLayout().GeneratedBlocks[0]
	for _, want := range []string{
		"cli/internal/maintainer/coveragereport/catalog.go",
		"cli/internal/maintainer/knowledgegate/table_read.go",
		"cli/internal/maintainer/knowledgegate/generated_block.go",
	} {
		if !slices.Contains(coverage.Sources, want) {
			t.Errorf("%s is not a source of the coverage block", want)
		}
	}
}
