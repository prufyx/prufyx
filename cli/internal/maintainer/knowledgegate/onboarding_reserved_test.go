// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"sort"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/customresources"
)

const obReservedGroup = "a.storage.synthetic.k8s.io"

// reservedFixture is the onboarding fixture whose new project lists a group
// of a reserved namespace. mutate edits the head table's rows and records
// (it sees the record owned by the new project); the result is signed as the
// signer would sign what it can read. resign signs after the edit; otherwise
// the record is signed first and the edit happens after the signature.
func reservedFixture(t *testing.T, resign bool, mutate func(rows []customresources.Project, recs []customresources.ReservedGroup) ([]customresources.Project, []customresources.ReservedGroup)) *onboardingFixture {
	t.Helper()
	f := newOnboardingFixture(t)
	writeUpstream(t, f.upstream, obFrom, obCRD, obCRDDoc(obReservedGroup, "v1alpha1", "v1"))
	writeUpstream(t, f.upstream, obTo, obCRD, obCRDDoc(obReservedGroup, "v1"))
	edit := func(mut func([]customresources.Project, []customresources.ReservedGroup) ([]customresources.Project, []customresources.ReservedGroup)) {
		ol := DefaultLayout().Onboarding
		raw, err := f.head.Read(ol.TablePath, MaxFileBytes)
		if err != nil {
			t.Fatal(err)
		}
		rows, recs, err := customresources.LoadTable(raw)
		if err != nil {
			t.Fatal(err)
		}
		rows, recs = mut(rows, recs)
		out, err := customresources.CanonicalTable(rows, sortReserved(recs))
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, obHeadPath(f, ol.TablePath), out)
		f.follow(t)
	}
	// The born-together shape: the new row lists the group, the record names it.
	edit(func(rows []customresources.Project, recs []customresources.ReservedGroup) ([]customresources.Project, []customresources.ReservedGroup) {
		for i := range rows {
			if rows[i].Slug == obSlug {
				rows[i].Groups = []customresources.Group{{Name: obReservedGroup, Source: rows[i].Groups[0].Source}}
			}
		}
		recs = append(recs, customresources.ReservedGroup{Name: obReservedGroup, Owner: obSlug, Repository: "https://" + obRepo, Reason: "synthetic group defined by this repository alone"})
		return rows, recs
	})
	f.draft.Projects[0].Groups = []string{obReservedGroup}
	if resign {
		f.refresh()
		pre := f.record(t)
		if mutate != nil {
			edit(mutate)
		}
		f.refresh()
		rec, _ := f.tryRecord(t)
		if rec.BatchID == "" {
			// The edited head cannot be read at all: sign the unedited record.
			rec = pre
		}
		f.sign(t, rec)
		return f
	}
	f.refresh()
	f.sign(t, f.record(t))
	if mutate != nil {
		edit(mutate)
	}
	return f
}

func obHeadPath(f *onboardingFixture, rel string) string {
	return f.head.Root + "/" + rel
}

func TestOnboardingBatchAdmitsReservedRecordBornWithItsRow(t *testing.T) {
	t.Parallel()
	f := reservedFixture(t, true, nil)
	r := f.gate(t)
	requirePass(t, r)
	if c, ok := check(r, CheckOnboarding); !ok || !c.OK {
		t.Fatalf("onboarding check %+v", c)
	}
}

func TestOnboardingBatchReservedRecordRefusals(t *testing.T) {
	t.Parallel()
	type rows = []customresources.Project
	type recs = []customresources.ReservedGroup
	cases := []struct {
		name   string
		resign bool
		mutate func(rows, recs) (rows, recs)
		want   string
	}{
		{"record owned by an existing project", true, func(rs rows, rc recs) (rows, recs) {
			other := otherSlug()
			for i := range rs {
				switch rs[i].Slug {
				case obSlug:
					rs[i].Groups = []customresources.Group{{Name: obGroup, Source: rs[i].Groups[0].Source}}
				case other:
					rs[i].Groups = append(rs[i].Groups, customresources.Group{Name: obReservedGroup, Source: rs[i].Groups[0].Source})
					sort.Slice(rs[i].Groups, func(a, b int) bool { return rs[i].Groups[a].Name < rs[i].Groups[b].Name })
				}
			}
			for i := range rc {
				if rc[i].Name == obReservedGroup {
					for _, p := range rs {
						if p.Slug == other {
							rc[i].Owner, rc[i].Repository = other, "https://github.com/"+strings.TrimPrefix(p.Component, "pkg:github/")
						}
					}
				}
			}
			return rs, rc
		}, "not a new project row of the batch"},
		{"record whose owner row is absent", true, func(rs rows, rc recs) (rows, recs) {
			for i := range rc {
				if rc[i].Name == obReservedGroup {
					rc[i].Owner = "no-such-project"
				}
			}
			return rs, rc
		}, "does not load"},
		{"record with another repository", true, func(rs rows, rc recs) (rows, recs) {
			for i := range rc {
				if rc[i].Name == obReservedGroup {
					rc[i].Repository = "https://github.com/someone/else"
				}
			}
			return rs, rc
		}, "does not load"},
		{"existing record changed", true, func(rs rows, rc recs) (rows, recs) {
			for i := range rc {
				if rc[i].Name != obReservedGroup {
					rc[i].Reason += " (edited)"
					return rs, rc
				}
			}
			t.Fatal("no existing record")
			return rs, rc
		}, "changes"},
		{"existing record removed", true, func(rs rows, rc recs) (rows, recs) {
			var out recs
			dropped := false
			for _, r := range rc {
				if r.Name != obReservedGroup && !dropped {
					dropped = true
					continue
				}
				out = append(out, r)
			}
			if !dropped {
				t.Fatal("no existing record")
			}
			return rs, out
		}, "does not load"},
		{"reserved group on a row without a record", true, func(rs rows, rc recs) (rows, recs) {
			var out recs
			for _, r := range rc {
				if r.Name != obReservedGroup {
					out = append(out, r)
				}
			}
			return rs, out
		}, "does not load"},
		{"record bytes changed after signing", false, func(rs rows, rc recs) (rows, recs) {
			for i := range rc {
				if rc[i].Name == obReservedGroup {
					rc[i].Reason = "a different reason than the one signed"
				}
			}
			return rs, rc
		}, "O3: the head state differs"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := reservedFixture(t, tc.resign, tc.mutate)
			r := f.gate(t)
			requireFail(t, r, tc.want)
			for _, ch := range r.Changes {
				if ch.Member != "" && ch.OK {
					t.Fatalf("member change admitted: %+v", ch)
				}
			}
		})
	}
}

func TestReservedChangesUnit(t *testing.T) {
	t.Parallel()
	const (
		repo  = "https://github.com/synthetic/owner"
		group = "a.storage.synthetic.k8s.io"
		other = "b.storage.synthetic.k8s.io"
	)
	row := func(slug string, groups ...customresources.Group) customresources.Project {
		return customresources.Project{Slug: slug, Catalog: customresources.CatalogCNCF, Component: "pkg:github/synthetic/owner", Groups: groups}
	}
	whole := customresources.Group{Name: group}
	rec := customresources.ReservedGroup{Name: group, Owner: "fresh", Repository: repo, Reason: "synthetic"}
	old := customresources.ReservedGroup{Name: other, Owner: "old", Repository: repo, Reason: "synthetic"}
	batch := func(kind string) OnboardingRecord {
		return OnboardingRecord{Projects: []OnboardingProject{{Slug: "fresh", Kind: kind}}}
	}
	baseRows := map[string]customresources.Project{"old": row("old")}
	headRows := func(r customresources.Project) map[string]customresources.Project {
		return map[string]customresources.Project{"old": row("old"), "fresh": r}
	}
	cases := []struct {
		name string
		rec  OnboardingRecord
		base []customresources.ReservedGroup
		head []customresources.ReservedGroup
		rows map[string]customresources.Project
		want string // empty: admitted
	}{
		{"born together", batch(OnboardingKindNew), []customresources.ReservedGroup{old}, []customresources.ReservedGroup{rec, old}, headRows(row("fresh", whole)), ""},
		{"removal", batch(OnboardingKindNew), []customresources.ReservedGroup{old}, nil, headRows(row("fresh")), "is removed"},
		{"change", batch(OnboardingKindNew), []customresources.ReservedGroup{old}, []customresources.ReservedGroup{{Name: other, Owner: "old", Repository: repo, Reason: "edited"}}, headRows(row("fresh")), "changes"},
		{"repository mismatch", batch(OnboardingKindNew), nil, []customresources.ReservedGroup{{Name: group, Owner: "fresh", Repository: "https://github.com/someone/else", Reason: "synthetic"}}, headRows(row("fresh", whole)), "repository other than"},
		{"kinds listed", batch(OnboardingKindNew), nil, []customresources.ReservedGroup{rec}, headRows(row("fresh", customresources.Group{Name: group, Kinds: []string{"Thing"}})), "does not list the group whole"},
		{"attest-kind project", batch(OnboardingKindAttest), nil, []customresources.ReservedGroup{rec}, headRows(row("fresh", whole)), "not a new project row"},
		{"owner is an existing row", batch(OnboardingKindNew), nil, []customresources.ReservedGroup{{Name: group, Owner: "old", Repository: repo, Reason: "synthetic"}}, headRows(row("fresh", whole)), "not a new project row"},
		{"owner row absent", batch(OnboardingKindNew), nil, []customresources.ReservedGroup{{Name: group, Owner: "gone", Repository: repo, Reason: "synthetic"}}, headRows(row("fresh", whole)), "not a new project row"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := reservedChanges(tc.rec, tc.base, tc.head, baseRows, tc.rows)
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("refused: %v", got)
				}
				return
			}
			if len(got) == 0 || !strings.Contains(strings.Join(got, "\n"), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, got)
			}
		})
	}
}
