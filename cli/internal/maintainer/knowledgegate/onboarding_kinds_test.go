// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/customresources"
)

// The shared-group tests share a group of the reviewed table (antrea's
// crd.antrea.io, a whole listing in the base) with the fixture's new project.
const kindsGroup = "crd.antrea.io"

func kindsSourceURL() string {
	return "https://github.com/" + obOwnerRepo + "/blob/" + obTo + "/" + obCRD
}

// setListing sets the kinds of antrea's listing of kindsGroup.
func setListing(ps []customresources.Project, kinds []string) []customresources.Project {
	for i := range ps {
		if ps[i].Slug != "antrea" {
			continue
		}
		for j := range ps[i].Groups {
			if ps[i].Groups[j].Name == kindsGroup {
				ps[i].Groups[j].Kinds = kinds
			}
		}
	}
	return ps
}

// editBaseTable rewrites the base table (the registry does not depend on
// kinds, so nothing else of the base moves).
func (f *onboardingFixture) editBaseTable(t *testing.T, edit func([]customresources.Project) []customresources.Project) {
	t.Helper()
	ol := DefaultLayout().Onboarding
	raw, err := f.base.Read(ol.TablePath, MaxFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	projects, reserved, err := customresources.LoadTable(raw)
	if err != nil {
		t.Fatal(err)
	}
	table, err := customresources.CanonicalTable(edit(projects), reserved)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(f.base.Root, filepath.FromSlash(ol.TablePath)), table)
}

// shareWith makes the fixture's new project list kindsGroup with kinds, and
// lets the head's antrea listing be edit's (the base's is baseKinds).
func (f *onboardingFixture) shareWith(t *testing.T, baseKinds, headKinds, newKinds []string) {
	t.Helper()
	f.editBaseTable(t, func(ps []customresources.Project) []customresources.Project { return setListing(ps, baseKinds) })
	for _, c := range []string{obFrom, obTo} {
		writeUpstream(t, f.upstream, c, obCRD, obCRDDoc(kindsGroup, "v1"))
	}
	f.editTable(t, func(ps []customresources.Project) []customresources.Project {
		ps = setListing(ps, headKinds)
		for i := range ps {
			if ps[i].Slug == obSlug {
				ps[i].Groups = []customresources.Group{{Name: kindsGroup, Source: kindsSourceURL(), Kinds: newKinds}}
			}
		}
		return ps
	})
	f.draft.Projects[0].Groups = []string{kindsGroup}
	f.refresh()
}

// problems runs the offline checks the signer and the gate share.
func (f *onboardingFixture) problems(t *testing.T) []string {
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
	rec := OnboardingRecord{Base: st.base.state, Head: st.head.state, BatchID: f.draft.BatchID, CandidateID: f.draft.CandidateID, ChangeSetDigest: st.changeSetDigest, Nonce: obNonce, Projects: f.draft.Projects}
	rec.Sample, err = onboardingSample(rec.core())
	if err != nil {
		t.Fatal(err)
	}
	return st.check(rec, layout.Onboarding.Dir+"/"+rec.BatchID+".json")
}

func TestOnboardingSharedGroupByKinds(t *testing.T) {
	t.Parallel()
	alpha, beta, widget := []string{"Alpha"}, []string{"Beta"}, []string{"Widget"}
	for _, tc := range []struct {
		name              string
		base, head, added []string
		want              string // "" admitted; else a problem fragment
	}{
		{"disjoint kinds next to a kinded listing", alpha, alpha, beta, ""},
		{"kinds added to the whole listing the batch shares", nil, alpha, beta, ""},
		{"overlapping kinds", alpha, alpha, []string{"Alpha", "Beta"}, "does not load"},
		{"whole listing next to a new listing", nil, nil, beta, "does not load"},
		{"new whole listing next to a kinded one", alpha, alpha, nil, "does not load"},
		{"kinds added to a listing that already had kinds", alpha, []string{"Alpha", "Zeta"}, beta, "the table row of antrea changes"},
		{"kinds replaced", alpha, widget, beta, "the table row of antrea changes"},
		{"kinds removed", alpha, nil, beta, "does not load"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newOnboardingFixture(t)
			f.shareWith(t, tc.base, tc.head, tc.added)
			problems := strings.Join(f.problems(t), "\n")
			switch {
			case tc.want == "" && problems != "":
				t.Fatalf("refused: %s", problems)
			case tc.want != "" && !strings.Contains(problems, tc.want):
				t.Fatalf("problems %q, want %q", problems, tc.want)
			}
		})
	}
}

// An amendment is limited to adding kinds, for a group the batch shares.
func TestOnboardingAmendmentLimits(t *testing.T) {
	t.Parallel()
	beta := []string{"Beta"}
	for name, edit := range map[string]func(ps []customresources.Project) []customresources.Project{
		"kinds on a group nobody in the batch shares": func(ps []customresources.Project) []customresources.Project {
			for i := range ps {
				if ps[i].Slug == "antrea" {
					for j := range ps[i].Groups {
						if ps[i].Groups[j].Name == "multicluster.crd.antrea.io" {
							ps[i].Groups[j].Kinds = []string{"Alpha"}
						}
					}
				}
			}
			return ps
		},
		"another field of the row changes too": func(ps []customresources.Project) []customresources.Project {
			for i := range ps {
				if ps[i].Slug == "antrea" {
					ps[i].Groups[0].Source = strings.Replace(ps[i].Groups[0].Source, "/blob/", "/blob/x", 1)
				}
			}
			return ps
		},
		"a group of the row is dropped": func(ps []customresources.Project) []customresources.Project {
			for i := range ps {
				if ps[i].Slug == "antrea" {
					ps[i].Groups = ps[i].Groups[1:]
				}
			}
			return ps
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newOnboardingFixture(t)
			f.shareWith(t, nil, []string{"Alpha"}, beta)
			f.editTable(t, edit)
			problems := strings.Join(f.problems(t), "\n")
			if !strings.Contains(problems, "the table row of antrea changes") && !strings.Contains(problems, "does not load") {
				t.Fatalf("problems %q", problems)
			}
		})
	}
}

// An amendment with no new project sharing its group is refused.
func TestOnboardingAmendmentWithoutSharingRow(t *testing.T) {
	t.Parallel()
	f := newOnboardingFixture(t)
	f.editTable(t, func(ps []customresources.Project) []customresources.Project { return setListing(ps, []string{"Alpha"}) })
	problems := strings.Join(f.problems(t), "\n")
	if !strings.Contains(problems, "the table row of antrea changes") {
		t.Fatalf("problems %q", problems)
	}
}

// The full gate admits an amending batch, and the review summary shows the
// amendment and the new row's kinds to the signer.
func TestOnboardingGateAdmitsAmendingBatch(t *testing.T) {
	t.Parallel()
	f := newOnboardingFixture(t)
	f.shareWith(t, nil, []string{"Alpha", "Gamma"}, []string{"Beta"})
	rec := f.record(t)
	f.sign(t, rec)
	requirePass(t, f.gate(t))

	layout := DefaultLayout()
	cls, err := Classify(layout, f.base, f.head)
	if err != nil {
		t.Fatal(err)
	}
	paths, _ := ChangedPaths(f.base, f.head)
	st, err := newOnboardingState(layout, f.base, f.head, cls, paths)
	if err != nil {
		t.Fatal(err)
	}
	summary := st.summary(rec)
	for _, want := range []string{"## Amended table rows", "- antrea, group crd.antrea.io: Alpha, Gamma", "## Listed kinds of the new rows", "- " + obSlug + ", group crd.antrea.io: Beta"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary lacks %q", want)
		}
	}
}

// A batch without kinds renders the summary it rendered before kinds existed:
// no kinds sections and no Kinds member in the table row.
func TestOnboardingSummaryWithoutKindsIsUnchanged(t *testing.T) {
	t.Parallel()
	f := newOnboardingFixture(t)
	rec := f.record(t)
	layout := DefaultLayout()
	cls, err := Classify(layout, f.base, f.head)
	if err != nil {
		t.Fatal(err)
	}
	paths, _ := ChangedPaths(f.base, f.head)
	st, err := newOnboardingState(layout, f.base, f.head, cls, paths)
	if err != nil {
		t.Fatal(err)
	}
	summary := st.summary(rec)
	if strings.Contains(summary, "Kinds") || strings.Contains(summary, "Amended") || strings.Contains(summary, "Listed kinds") {
		t.Fatalf("summary mentions kinds:\n%s", summary)
	}
	if !strings.Contains(summary, `"Source"`) {
		t.Fatalf("summary has no table row:\n%s", summary)
	}
}
