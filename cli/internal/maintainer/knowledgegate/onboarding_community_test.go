// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
)

// O4 for the community catalog: a batch may onboard a community project (a
// table row with an upstream record, outside the landscape) and turn on its
// attestation, under the same checks as a CNCF project's. Every name here is
// synthetic.

// ocSpec names a synthetic project of the fixture.
type ocSpec struct{ slug, ownerRepo string }

var ocDefault = ocSpec{slug: "synthetic-widgets-operator", ownerRepo: "synthetic-widgets/operator"}

func (s ocSpec) repo() string      { return "github.com/" + s.ownerRepo }
func (s ocSpec) component() string { return "pkg:github/" + s.ownerRepo }
func (s ocSpec) fact() string      { return strings.ReplaceAll(s.slug, "-", "_") }

const (
	ocGroup   = "widgets.synthetic.example"
	ocCRD     = "deploy/crds/widgets.yaml"
	ocLicense = "0123456789abcdef0123456789abcdef01234567"
)

// targetJSON is the project's target file; catalog is spelled in it unless
// empty.
func (s ocSpec) targetJSON(catalog string) string {
	spelled := ""
	if catalog != "" {
		spelled = `"catalog": "` + catalog + `",` + "\n    "
	}
	return `{
  "schema": "prufyx.io/crd-version-target/v1",
  "target": {
    "project": "` + s.slug + `",
    ` + spelled + `"name": "Synthetic Widgets",
    "repo": "` + s.repo() + `",
    "component": "` + s.component() + `",
    "factProject": "` + s.fact() + `",
    "tagPrefixes": ["v"],
    "minFrom": "1.0",
    "paths": [
      {"path": "deploy/crds", "directory": true, "match": "^[^.][^/]*\\.ya?ml$", "guard": "(?i)crd"}
    ],
    "exclude": []
  }
}
`
}

// row is the project's table row as a community row.
func (s ocSpec) row() customresources.Project {
	return customresources.Project{Slug: s.slug, Catalog: customresources.CatalogCommunity, FactProject: s.fact(), Component: s.component(),
		Upstream: customresources.Upstream{Name: "Synthetic Widgets", Repository: "https://" + s.repo(), License: "Apache-2.0", LicenseSource: "https://" + s.repo() + "/blob/" + ocLicense + "/LICENSE"},
		Groups:   []customresources.Group{{Name: ocGroup, Source: "https://" + s.repo() + "/blob/" + obTo + "/" + ocCRD}}}
}

// newCommunityFixture is an onboarding batch of one new community project,
// served by a local upstream fixture.
func newCommunityFixture(t *testing.T, s ocSpec) *onboardingFixture {
	t.Helper()
	base, head := trees(t)
	onboardingRepoFiles(t, base)
	onboardingRepoFiles(t, head)
	key := newApprovalKey(t)
	key.pinBoth(t, base, head, obOwner)
	up := t.TempDir()
	writeFile(t, filepath.Join(up, filepath.FromSlash(s.repo()), "tags.json"), []byte(`{"v1.0.0": "`+obFrom+`", "v1.1.0": "`+obTo+`"}`))
	for commit, doc := range map[string]string{obFrom: obCRDDoc(ocGroup, "v1alpha1", "v1"), obTo: obCRDDoc(ocGroup, "v1")} {
		writeFile(t, filepath.Join(up, filepath.FromSlash(s.repo()), "commits", commit, filepath.FromSlash(ocCRD)), []byte(doc))
	}
	f := &onboardingFixture{base: base, head: head, key: key, upstream: up, src: &obSource{FixtureReader: extract.FixtureReader{Root: up}, perList: 1}, signedAt: gateNow.Add(-time.Hour)}
	ol := DefaultLayout().Onboarding
	writeFile(t, filepath.Join(f.head.Root, filepath.FromSlash(targetPath(ol, s.slug))), []byte(s.targetJSON("community")))
	f.editTable(t, func(ps []customresources.Project) []customresources.Project { return append(ps, s.row()) })
	p := f.project(s.slug, OnboardingKindNew, ocGroup)
	p.Catalog = "community"
	f.draft = onboardingDraft{BatchID: "ob-20261003-1", CandidateID: "pr-1", Projects: []OnboardingProject{p}}
	return f
}

// blindSign changes the head with edit, then signs what the signer would
// refuse (the record of the unedited head when the edited one cannot be read).
func (f *onboardingFixture) blindSign(t *testing.T, edit func()) {
	t.Helper()
	pre, _ := f.tryRecord(t)
	edit()
	f.refresh()
	rec, _ := f.tryRecord(t)
	if rec.BatchID == "" {
		rec = pre
	}
	f.sign(t, rec)
}

func (f *onboardingFixture) editTargetOf(t *testing.T, slug string, edit func(target map[string]any)) {
	t.Helper()
	path := filepath.Join(f.head.Root, filepath.FromSlash(targetPath(DefaultLayout().Onboarding, slug)))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	edit(doc["target"].(map[string]any))
	out, _ := json.MarshalIndent(doc, "", "  ")
	writeFile(t, path, append(out, '\n'))
	f.writeDocs(t)
}

// A batch onboards a community project: admitted, and the only pack change
// is the cncf pack's registryDigest (no rule, no record, no other member).
func TestOnboardingCommunityNewAdmitted(t *testing.T) {
	t.Parallel()
	f := newCommunityFixture(t, ocDefault)
	f.sign(t, f.record(t))
	r := f.gate(t)
	requirePass(t, r)
	if c, ok := check(r, CheckOnboarding); !ok || !c.OK || !strings.Contains(c.Detail, "admits 1 projects") {
		t.Fatalf("onboarding check %+v", c)
	}
	if len(r.Changes) != 1 || r.Changes[0].Member != "registryDigest" || r.Changes[0].Pack != "cncf" || !r.Changes[0].OK || r.Changes[0].Proof != ProofOnboarding {
		t.Fatalf("changes %+v", r.Changes)
	}
	// Byte level: the head pack is the base pack with its registryDigest
	// replaced, so no rule, record, section or other member moved.
	baseRaw, err := f.base.Read(cncfRulesPath, MaxFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	headRaw, err := f.head.Read(cncfRulesPath, MaxFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	var baseMembers, headMembers struct {
		RegistryDigest string `json:"registryDigest"`
	}
	if json.Unmarshal(baseRaw, &baseMembers) != nil || json.Unmarshal(headRaw, &headMembers) != nil || baseMembers.RegistryDigest == headMembers.RegistryDigest {
		t.Fatal("the registryDigest did not move")
	}
	if !bytes.Equal(bytes.Replace(headRaw, []byte(headMembers.RegistryDigest), []byte(baseMembers.RegistryDigest), 1), baseRaw) {
		t.Fatal("the head pack differs from the base pack in more than its registryDigest")
	}
}

func TestOnboardingCommunityRefusals(t *testing.T) {
	t.Parallel()
	ol := DefaultLayout().Onboarding
	cases := []struct {
		name string
		spec ocSpec
		edit func(t *testing.T, f *onboardingFixture)
		want string
	}{
		{name: "the slug is in the landscape", spec: ocSpec{slug: obSlug, ownerRepo: obOwnerRepo}, want: "may not be in the CNCF landscape catalog"},
		{name: "the target repository is not the row's upstream", spec: ocDefault, edit: func(t *testing.T, f *onboardingFixture) {
			f.editTargetOf(t, ocDefault.slug, func(tg map[string]any) {
				tg["repo"], tg["component"] = ocDefault.repo()+"-fork", ocDefault.component()+"-fork"
			})
		}, want: "is not the table row's upstream repository"},
		{name: "the target names no catalog but the row is community", spec: ocDefault, edit: func(t *testing.T, f *onboardingFixture) {
			writeFile(t, filepath.Join(f.head.Root, filepath.FromSlash(targetPath(ol, ocDefault.slug))), []byte(ocDefault.targetJSON("")))
			f.writeDocs(t)
		}, want: "name different catalogs"},
		{name: "the batch names another catalog than the row", spec: ocDefault, edit: func(t *testing.T, f *onboardingFixture) {
			f.draft.Projects[0].Catalog = "cncf"
		}, want: "another catalog than the table row's"},
		{name: "a new community target attests", spec: ocDefault, edit: func(t *testing.T, f *onboardingFixture) {
			f.editTargetOf(t, ocDefault.slug, func(tg map[string]any) { tg["attest"] = true })
		}, want: "a new target may not attest"},
		{name: "a community target with exclusions", spec: ocDefault, edit: func(t *testing.T, f *onboardingFixture) {
			f.editTargetOf(t, ocDefault.slug, func(tg map[string]any) {
				tg["exclude"] = []any{map[string]any{"path": "test/crds/", "repo": ocDefault.repo(), "reason": "end-to-end test manifests", "evidence": "the directory holds only the manifests of the end-to-end tests"}}
			})
		}, want: "may not exclude files"},
		{name: "a community row in a reserved group (the table refuses it before the batch check)", spec: ocDefault, edit: func(t *testing.T, f *onboardingFixture) {
			f.editTable(t, func(ps []customresources.Project) []customresources.Project {
				for i := range ps {
					if ps[i].Slug == ocDefault.slug {
						ps[i].Groups[0].Name = "a.widgets.synthetic.k8s.io"
					}
				}
				return ps
			})
			f.draft.Projects[0].Groups = []string{"a.widgets.synthetic.k8s.io"}
		}, want: "custom-resource table does not load"},
		{name: "the row has no upstream record", spec: ocDefault, edit: func(t *testing.T, f *onboardingFixture) {
			raw, err := f.head.Read(ol.TablePath, MaxFileBytes)
			if err != nil {
				t.Fatal(err)
			}
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			for _, p := range doc["projects"].([]any) {
				if m := p.(map[string]any); m["slug"] == ocDefault.slug {
					delete(m, "upstream")
				}
			}
			out, _ := json.MarshalIndent(doc, "", "  ")
			writeFile(t, filepath.Join(f.head.Root, filepath.FromSlash(ol.TablePath)), append(out, '\n'))
		}, want: "custom-resource table does not load"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newCommunityFixture(t, tc.spec)
			f.blindSign(t, func() {
				if tc.edit != nil {
					tc.edit(t, f)
				}
			})
			requireFail(t, f.gate(t), tc.want)
		})
	}
}

// A CNCF row with a community target is refused (the other direction of the
// catalog equality).
func TestOnboardingCNCFRowCommunityTargetRefused(t *testing.T) {
	t.Parallel()
	f := newOnboardingFixture(t)
	f.blindSign(t, func() {
		f.editTargetOf(t, obSlug, func(tg map[string]any) { tg["catalog"] = "community" })
	})
	requireFail(t, f.gate(t), "name different catalogs")
}

// Control: the CNCF path is unchanged; its landscape checks still apply.
func TestOnboardingCNCFLandscapeChecksUnchanged(t *testing.T) {
	t.Parallel()
	f := newOnboardingFixture(t)
	f.sign(t, f.record(t))
	requirePass(t, f.gate(t))
}

// A batch of more than 50 projects is refused whatever the catalog.
func TestOnboardingCommunityOverBatchCap(t *testing.T) {
	t.Parallel()
	f := newCommunityFixture(t, ocDefault)
	rec := f.record(t)
	for len(rec.Projects) <= MaxOnboardingProjects {
		q := rec.Projects[0]
		q.Slug += "-" + strings.Repeat("x", len(rec.Projects))
		rec.Projects = append(rec.Projects, q)
	}
	if err := rec.validate(); err == nil || !strings.Contains(err.Error(), "holds 1 to 50 projects") {
		t.Fatalf("51 projects: %v", err)
	}
}

// Attestation of a community project of the base is turned on like a CNCF
// project's: only the attest member changes.
func TestOnboardingCommunityAttestFlip(t *testing.T) {
	t.Parallel()
	f := attestFixtureIn(t, crdversions.CatalogCommunity, nil)
	f.sign(t, f.record(t))
	r := f.gate(t)
	requirePass(t, r)
	if len(r.Changes) != 0 {
		t.Fatalf("an attest flip changes no pack member, got %+v", r.Changes)
	}
	// The batch's catalog must be the row's.
	f = attestFixtureIn(t, crdversions.CatalogCommunity, nil)
	f.draft.Projects[0].Catalog = "cncf"
	rec, _ := f.tryRecord(t)
	f.sign(t, rec)
	requireFail(t, f.gate(t), "another catalog than the table row's")
}
