// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/customresources"
)

// Fixtures of derive mode are synthetic trees with neutral names.
const (
	dvGroup   = "widgets.example.test"
	dvForeign = "gadgets.example.test"
)

func dvCRD(group, kind, desc string) string {
	return "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nspec:\n  group: " + group +
		"\n  names:\n    kind: " + kind + "\n  versions:\n  - name: v1\n    served: true\n    storage: true\n    schema:\n      openAPIV3Schema:\n        description: " + desc + "\n"
}

// dvBase is the control layout: one install directory, two definitions.
func dvBase() map[string]string {
	return map[string]string{
		"config/crd/bases/a.yaml": dvCRD(dvGroup, "Alpha", "d"),
		"config/crd/bases/b.yaml": dvCRD(dvGroup, "Beta", "d"),
		"README.md":               "not a definition",
	}
}

func dvSource(tags []string, files func() map[string]string, mutate func(tag string, m *memTree)) memSource {
	s := memSource{trees: map[string]*memTree{}}
	for _, tag := range tags {
		m := newMemTree()
		for p, c := range files() {
			m.files[p] = []byte(c)
		}
		if mutate != nil {
			mutate(tag, m)
		}
		s.trees[tag] = m
	}
	return s
}

func dvInput(src Source, idx *customresources.Index) Input {
	in := ipInput(src, nil)
	in.DeriveRules = true
	if idx == nil {
		idx = kindIndex()
	}
	in.Index = idx
	return in
}

func dvOwnedBy(slug string, groups ...string) *customresources.Index {
	var gs []customresources.Group
	for _, g := range groups {
		gs = append(gs, customresources.Group{Name: g})
	}
	return kindIndex(customresources.Project{Slug: slug, Groups: gs})
}

func dvRun(t *testing.T, files func() map[string]string, mutate func(string, *memTree), idx *customresources.Index) (*Result, error) {
	t.Helper()
	return Generate(dvInput(dvSource(ipTags, files, mutate), idx))
}

func dvOK(t *testing.T, files func() map[string]string, mutate func(string, *memTree), idx *customresources.Index) *Result {
	t.Helper()
	res, err := dvRun(t, files, mutate, idx)
	if err != nil {
		t.Fatalf("want a draft: %v", err)
	}
	return res
}

func dvStop(t *testing.T, files func() map[string]string, mutate func(string, *memTree), idx *customresources.Index, code string) *StopError {
	t.Helper()
	res, err := dvRun(t, files, mutate, idx)
	if err == nil {
		t.Fatalf("want stop %s, got a draft", code)
	}
	if res != nil {
		t.Fatal("a stop returns no result")
	}
	return wantStop(t, err, code)
}

func dvRules(t *testing.T, res *Result) *Rules {
	t.Helper()
	r, err := ParseRules(res.RulesJSON)
	if err != nil {
		t.Fatalf("derived rules do not parse: %v", err)
	}
	return r
}

func TestDeriveControlUsesRuleR2(t *testing.T) {
	files := func() map[string]string {
		m := dvBase()
		m["charts/x/crds/all.yaml"] = dvCRD(dvGroup, "Alpha", "d") + "---\n" + dvCRD(dvGroup, "Beta", "d")
		m["bundle/manifests/all.yaml"] = dvCRD(dvGroup, "Alpha", "d")
		m["docs/crds/a.yaml"] = dvCRD(dvGroup, "Alpha", "d")
		return m
	}
	res := dvOK(t, files, nil, nil)
	r := dvRules(t, res)
	if len(r.InstallPaths) != 1 || r.InstallPaths[0].Path != "config/crd/bases/" || len(r.Exclusions) != 0 {
		t.Fatalf("rules: %+v", r)
	}
	d := res.Report.DerivedRules
	if d == nil || d.Rule != "R2" || len(d.Loosening) != 0 || d.InstallPath != "config/crd/bases/" || len(d.Tags) != 3 {
		t.Fatalf("report block: %+v", d)
	}
	if !strings.Contains(string(res.Changelog), "derived from tree facts") {
		t.Fatal("changelog does not say the rules were derived")
	}
	if res.Report.CRDCount != 2 {
		t.Fatalf("crds %d", res.Report.CRDCount)
	}
}

// Derived output is byte-identical on a second run and the facts digest moves
// with the derivation.
func TestDeriveIsDeterministic(t *testing.T) {
	a := dvOK(t, dvBase0, nil, nil)
	b := dvOK(t, dvBase0, nil, nil)
	ra, _ := marshal(a.Report)
	rb, _ := marshal(b.Report)
	if !bytes.Equal(a.A, b.A) || !bytes.Equal(a.B, b.B) || !bytes.Equal(a.RulesJSON, b.RulesJSON) || !bytes.Equal(ra, rb) || !bytes.Equal(a.Changelog, b.Changelog) {
		t.Fatal("two derive runs differ")
	}
	plain, err := Generate(func() Input {
		in := ipInput(dvSource(ipTags, dvBase0, nil), ipRules(t, `[{"path":"config/crd/bases/","reason":"r","evidence":"e"}]`))
		in.Index = kindIndex()
		return in
	}())
	if err != nil {
		t.Fatal(err)
	}
	if plain.Report.FactsDigest == a.Report.FactsDigest {
		t.Fatal("derive facts digest equals the hand-rule digest: the derivation is not covered")
	}
}

func dvBase0() map[string]string { return dvBase() }

// ---- rule R3 and the same-tag literal reference (C4) ----

func dvR3Files() map[string]string {
	return map[string]string{
		"deploy/kustomization.yaml":           "resources:\n- manifests\n",
		"deploy/manifests/kustomization.yaml": "resources:\n- a.yaml\n- b.yaml\n",
		"deploy/manifests/a.yaml":             dvCRD(dvGroup, "Alpha", "d"),
		"deploy/manifests/b.yaml":             dvCRD(dvGroup, "Beta", "d"),
	}
}

func TestDeriveR3NeedsALiteralReferenceFromOutside(t *testing.T) {
	res := dvOK(t, dvR3Files, nil, nil)
	r := dvRules(t, res)
	if r.InstallPaths[0].Path != "deploy/manifests/" || res.Report.DerivedRules.Rule != "R3" || !strings.Contains(r.InstallPaths[0].Evidence, "R3") {
		t.Fatalf("R3 not chosen: %+v %+v", r.InstallPaths, res.Report.DerivedRules)
	}
	mut := func(f func(m map[string]string)) func() map[string]string {
		return func() map[string]string {
			m := dvR3Files()
			f(m)
			return m
		}
	}
	cases := map[string]func() map[string]string{
		"no reference at all": mut(func(m map[string]string) {
			delete(m, "deploy/kustomization.yaml")
			delete(m, "deploy/manifests/kustomization.yaml")
		}),
		"only the directory's own kustomization lists the files": mut(func(m map[string]string) {
			delete(m, "deploy/kustomization.yaml")
		}),
		"a file is not covered": mut(func(m map[string]string) {
			m["deploy/manifests/kustomization.yaml"] = "resources:\n- a.yaml\n"
		}),
		"the reference escapes the tree": mut(func(m map[string]string) {
			m["deploy/kustomization.yaml"] = "resources:\n- ../../../manifests\n"
		}),
		"the reference is templated": mut(func(m map[string]string) {
			m["deploy/kustomization.yaml"] = "resources:\n- ${DIR}/manifests\n"
		}),
		"the reference is remote": mut(func(m map[string]string) {
			m["deploy/kustomization.yaml"] = "resources:\n- https://example.test/x//deploy/manifests\n"
		}),
		"the referrer sits in a documentation directory": mut(func(m map[string]string) {
			delete(m, "deploy/kustomization.yaml")
			m["docs/kustomization.yaml"] = "resources:\n- ../deploy/manifests\n"
		}),
		"the referrer sits in a test directory": mut(func(m map[string]string) {
			delete(m, "deploy/kustomization.yaml")
			m["test/kustomization.yaml"] = "resources:\n- ../deploy/manifests\n"
		}),
		"a non-string entry makes the kustomization void": mut(func(m map[string]string) {
			m["deploy/kustomization.yaml"] = "resources:\n- manifests\n- {a: b}\n"
		}),
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			dvStop(t, f, nil, nil, StopInstallPathUnreferenced)
		})
	}
	// The reference must exist at EVERY tag that holds definitions.
	dvStop(t, dvR3Files, func(tag string, m *memTree) {
		if tag == "v1.2.0" {
			delete(m.files, "deploy/kustomization.yaml")
		}
	}, nil, StopInstallPathUnreferenced)
}

func TestDeriveR3NeverGuessesBetweenDirectories(t *testing.T) {
	// Two non-skipped directories that share their groups, no ranking: stop.
	files := func() map[string]string {
		m := dvR3Files()
		m["deploy/other/c.yaml"] = dvCRD(dvGroup, "Alpha", "d")
		return m
	}
	dvStop(t, files, nil, nil, StopInstallPathAmbiguous)
	// A directory present at some tags only (no range proof): ambiguous.
	dvStop(t, dvR3Files, func(tag string, m *memTree) {
		if tag == "v1.2.0" {
			for p, b := range m.files {
				if strings.HasPrefix(p, "deploy/manifests/") && !strings.HasSuffix(p, "kustomization.yaml") {
					delete(m.files, p)
					m.files[strings.Replace(p, "deploy/manifests/", "deploy/moved/", 1)] = b
				}
			}
			m.files["deploy/kustomization.yaml"] = []byte("resources:\n- moved\n")
			m.files["deploy/moved/kustomization.yaml"] = []byte("resources:\n- a.yaml\n- b.yaml\n")
		}
	}, nil, StopInstallPathAmbiguous)
	// A definition at the repository root is never an install directory.
	dvStop(t, func() map[string]string { return map[string]string{"crd.yaml": dvCRD(dvGroup, "Alpha", "d")} }, nil, nil, StopInstallPathAmbiguous)
	// Two candidates at one tag under R2.
	dvStop(t, func() map[string]string {
		m := dvBase()
		m["deploy/crds/c.yaml"] = dvCRD(dvGroup, "Gamma", "d")
		return m
	}, nil, nil, StopInstallPathAmbiguous)
}

// ---- scope-needs-owner (C5) ----

func TestDeriveScopeNeedsOwnerOverridesTheInstallRules(t *testing.T) {
	// An operator-shaped tree: two scopes with disjoint groups. R2 would pick
	// the config/crd directory; derive mode never auto-selects.
	files := func() map[string]string {
		m := dvBase()
		m["operator/config/crd/bases/x.yaml"] = dvCRD(dvForeign, "Gamma", "d")
		return m
	}
	se := dvStop(t, files, nil, nil, StopScopeNeedsOwner)
	if len(se.Proposals) != 1 {
		t.Fatalf("proposals %+v", se.Proposals)
	}
	p := se.Proposals[0]
	if p.Kind != ProposalScope || p.Status != "proposed" || len(p.Candidates) != 2 {
		t.Fatalf("proposal %+v", p)
	}
	for _, c := range p.Candidates {
		if len(c.Files) < 3 || c.Files[0].Blob == "" || len(c.Groups) != 1 {
			t.Fatalf("candidate %+v", c)
		}
	}
	// R3-shaped scopes too.
	dvStop(t, func() map[string]string {
		m := dvR3Files()
		m["tools/gen/x.yaml"] = dvCRD(dvForeign, "Gamma", "d")
		return m
	}, nil, nil, StopScopeNeedsOwner)
	// Equal group sets in two directories are copies, not scopes.
	dvOK(t, func() map[string]string {
		m := dvBase()
		m["charts/x/crds/all.yaml"] = dvCRD(dvGroup, "Alpha", "d") + "---\n" + dvCRD(dvGroup, "Beta", "d")
		return m
	}, nil, nil)
	// Component-prefixed tags are a scope too.
	tags := []string{"app-1.1.0", "app-1.2.0", "app-1.3.0"}
	in := dvInput(dvSource(tags, dvBase, nil), nil)
	in.Tags = tags
	_, err := Generate(in)
	se = wantStop(t, err, StopScopeNeedsOwner)
	if len(se.Proposals) != 1 || se.Proposals[0].TagPrefix != "app-" {
		t.Fatalf("prefix proposal %+v", se.Proposals)
	}
}

// ---- foreign-carrier exclusions (C2) and the install CRDs that are never excluded (C6) ----

func dvCarrier(path, group string) func() map[string]string {
	return func() map[string]string {
		m := dvBase()
		m[path] = dvCRD(group, "Gamma", "d")
		return m
	}
}

func TestDeriveForeignCarrierByOwnerListing(t *testing.T) {
	path := "third_party/dep/crds/x.yaml"
	res := dvOK(t, dvCarrier(path, dvForeign), nil, dvOwnedBy("other", dvForeign))
	r := dvRules(t, res)
	if len(r.Exclusions) != 1 || r.Exclusions[0].Path != path || r.Exclusions[0].Class != ClassExactFile {
		t.Fatalf("exclusions %+v", r.Exclusions)
	}
	ev := r.Exclusions[0].Evidence
	for _, tag := range ipTags {
		if !strings.Contains(ev, tag+" blob ") {
			t.Fatalf("evidence lacks tag %s: %s", tag, ev)
		}
	}
	if !strings.Contains(ev, "proof owner-listed other") || !strings.Contains(ev, "segment third_party") || !strings.Contains(ev, "groups "+dvForeign) {
		t.Fatalf("evidence: %s", ev)
	}
	if got := res.Report.DerivedRules.Loosening; len(got) != 1 || got[0].Path != path {
		t.Fatalf("loosening %+v", got)
	}
	if !strings.Contains(string(res.Changelog), "Loosening: 1 exclusion") {
		t.Fatal("changelog does not list the loosening")
	}
	// No proof: the group is unlisted (an own CRD that sits only in a skipped
	// directory is never taken for foreign).
	dvStop(t, dvCarrier(path, dvForeign), nil, nil, StopInstallPathHidesCRD)
	// A group listed by another project AND by this one is not a proof.
	dvStop(t, dvCarrier(path, dvForeign), nil, kindIndex(
		customresources.Project{Slug: "other", Groups: []customresources.Group{{Name: dvForeign}}},
		customresources.Project{Slug: "widgets", Groups: []customresources.Group{{Name: dvForeign}}},
	), StopInstallPathHidesCRD)
	// Listed for this project itself: not foreign.
	dvStop(t, dvCarrier(path, dvForeign), nil, dvOwnedBy("widgets", dvForeign), StopInstallPathHidesCRD)
}

func TestDeriveForeignCarrierByModuleOrigin(t *testing.T) {
	vendored := func() map[string]string {
		m := dvBase()
		m["vendor/example.org/dep/crd/x.yaml"] = dvCRD(dvForeign, "Gamma", "d")
		m["vendor/modules.txt"] = "# example.org/dep v1.0.0\n## explicit\nexample.org/dep\n"
		return m
	}
	res := dvOK(t, vendored, nil, nil)
	r := dvRules(t, res)
	if len(r.Exclusions) != 1 || !strings.Contains(r.Exclusions[0].Evidence, "proof module example.org/dep") || !strings.Contains(r.Exclusions[0].Evidence, "segment vendor") {
		t.Fatalf("exclusions %+v", r.Exclusions)
	}
	gomod := func() map[string]string {
		m := dvBase()
		m["third_party/dep/crd/x.yaml"] = dvCRD(dvForeign, "Gamma", "d")
		m["third_party/dep/go.mod"] = "module example.org/dep // comment\n\ngo 1.21\n"
		return m
	}
	if r := dvRules(t, dvOK(t, gomod, nil, nil)); len(r.Exclusions) != 1 || !strings.Contains(r.Exclusions[0].Evidence, "proof module example.org/dep") {
		t.Fatalf("go.mod proof: %+v", r.Exclusions)
	}
	// The module origin is the repository itself (or below it): no proof.
	for _, own := range []string{"github.com/example/widgets", "github.com/example/widgets/sub", "GitHub.com/Example/Widgets"} {
		f := func() map[string]string {
			m := vendored()
			m["vendor/modules.txt"] = "# " + own + " v1.0.0\n"
			m["vendor/"+own+"/crd/x.yaml"] = dvCRD(dvForeign, "Gamma", "d")
			delete(m, "vendor/example.org/dep/crd/x.yaml")
			return m
		}
		dvStop(t, f, nil, nil, StopInstallPathHidesCRD)
	}
	// An unparseable or unclean module path is no proof.
	dvStop(t, func() map[string]string {
		m := vendored()
		m["vendor/modules.txt"] = "# example.org/dep;rm v1.0.0\n"
		return m
	}, nil, nil, StopInstallPathHidesCRD)
	// A vendored file with no modules.txt line and no go.mod: no proof.
	dvStop(t, func() map[string]string {
		m := vendored()
		delete(m, "vendor/modules.txt")
		return m
	}, nil, nil, StopInstallPathHidesCRD)
}

func TestDeriveNeverExcludesInstallCRDs(t *testing.T) {
	vendoredOf := func(group, desc string) func() map[string]string {
		return func() map[string]string {
			m := dvBase()
			m["vendor/example.org/dep/crd/x.yaml"] = dvCRD(group, "Alpha", desc)
			m["vendor/modules.txt"] = "# example.org/dep v1.0.0\n"
			return m
		}
	}
	// A carrier with a PROVEN foreign origin that repeats an installed group
	// with different content: the group is installed, so no exclusion; the
	// copy check stops.
	dvStop(t, vendoredOf(dvGroup, "other"), nil, nil, StopInstallPathCopyDiffers)
	// The same with a group the install paths define and another project lists.
	dvStop(t, vendoredOf(dvGroup, "other"), nil, dvOwnedBy("other", dvGroup), StopGroupOwnedElsewhere)
	// An own CRD (no proof of foreign origin) under bundle*, olm and templates
	// is never excluded.
	for _, dir := range []string{"bundle/manifests", "bundle-v2/manifests", "olm/crds", "olm-catalog/x", "charts/x/templates"} {
		f := func() map[string]string {
			m := dvBase()
			m[dir+"/own.yaml"] = dvCRD(dvForeign, "Gamma", "d")
			return m
		}
		dvStop(t, f, nil, nil, StopInstallPathHidesCRD)
	}
	// A CRD referenced by an install surface that sits under a skipped
	// segment is the only definition: no install directory, nothing excluded.
	only := func() map[string]string {
		return map[string]string{
			"deploy/kustomization.yaml":        "resources:\n- bundle/crds.yaml\n",
			"deploy/bundle/crds.yaml":          dvCRD(dvGroup, "Alpha", "d"),
			"deploy/bundle/kustomization.yaml": "resources:\n- crds.yaml\n",
		}
	}
	dvStop(t, only, nil, nil, StopInstallPathAmbiguous)
	dvStop(t, only, nil, dvOwnedBy("other", dvGroup), StopInstallPathAmbiguous)
	// A group defined in a non-skipped carrier directory too: no exclusion.
	dvStop(t, func() map[string]string {
		m := dvBase()
		m["config/crd/bases/c.yaml"] = dvCRD(dvForeign, "Delta", "d")
		m["third_party/dep/crds/x.yaml"] = dvCRD(dvForeign, "Gamma", "d")
		return m
	}, nil, dvOwnedBy("other", dvForeign), StopGroupOwnedElsewhere)
}

func TestDeriveCarrierMustQualifyAtEveryTag(t *testing.T) {
	path := "third_party/dep/crds/x.yaml"
	idx := dvOwnedBy("other", dvForeign)
	// The carrier is unreadable at one older tag: it is never excluded at all.
	dvStop(t, dvCarrier(path, dvForeign), func(tag string, m *memTree) {
		if tag == "v1.1.0" {
			m.files[path] = []byte("apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nspec:\n  group: " + dvForeign + "\n")
		}
	}, idx, StopInstallPathHidesCRD)
	// The carrier changes its group at one tag to one nobody lists.
	dvStop(t, dvCarrier(path, dvForeign), func(tag string, m *memTree) {
		if tag == "v1.1.0" {
			m.files[path] = []byte(dvCRD("unlisted.example.test", "Gamma", "d"))
		}
	}, idx, StopInstallPathHidesCRD)
	// Reached through a link from an install-like location: never excluded.
	dvStop(t, dvCarrier(path, dvForeign), func(tag string, m *memTree) {
		m.links["config/crd/linked.yaml"] = "../../" + path
	}, idx, StopInstallPathHidesCRD)
	// Qualifies at every tag: one exclusion lists every tag.
	res := dvOK(t, dvCarrier(path, dvForeign), nil, idx)
	if n := strings.Count(res.Report.DerivedRules.Loosening[0].Evidence, " blob "); n != 3 {
		t.Fatalf("evidence enumerates %d tags, want 3", n)
	}
	// A carrier present only at older tags gets no rule (no matches-nothing stop).
	dvOK(t, dvBase0, func(tag string, m *memTree) {
		if tag == "v1.1.0" {
			m.files[path] = []byte(dvCRD(dvForeign, "Gamma", "d"))
		}
	}, idx)
}

// ---- withheld older tags (C7, review numbering) ----

func TestDeriveFromTagWithNoDefinitionsIsWithheld(t *testing.T) {
	strip := func(tag string, m *memTree) {
		if tag == "v1.1.0" {
			for p := range m.files {
				if strings.HasPrefix(p, "config/") {
					delete(m.files, p)
				}
			}
		}
	}
	res := dvOK(t, dvBase0, strip, nil)
	if len(res.Report.Dropped) != 1 || res.Report.Dropped[0].Tag != "v1.1.0" || len(res.Report.Tags) != 2 {
		t.Fatalf("dropped %+v tags %+v", res.Report.Dropped, res.Report.Tags)
	}
	if r := dvRules(t, res); len(r.InstallPaths) != 1 || r.InstallPaths[0].Optional || len(r.InstallPaths[0].AbsentTags) != 0 {
		t.Fatalf("derive mode never writes optional or absent-tag entries: %+v", r.InstallPaths)
	}
	in := dvInput(dvSource(ipTags, dvBase0, strip), nil)
	in.StrictWindow = true
	_, err := Generate(in)
	wantStop(t, err, StopWindowShortened)
	// No definitions at the newest tag, or a different directory at an older
	// tag, are stops.
	dvStop(t, dvBase0, func(tag string, m *memTree) {
		if tag == "v1.3.0" {
			strip("v1.1.0", m)
		}
	}, nil, StopInstallPathAmbiguous)
	dvStop(t, dvBase0, func(tag string, m *memTree) {
		if tag == "v1.1.0" {
			for p, b := range m.files {
				if strings.HasPrefix(p, "config/crd/bases/") {
					delete(m.files, p)
					m.files[strings.Replace(p, "config/crd/bases/", "config/crd/old/", 1)] = b
				}
			}
		}
	}, nil, StopInstallPathAmbiguous)
}

// ---- owner-record proposals ----

func TestDeriveProposalsForReservedAndSharedGroups(t *testing.T) {
	reserved := func() map[string]string {
		return map[string]string{"config/crd/bases/a.yaml": dvCRD("policy.networking.k8s.io", "Thing", "d"), "config/crd/bases/b.yaml": dvCRD(dvGroup, "Beta", "d")}
	}
	se := dvStop(t, reserved, nil, nil, StopReservedGroup)
	if len(se.Proposals) != 1 {
		t.Fatalf("proposals %+v", se.Proposals)
	}
	p := se.Proposals[0]
	if p.Kind != ProposalReservedGroup || p.Group != "policy.networking.k8s.io" || p.Slug != "widgets" || p.Repo != "https://github.com/example/widgets" || p.Status != "proposed" || p.InstallPathOrCopy != "install-path" || len(p.DefiningFilesAtTags) != 3 {
		t.Fatalf("proposal %+v", p)
	}
	// An owner record naming another slug or another repository spelling
	// never helps.
	rec := []customresources.ReservedGroup{{Name: "policy.networking.k8s.io", Owner: "other", Repository: "https://github.com/example/widgets"}}
	if ownsReserved(rec, "policy.networking.k8s.io", "widgets", "example/widgets") {
		t.Fatal("a record of another slug was accepted")
	}
	rec[0].Owner, rec[0].Repository = "widgets", "https://github.com/Example/Widgets"
	if ownsReserved(rec, "policy.networking.k8s.io", "widgets", "example/widgets") {
		t.Fatal("another repository spelling was accepted")
	}
	// A reserved group that only a carrier outside the install paths defines
	// needs no record and no proposal.
	res := dvOK(t, dvCarrier("third_party/dep/crds/x.yaml", "policy.networking.k8s.io"), nil, dvOwnedBy("other", "policy.networking.k8s.io"))
	if len(res.Proposals) != 0 {
		t.Fatalf("carrier proposals %+v", res.Proposals)
	}
	shared := dvStop(t, dvBase0, nil, dvOwnedBy("other", dvGroup), StopGroupOwnedElsewhere)
	if len(shared.Proposals) != 1 || shared.Proposals[0].Kind != ProposalSharedGroup || shared.Proposals[0].CarrierOf != "other" {
		t.Fatalf("shared proposals %+v", shared.Proposals)
	}
}

// ---- upstream text never reaches a derived text unescaped ----

func TestDeriveUpstreamTextIsAllowListed(t *testing.T) {
	idx := dvOwnedBy("other", dvForeign)
	bad := []string{"third_party/dep/crds/line\nbreak.yaml", "third_party/dep/crds/reason: x.yaml", "third_party/dep/crds/sp ace.yaml", "third_party/dep/crds/semi;colon.yaml", "third_party/dep/crds/é.yaml"}
	for _, p := range bad {
		res, err := dvRun(t, dvCarrier(p, dvForeign), nil, idx)
		if err == nil {
			t.Fatalf("%q: the file was excluded: %s", p, res.RulesJSON)
		}
		wantStop(t, err, StopInstallPathHidesCRD)
	}
	// A group name that is not plain: never a carrier.
	for _, g := range []string{"Gadgets.Example.Test", "gadgets.example.test reason: pwn", "gadgets_example.test"} {
		dvStop(t, dvCarrier("third_party/dep/crds/x.yaml", strconv.Quote(g)), nil, kindIndex(customresources.Project{Slug: "other", Groups: []customresources.Group{{Name: g}}}), StopInstallPathHidesCRD)
	}
	// An install directory outside the allow-list is a derive stop.
	dvStop(t, func() map[string]string {
		return map[string]string{"config/crd/my dir/a.yaml": dvCRD(dvGroup, "Alpha", "d")}
	}, nil, nil, StopDeriveUncleanText)
	// A scope candidate path outside the allow-list too.
	dvStop(t, func() map[string]string {
		m := dvBase()
		m["operator/config/crd/x y.yaml"] = dvCRD(dvForeign, "Gamma", "d")
		return m
	}, nil, nil, StopDeriveUncleanText)
	// Allowed texts: nothing in a derived file carries a control character.
	res := dvOK(t, dvCarrier("third_party/dep/crds/ok-1.yaml", dvForeign), nil, idx)
	for _, b := range [][]byte{res.RulesJSON, res.Changelog} {
		if !cleanText(strings.ReplaceAll(strings.ReplaceAll(string(b), "\n", ""), "\t", "")) {
			t.Fatal("control characters in derived text")
		}
	}
}

// ---- input refusals and the idempotence key ----

func TestDeriveRefusesMixedInputs(t *testing.T) {
	src := dvSource(ipTags, dvBase0, nil)
	mk := func(f func(in *Input)) error {
		in := dvInput(src, nil)
		f(&in)
		_, err := Generate(in)
		return err
	}
	for name, f := range map[string]func(in *Input){
		"rules":     func(in *Input) { in.Rules = ipRules(t, `[{"path":"config/crd/bases/","reason":"r","evidence":"e"}]`) },
		"infer":     func(in *Input) { in.InferInstallPaths = true },
		"range":     func(in *Input) { in.RangeCheckTags = []string{"v1.1.0"} },
		"multi":     func(in *Input) { in.MultiPrefix = true },
		"community": nil,
	} {
		if f == nil {
			err := mk(func(in *Input) { in.Catalog = "community" })
			wantStop(t, err, StopCommunityUpstream)
			continue
		}
		t.Run(name, func(t *testing.T) { wantStop(t, mk(f), StopBadInput) })
	}
	// A rules file that only carries an exclusion is a hand rule as well.
	r, err := ParseRules([]byte(`{"schema":"prufyx.io/target-draft-rules/v1","installSurface":[],"exclusions":[{"class":"exact-file","path":"x/y.yaml","reason":"r","evidence":"e"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	wantStop(t, mk(func(in *Input) { in.Rules = r }), StopBadInput)
}

type commitOverride struct {
	Source
	commits map[string]string
}

func (c commitOverride) Open(tag string) (Tree, string, error) {
	t, cm, err := c.Source.Open(tag)
	if v, ok := c.commits[tag]; ok {
		cm = v
	}
	return t, cm, err
}

func TestDeriveKeyCoversTagsCommitsAndFlags(t *testing.T) {
	src := dvSource(ipTags, dvBase0, nil)
	in := dvInput(src, nil)
	k1, err := DeriveKey(in)
	if err != nil {
		t.Fatal(err)
	}
	if k2, _ := DeriveKey(in); k1 != k2 || !strings.HasPrefix(k1, "sha256:") {
		t.Fatalf("key not stable: %s %s", k1, k2)
	}
	res, err := Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	if res.Report.DerivedRules.Key != k1 {
		t.Fatal("the report key is not the pre-run key")
	}
	moved := in
	moved.Source = commitOverride{src, map[string]string{"v1.2.0": strings.Repeat("a", 40)}}
	if km, _ := DeriveKey(moved); km == k1 {
		t.Fatal("a force-moved tag does not change the key")
	}
	strict := in
	strict.StrictWindow = true
	if ks, _ := DeriveKey(strict); ks == k1 {
		t.Fatal("the strict flag does not change the key")
	}
	fewer := in
	fewer.Tags = ipTags[1:]
	if kf, _ := DeriveKey(fewer); kf == k1 {
		t.Fatal("the tag set does not change the key")
	}
	other := in
	other.Slug = "gizmos"
	if ko, _ := DeriveKey(other); ko == k1 {
		t.Fatal("the slug does not change the key")
	}
	// The tables digest moves with every table and text it names.
	d0 := deriveTablesDigest()
	inferSkipExact["zz-test-segment"] = true
	d1 := deriveTablesDigest()
	delete(inferSkipExact, "zz-test-segment")
	if d0 == d1 || d0 != deriveTablesDigest() {
		t.Fatal("the tables digest does not cover the skipped-segment table")
	}
}

// ---- command line ----

func TestDeriveCLI(t *testing.T) {
	src := dvSource(ipTags, dvCarrier("third_party/dep/crds/x.yaml", dvForeign), nil)
	open := func(string) Source { return src }
	args := func(out string, extra ...string) []string {
		return append([]string{"generate", "--dir", "x", "--slug", "widgets", "--name", "Widgets", "--repo", "github.com/example/widgets", "--tags", strings.Join(ipTags, ","), "--out", out}, extra...)
	}
	var so, se bytes.Buffer
	if code := run(args(filepath.Join(t.TempDir(), "o"), "--derive-rules", "--rules", "x.json"), &so, &se, open); code != 2 {
		t.Fatalf("--rules with --derive-rules: exit %d", code)
	}
	if code := run(args(filepath.Join(t.TempDir(), "o"), "--emit-proposals", filepath.Join(t.TempDir(), "p.json")), &so, &se, open); code != 2 {
		t.Fatalf("--emit-proposals without --derive-rules: exit %d", code)
	}
	// With the default ownership index the foreign group has no proof: stop,
	// proposals file written (empty), no draft.
	out := filepath.Join(t.TempDir(), "o")
	prop := filepath.Join(t.TempDir(), "p.json")
	so.Reset()
	if code := run(args(out, "--derive-rules", "--emit-proposals", prop), &so, &se, open); code != 1 {
		t.Fatalf("exit %d: %s %s", code, so.String(), se.String())
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("a stop wrote a draft")
	}
	raw, err := os.ReadFile(prop)
	if err != nil {
		t.Fatal(err)
	}
	var doc ProposalsDoc
	if err := json.Unmarshal(raw, &doc); err != nil || doc.Schema != ProposalsSchema || !doc.Stopped || doc.Slug != "widgets" {
		t.Fatalf("proposals doc: %v %s", err, raw)
	}
	// A success writes rules.json next to the draft, byte-equal to the result.
	src2 := dvSource(ipTags, dvBase0, nil)
	out2 := filepath.Join(t.TempDir(), "o2")
	prop2 := filepath.Join(t.TempDir(), "p2.json")
	so.Reset()
	if code := run(args(out2, "--derive-rules", "--emit-proposals", prop2), &so, &se, func(string) Source { return src2 }); code != 0 {
		t.Fatalf("exit %d: %s %s", code, so.String(), se.String())
	}
	rules, err := os.ReadFile(filepath.Join(out2, "rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRules(rules); err != nil {
		t.Fatal(err)
	}
	var ok ProposalsDoc
	raw, _ = os.ReadFile(prop2)
	if err := json.Unmarshal(raw, &ok); err != nil || ok.Stopped || ok.RulesDigest != sumHex(rules) {
		t.Fatalf("proposals doc %v %s", err, raw)
	}
}
