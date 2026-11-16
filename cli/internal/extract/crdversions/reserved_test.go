// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/extract"
)

// reservedScan runs a quiet pair whose listed paths hold def (a definition
// in the table's group of the synthetic target) with files next to them at
// both releases, the index listing owned groups for the target, and returns
// the later release's scan.
func reservedScan(t *testing.T, listed string, owned []string, files map[string]string, exclude ...Exclusion) *ScanRecord {
	t.Helper()
	f := map[string]string{"deploy/crds/a.yaml": listed}
	for p, c := range files {
		f[p] = c
	}
	s := newSynth(release{"v1.0.0", f}, release{"v1.1.0", f})
	tg := synthTarget(exclude...)
	repo, err := extract.ParseRepo(tg.Repo)
	must(t, err)
	out, err := extract.Run(context.Background(), New(tg).WithIndex(syntheticOwnership(tg, owned...)), ReleaseTags(New(tg), s), s, extract.Options{Repo: repo, DerivedAt: derivedAt})
	if err != nil {
		t.Fatal(err)
	}
	_, proof := pairOf(t, out, "1.0.0", "1.1.0")
	if proof.To == nil || proof.To.Scan == nil {
		t.Fatal("no scan")
	}
	return proof.To.Scan
}

func quietListed() string { return crd("Alpha", "v1beta1", "v1") }

// Documentation names and unowned reserved-namespace groups under a
// default-excluded directory are left out and recorded; the file is a copy.
func TestReservedLeftOutUnderDefaultDirectory(t *testing.T) {
	for _, group := range []string{"hello.example.com", "stable.example.com", "example.org", "a.example.net", "foo.test", "example.k8s.io", "populator.storage.k8s.io", "a.x-k8s.io", "a.kubernetes.io"} {
		t.Run(group, func(t *testing.T) {
			const path = "test/e2e/fixture.yaml"
			file := crdIn(group, "Dummy", "v1")
			scan := reservedScan(t, quietListed(), []string{synthGroup}, map[string]string{path: file})
			if !slices.Contains(scan.Copies, path) || findingOf(scan, path) != nil {
				t.Fatalf("not left out: copies %v findings %+v", scan.Copies, scan.Findings)
			}
			var rc *ReservedCopy
			for i := range scan.ReservedCopies {
				if scan.ReservedCopies[i].Path == path {
					rc = &scan.ReservedCopies[i]
				}
			}
			if rc == nil || rc.SHA256 == "" || !slices.Equal(rc.Definitions, []string{"dummys." + group}) {
				t.Fatalf("reserved record: %+v", scan.ReservedCopies)
			}
			if len(scan.ForeignCopies) != 0 {
				t.Fatalf("foreign records: %+v", scan.ForeignCopies)
			}
			if r := copyRecordOf(scan, path); r == nil || r.Reason != "v1-reserved-only" || len(r.Definitions) != 0 {
				t.Fatalf("copy record: %+v", r)
			}
			if !scan.Clean() {
				t.Fatalf("scan blocks: %+v", scan.Findings)
			}
		})
	}
}

// (1) the open tree is unchanged.
func TestReservedOpenTreeStaysExtra(t *testing.T) {
	const path = "pkg/other/fixture.yaml"
	scan := reservedScan(t, quietListed(), []string{synthGroup}, map[string]string{path: crdIn("hello.example.com", "Dummy", "v1")})
	if f := findingOf(scan, path); f == nil || f.Class != ClassExtra || len(scan.ReservedCopies) != 0 || scan.Clean() {
		t.Fatalf("finding %+v, scan %+v", f, scan)
	}
}

// (2) a void entry keeps today's behaviour; a reviewed entry too.
func TestReservedVoidAndReviewedStayAsToday(t *testing.T) {
	file := crdIn("hello.example.com", "Dummy", "v1")
	_, proof := guardPair(t, map[string]string{
		"deploy/kustomization.yaml": "resources:\n- ../test/fixtures/crd.yaml\n",
		fixtureDir + "crd.yaml":     file,
	}, fixtureExclusion())
	f := findingOf(proof.To.Scan, fixtureDir+"crd.yaml")
	if f == nil || f.Class != ClassExtra || f.Location != "void: "+fixtureDir || len(proof.To.Scan.ReservedCopies) != 0 || proof.Completeness.Attestable {
		t.Fatalf("void: finding %+v", f)
	}
	scan := reservedScan(t, quietListed(), []string{synthGroup}, map[string]string{fixtureDir + "crd.yaml": file}, fixtureExclusion())
	if f := findingOf(scan, fixtureDir+"crd.yaml"); f == nil || f.Class != ClassExcluded || len(scan.ReservedCopies) != 0 {
		t.Fatalf("reviewed: finding %+v", f)
	}
}

// (3) one reserved and one own or unattributed definition: the file is extra.
func TestReservedMixedFileStaysExtra(t *testing.T) {
	const path = "test/e2e/mixed.yaml"
	for name, other := range map[string]string{"own group": crd("Gamma", "v1"), "unattributed": crdIn("unowned.example.io", "Gamma", "v1")} {
		t.Run(name, func(t *testing.T) {
			scan := reservedScan(t, quietListed(), []string{synthGroup}, map[string]string{path: crdIn("hello.example.com", "Dummy", "v1") + "---\n" + other})
			f := findingOf(scan, path)
			if f == nil || f.Class != ClassExtra || scan.Clean() {
				t.Fatalf("finding %+v", f)
			}
			if slices.Contains(f.CRDs, "dummys.hello.example.com") {
				t.Fatalf("left-out definition is named as extra: %+v", f.CRDs)
			}
		})
	}
}

// (4) a target whose inventory defines the group keeps the file extra.
func TestReservedOffWhenInventoryDefinesGroup(t *testing.T) {
	const path = "test/e2e/fixture.yaml"
	for _, group := range []string{"hello.example.com", "own.k8s.io"} {
		listed := crdIn(group, "Alpha", "v1")
		scan := reservedScan(t, listed, nil, map[string]string{path: crdIn(group, "Dummy", "v1")})
		if f := findingOf(scan, path); f == nil || f.Class != ClassExtra || len(scan.ReservedCopies) != 0 {
			t.Fatalf("%s: finding %+v", group, f)
		}
	}
}

// (5) names that only look reserved stay extra.
func TestReservedLookAlikesStayExtra(t *testing.T) {
	const path = "test/e2e/fixture.yaml"
	for _, group := range []string{"example.io", "my.domain", "exampleXcom", "example.com.evil.io", "xexample.com", "k8s.io.evil.io", "notk8s.io", "argoproj.io"} {
		scan := reservedScan(t, quietListed(), []string{synthGroup}, map[string]string{path: crdIn(group, "Dummy", "v1")})
		// exampleXcom is not even a valid API group: the file is unread.
		if f := findingOf(scan, path); f == nil || !f.blocks() || (f.Class != ClassExtra && group != "exampleXcom") || len(scan.ReservedCopies) != 0 || scan.Clean() {
			t.Errorf("%s: finding %+v", group, f)
		}
	}
}

// (6) a reserved-namespace group the table gives to the target is compared,
// not left out; one another project owns is foreign as before.
func TestReservedGroupOfTargetIsCompared(t *testing.T) {
	const path = "test/e2e/fixture.yaml"
	scan := reservedScan(t, quietListed(), []string{synthGroup, "mine.x-k8s.io"}, map[string]string{path: crdIn("mine.x-k8s.io", "Dummy", "v1")})
	if f := findingOf(scan, path); f == nil || f.Class != ClassExtra || len(scan.ReservedCopies) != 0 {
		t.Fatalf("finding %+v", f)
	}
	// A group listed by two projects is ambiguous: kept.
	tg := synthTarget()
	ps := customresources.Projects()
	ps = append(ps, customresources.Project{Slug: "zz1", Groups: []customresources.Group{{Name: "shared.x-k8s.io"}}}, customresources.Project{Slug: "zz2", Groups: []customresources.Group{{Name: "shared.x-k8s.io"}}})
	ix := customresources.NewIndex(ps)
	inv := &Inventory{Complete: true}
	if ReservedLeftOut(ix, tg.Project, inv, "shared.x-k8s.io", "Dummy") {
		t.Fatal("an ambiguous group is left out")
	}
	// Another project's group is not "reserved": it is foreign.
	ps = customresources.Projects()
	ps = append(ps, customresources.Project{Slug: "zz1", Groups: []customresources.Group{{Name: "other.x-k8s.io"}}})
	scan = reservedScan(t, quietListed(), []string{synthGroup}, nil)
	_ = scan
	if !ReservedLeftOut(customresources.NewIndex(ps), tg.Project, inv, "other.x-k8s.io", "Dummy") {
		t.Fatal("a group of another project is not left out by the predicate")
	}
}

// (7) templated, undecodable and legacy files under a default directory are
// not read as reserved: they stay unread or as today.
func TestReservedUnreadStaysBlocking(t *testing.T) {
	const path = "test/e2e/fixture.yaml"
	good := crdIn("hello.example.com", "Dummy", "v1")
	cases := map[string]string{
		"templated":      metallbTemplate(good),
		"undecodable":    "kind: CustomResourceDefinition\nspec: [\n",
		"embedded":       "data: |\n  apiVersion: apiextensions.k8s.io/v1\n  kind: CustomResourceDefinition\n",
		"template tag":   "{{ if .Values.x }}\n" + good + "{{ end }}\n",
		"legacy v1beta1": strings.ReplaceAll(legacyCRD("Dummy", "v1beta1"), synthGroup, "hello.example.com"),
	}
	for name, file := range cases {
		t.Run(name, func(t *testing.T) {
			scan := reservedScan(t, quietListed(), []string{synthGroup}, map[string]string{path: file})
			if len(scan.ReservedCopies) != 0 {
				t.Fatalf("reserved record: %+v", scan.ReservedCopies)
			}
			if f := findingOf(scan, path); f == nil || !f.blocks() {
				t.Fatalf("does not block: finding %+v, copies %v", f, scan.Copies)
			}
		})
	}
}

// (9) the scan and the exported predicate agree on one corpus.
func TestReservedScanAgreesWithPredicate(t *testing.T) {
	const path = "test/e2e/fixture.yaml"
	tg := synthTarget()
	ix := syntheticOwnership(tg, synthGroup)
	inv := &Inventory{Complete: true, CRDs: []CRD{{Group: synthGroup, Kind: "Alpha"}}}
	for _, group := range []string{"hello.example.com", "example.org", "foo.test", "foo.localhost", "a.invalid", "example.k8s.io", "a.x-k8s.io", "example.io", "my.domain", "exampleXcom", "example.com.evil.io", "argoproj.io", synthGroup} {
		want := ReservedLeftOut(ix, tg.Project, inv, group, "Dummy")
		scan := reservedScan(t, quietListed(), []string{synthGroup}, map[string]string{path: crdIn(group, "Dummy", "v1")})
		got := len(scan.ReservedCopies) == 1 && scan.ReservedCopies[0].Path == path
		if got != want {
			t.Errorf("%s: scan leaves out %v, predicate %v", group, got, want)
		}
	}
	// Fail closed on missing or incomplete inventory, empty project or group.
	for name, c := range map[string]struct {
		inv     *Inventory
		project string
		group   string
	}{
		"no inventory": {nil, tg.Project, "a.example.com"}, "incomplete": {&Inventory{}, tg.Project, "a.example.com"},
		"no project": {inv, "", "a.example.com"}, "no group": {inv, tg.Project, ""},
	} {
		if ReservedLeftOut(ix, c.project, c.inv, c.group, "Dummy") {
			t.Errorf("%s: left out", name)
		}
	}
}

// (10) own-group fixtures and externals stay typed stops.
func TestReservedOwnGroupFixtureAndExternalStayBlocking(t *testing.T) {
	const path = "test/e2e/testdata/dummy.yaml"
	// argo-cd owns argoproj.io by kind; a kind outside the row is unattributed.
	dummy := strings.ReplaceAll(crdIn("argoproj.io", "Dummy", "v1"), "dummys.argoproj.io", "dummys.argoproj.io")
	scan := reservedScan(t, quietListed(), []string{synthGroup}, map[string]string{path: dummy})
	if f := findingOf(scan, path); f == nil || f.Class != ClassExtra || len(scan.ReservedCopies) != 0 || scan.Clean() {
		t.Fatalf("own group: finding %+v", f)
	}
	chart := "apiVersion: v2\nname: app\nversion: 1.0.0\ndependencies:\n- name: crds\n  version: 1.0.0\n  repository: https://charts.example.com/\n"
	scan = reservedScan(t, quietListed(), []string{synthGroup}, map[string]string{"test/e2e/chart/Chart.yaml": chart})
	if f := findingOf(scan, "test/e2e/chart/Chart.yaml"); f == nil || f.Class != ClassExternal || !f.blocks() || scan.Clean() {
		t.Fatalf("external: finding %+v", f)
	}
}

// The facts' shape: openkruise vendor e2e CRDs and argo-cd example fixtures
// no longer block, argoproj.io fixtures and example.io still do.
func TestReservedFactsShape(t *testing.T) {
	files := map[string]string{
		"vendor/k8s.io/kubernetes/test/e2e/testing-manifests/hello.yaml":     crdIn("hello.example.com", "Hello", "v1"),
		"vendor/k8s.io/kubernetes/test/e2e/testing-manifests/populator.yaml": crdIn("populator.storage.k8s.io", "VolumePopulator", "v1beta1"),
		"test/e2e/testdata/stable.yaml":                                      crdIn("stable.example.com", "CronTab", "v1"),
		"test/e2e/testdata/example-k8s.yaml":                                 crdIn("example.k8s.io", "Example", "v1"),
	}
	scan := reservedScan(t, quietListed(), []string{synthGroup}, files)
	if !scan.Clean() || len(scan.ReservedCopies) != len(files) {
		t.Fatalf("blocks: %+v / %+v", scan.Findings, scan.ReservedCopies)
	}
	blockers := map[string]string{
		"test/e2e/testdata/workflow.yaml": crdIn("argoproj.io", "Workflow", "v1"),
		"test/e2e/testdata/example.yaml":  crdIn("example.io", "Thing", "v1"),
	}
	scan = reservedScan(t, quietListed(), []string{synthGroup}, blockers)
	for p := range blockers {
		if f := findingOf(scan, p); f == nil || f.Class != ClassExtra {
			t.Errorf("%s: finding %+v", p, f)
		}
	}
}

// (25) The rule only relaxes extra findings. For every combination of
// definitions, groups and inventories: an old copy stays identical, an old
// conflict stays a conflict (it names an inventory definition, whose group
// the rule never leaves out), and an old extra stays blocking unless every
// remaining definition is left out by the predicate. So a pair that attests
// today derives the same candidates and attestation.
func TestReservedOnlyRelaxesExtra(t *testing.T) {
	tg := synthTarget()
	ix := syntheticOwnership(tg, synthGroup, "mine.x-k8s.io")
	v1 := []CRDVersion{{Name: "v1", Served: true}}
	v2 := []CRDVersion{{Name: "v2", Served: true}}
	inv := &Inventory{Complete: true, CRDs: []CRD{
		{Name: "alphas." + synthGroup, Group: synthGroup, Kind: "Alpha", Versions: v1},
		{Name: "owns.example.com", Group: "example.com", Kind: "Own", Versions: v1},
	}}
	groups := []string{synthGroup, "example.com", "hello.example.com", "example.io", "example.k8s.io", "mine.x-k8s.io", "a.x-k8s.io", "argoproj.io", "foo.test"}
	var defs []CRD
	for _, g := range groups {
		for _, k := range []string{"Alpha", "Own", "Dummy"} {
			for _, v := range [][]CRDVersion{v1, v2} {
				defs = append(defs, CRD{Name: strings.ToLower(k) + "s." + g, Group: g, Kind: k, Versions: v})
			}
		}
	}
	at := attribution{project: tg.Project, index: ix}
	var sawConflict, sawRelaxed bool
	check := func(crds []CRD) {
		old := compareDefinitions(Finding{}, crds, inv, at, false)
		now := compareDefinitions(Finding{}, crds, inv, at, true)
		switch old.Class {
		case ClassCopy:
			if !reflect.DeepEqual(old, now) {
				t.Errorf("%v: copy changed: old %+v, new %+v", crds, old, now)
			}
			return
		case ClassConflict:
			sawConflict = true
			if now.Class != ClassConflict {
				t.Errorf("%v: conflict became %s", crds, now.Class)
			}
		}
		left := map[string]bool{}
		for _, name := range now.Reserved {
			for _, c := range crds {
				if c.Name == name {
					left[name] = true
					if !ReservedLeftOut(ix, tg.Project, inv, c.Group, c.Kind) || slices.Contains(targetGroups(inv), c.Group) {
						t.Errorf("%s left out against the predicate", name)
					}
				}
			}
		}
		rest := 0
		for _, c := range crds {
			if left[c.Name] || at.foreign(c.Group, c.Kind) {
				continue
			}
			// A definition the inventory holds with the same serving is a
			// copy and does not block by itself.
			same := false
			for i := range inv.CRDs {
				same = same || (inv.CRDs[i].Name == c.Name && sameServing(&inv.CRDs[i], &c))
			}
			if !same {
				rest++
			}
		}
		if rest > 0 && now.Class != ClassExtra && now.Class != ClassConflict {
			t.Errorf("%v: blocking became %s", crds, now.Class)
		}
		if rest == 0 && now.Class == ClassCopy {
			sawRelaxed = true
		}
	}
	for _, a := range defs {
		check([]CRD{a})
		for _, b := range defs {
			check([]CRD{a, b})
		}
	}
	if !sawConflict || !sawRelaxed {
		t.Fatalf("corpus lacks a case: conflict %v, relaxed extra %v", sawConflict, sawRelaxed)
	}
	if old := compareDefinitions(Finding{}, nil, nil, at, true); old.Class != ClassCopy {
		t.Fatalf("no definitions: %+v", old)
	}
	// Without a complete inventory nothing is left out.
	for _, bad := range []*Inventory{nil, {}} {
		if f := compareDefinitions(Finding{}, defs[:1:1], bad, at, true); len(f.Reserved) != 0 {
			t.Fatalf("left out without an inventory: %+v", f)
		}
	}
}

// (7) a gzip-compressed definition of a reserved group in a Go source is
// compared as before: Go sources are read only in the open tree or under a
// void entry, and there it stays an extra finding (never left out).
func TestReservedGzipStaysBlocking(t *testing.T) {
	const path = fixtureDir + "crds.go"
	file := goCRDs(gzipLiteral(t, crdIn("hello.example.com", "Dummy", "v1")))
	_, proof := guardPair(t, map[string]string{
		"deploy/kustomization.yaml": "resources:\n- ../test/fixtures/crds.go\n",
		path:                        file,
		fixtureDir + "crd.yaml":     crd("Gamma", "v1"),
	}, fixtureExclusion())
	scan := proof.To.Scan
	if len(scan.ReservedCopies) != 0 {
		t.Fatalf("reserved record: %+v", scan.ReservedCopies)
	}
	if f := findingOf(scan, path); f == nil || !f.blocks() || f.Location != "void: "+fixtureDir {
		t.Fatalf("does not block: finding %+v, copies %v", f, scan.Copies)
	}
}
