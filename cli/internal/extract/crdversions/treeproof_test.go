// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// treeTarget is a synthetic attesting target that reads deploy/crds.
func treeTarget(attest bool) Target {
	tg := synthTarget()
	tg.Project, tg.Name, tg.Repo = "synth-proj", "Synth", "github.com/synth/proj"
	tg.Component, tg.FactProject, tg.Attest = "pkg:github/synth/proj", "synth_proj", attest
	return tg
}

// treeLinkRepo marks the listed paths as symbolic links.
type treeLinkRepo struct {
	synthRepo
	links map[string]bool
}

func (l treeLinkRepo) List(r extract.RepoRef, c, d string) ([]extract.TreeEntry, error) {
	es, err := l.synthRepo.List(r, c, d)
	for i := range es {
		if l.links[es[i].Path] {
			es[i].Mode = "120000"
		}
	}
	return es, err
}

func (l treeLinkRepo) Read(r extract.RepoRef, c, p string) ([]byte, error) {
	if l.links[p] {
		return nil, os.ErrInvalid
	}
	return l.synthRepo.Read(r, c, p)
}

type treeRun struct {
	tg     Target
	derive bool
	links  map[string]bool
}

func (tr treeRun) run(t *testing.T, from, to map[string]string) (extract.PairRecord, PairProof, *extract.Output) {
	t.Helper()
	s := newSynth(release{"v1.0.0", from}, release{"v1.1.0", to})
	var src extract.PinnedReader = s
	if len(tr.links) > 0 {
		src = treeLinkRepo{s, tr.links}
	}
	repo, err := extract.ParseRepo(tr.tg.Repo)
	must(t, err)
	x := New(tr.tg).WithIndex(syntheticOwnership(tr.tg, synthGroup))
	if tr.derive {
		x = x.WithDerivedTrees()
	}
	out, err := extract.Run(context.Background(), x, ReleaseTags(x, s), src, extract.Options{Repo: repo, DerivedAt: derivedAt})
	must(t, err)
	p, proof := pairOf(t, out, "1.0.0", "1.1.0")
	return p, proof, out
}

// both builds the two releases' trees from one extra set.
func both(extra map[string]string) (map[string]string, map[string]string) {
	from := map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}
	to := map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}
	for p, c := range extra {
		from[p], to[p] = c, c
	}
	return from, to
}

func attestable(p PairProof) bool { return p.Completeness != nil && p.Completeness.Attestable }

func verdictOf(proof PairProof, root string) *TreeVerdict {
	var scans []*ScanRecord
	if proof.To != nil {
		scans = append(scans, proof.To.Scan)
	}
	if proof.From != nil {
		scans = append(scans, proof.From.Scan)
	}
	for _, sc := range scans {
		if sc == nil {
			continue
		}
		for i := range sc.TreeVerdicts {
			if sc.TreeVerdicts[i].Root == root {
				return &sc.TreeVerdicts[i]
			}
		}
	}
	return nil
}

const fixtureCRD = "crd.yaml"

// A tree that nothing reaches is cleared with proof; without the option, on
// a target that does not attest, and at an incomplete scan it is not.
func TestTreeProofClears(t *testing.T) {
	for _, tc := range []struct {
		name, file, root, class string
	}{
		{"test tree", "test/e2e/testdata/" + fixtureCRD, "test", TreeClassTest},
		{"testdata tree", "pkg/x/testdata/" + fixtureCRD, "pkg/x/testdata", TreeClassTest},
		{"example tree", "docs/examples/" + fixtureCRD, "docs/examples", TreeClassExample},
	} {
		t.Run(tc.name, func(t *testing.T) {
			from, to := both(map[string]string{tc.file: crd("Gamma", "v1")})
			_, off, _ := treeRun{tg: treeTarget(true)}.run(t, from, to)
			if attestable(off) || off.To.Scan.Clean() {
				t.Fatal("without the option the fixture CRD must keep blocking")
			}
			if len(off.To.Scan.TreeVerdicts) != 0 {
				t.Fatal("no verdicts without the option")
			}
			_, off2, _ := treeRun{tg: treeTarget(false), derive: true}.run(t, from, to)
			if off2.To.Scan.Clean() || len(off2.To.Scan.TreeVerdicts) != 0 {
				t.Fatal("a target that does not attest never derives")
			}
			_, on, _ := treeRun{tg: treeTarget(true), derive: true}.run(t, from, to)
			if !attestable(on) || !on.To.Scan.Clean() || !on.From.Scan.Clean() {
				t.Fatalf("not cleared: %+v", on.Completeness)
			}
			v := verdictOf(on, tc.root)
			if v == nil || v.Verdict != TreeCleared || v.Class != tc.class || v.Reason != TreeReasonProven || v.Count != 1 || len(v.Files) != 1 || v.Files[0].OID == "" || v.CheckedDigest == "" {
				t.Fatalf("verdict %+v", v)
			}
			found := false
			for _, f := range on.To.Scan.Findings {
				if f.Path == tc.file {
					found = true
					if f.blocks() || !strings.HasPrefix(f.Location, derivedPrefix+tc.class+" "+tc.root+"/") {
						t.Fatalf("finding %+v", f)
					}
				}
			}
			if !found {
				t.Fatal("the cleared file is still recorded")
			}
			// Deterministic.
			_, again, _ := treeRun{tg: treeTarget(true), derive: true}.run(t, from, to)
			a, _ := json.Marshal(on)
			b, _ := json.Marshal(again)
			if !bytes.Equal(a, b) {
				t.Fatal("the proof differs between runs")
			}
		})
	}
}

// Everything below must leave the tree UNKNOWN: the pair stays blocked and
// the verdict names the reason.
func TestTreeProofRefuses(t *testing.T) {
	fix := map[string]string{"test/data/" + fixtureCRD: crd("Gamma", "v1")}
	with := func(extra map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range fix {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	cases := []struct {
		name   string
		extra  map[string]string
		links  map[string]bool
		root   string
		reason string
	}{
		{name: "kustomization lists the tree", extra: map[string]string{"deploy/kustomization.yaml": "resources:\n- ../test/data/crd.yaml\n"}, reason: TreeReasonSurfaceReference},
		{name: "chart above the tree", extra: map[string]string{"Chart.yaml": "name: x\nversion: 1.0.0\n"}, reason: TreeReasonSurfaceReference},
		{name: "install target applies the tree", extra: map[string]string{"Makefile": "install:\n\tkubectl apply -f test/data/crd.yaml\n"}, reason: TreeReasonSurfaceReference},
		{name: "embedded by a non-test package", extra: map[string]string{"pkg/e.go": "package e\n\n//go:embed ../../test/data/crd.yaml\nvar x string\n"}, reason: ""},
		{name: "workflow names the tree", extra: map[string]string{".github/workflows/ci.yaml": "run: kubectl apply -f ./test/data/\n"}, reason: TreeReasonUnreadSurface},
		{name: "workflow builds a path from variables", extra: map[string]string{".github/workflows/ci.yaml": "run: cp ${{ env.A }}/${{ env.B }} /tmp\n"}, reason: TreeReasonUnreadSurface},
		{name: "script in another language", extra: map[string]string{"hack/apply.py": "import os\nos.system('kubectl apply -f test/data')\n"}, reason: TreeReasonUnreadSurface},
		{name: "wildcard path", extra: map[string]string{"hack/run.rb": "Dir.glob('test/*/x.yaml')\n"}, reason: TreeReasonUnreadSurface},
		{name: "path of wildcards only", extra: map[string]string{"hack/run.rb": "Dir.glob('*/*.yaml')\n"}, reason: TreeReasonUnreadSurface},
		{name: "task runner", extra: map[string]string{"Taskfile.yml": "tasks:\n  a:\n    cmds:\n      - kubectl apply -f test/data\n"}, reason: TreeReasonUnreadSurface},
		{name: "go joins the path", extra: map[string]string{"cmd/main.go": "package main\n\nfunc f() { _ = filepath.Join(\"test\", \"data\") }\n"}, reason: TreeReasonUnreadSurface},
		{name: "go opens a segment", extra: map[string]string{"cmd/main.go": "package main\n\nfunc f() { _, _ = os.ReadDir(\"test\") }\n"}, reason: TreeReasonUnreadSurface},
		{name: "build copies the context", extra: map[string]string{"Dockerfile": "FROM scratch\nCOPY . /src\n"}, reason: TreeReasonContextCopy},
		{name: "symbolic link in the tree", extra: map[string]string{"test/data/link.yaml": "x"}, links: map[string]bool{"test/data/link.yaml": true}, reason: TreeReasonSymlink},
		{name: "symbolic link named like an install file", extra: map[string]string{"other/kustomization.yaml": "x"}, links: map[string]bool{"other/kustomization.yaml": true}, reason: TreeReasonSymlink},
		{name: "symbolic link on a listed path", extra: map[string]string{"deploy/crds/b.yaml": "x"}, links: map[string]bool{"deploy/crds/b.yaml": true}, reason: ""},
		{name: "external source inside the tree", extra: map[string]string{"test/data/kustomization.yaml": "resources:\n- https://example.com/r/x?ref=v1\n"}, reason: TreeReasonOtherFinding},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			from, to := both(with(tc.extra))
			_, proof, _ := treeRun{tg: treeTarget(true), derive: true, links: tc.links}.run(t, from, to)
			if attestable(proof) || (proof.To != nil && proof.To.Scan.Clean()) {
				t.Fatalf("the tree was cleared")
			}
			v := verdictOf(proof, "test")
			if tc.reason == "" {
				if v != nil && v.Verdict == TreeCleared {
					t.Fatalf("cleared: %+v", v)
				}
				return
			}
			if v == nil || v.Verdict != TreeUnknown || v.Reason != tc.reason {
				t.Fatalf("verdict %+v, want %s", v, tc.reason)
			}
			if proof.To != nil && proof.To.Scan != nil {
				for _, f := range proof.To.Scan.Findings {
					if strings.HasPrefix(f.Location, derivedPrefix) {
						t.Fatalf("a refused tree rewrote %+v", f)
					}
				}
			}
		})
	}
}

// Words that do not name the tree leave it cleared: the test needs the
// refusals above to be about the tree, not about any CI file.
func TestTreeProofUnrelatedSurfaceFilesClear(t *testing.T) {
	from, to := both(map[string]string{
		"test/data/" + fixtureCRD:   crd("Gamma", "v1"),
		".github/workflows/ci.yaml": "run: go test ./... && make -C build/ all\n",
		"hack/gen.py":               "print('hello')\n",
		"Dockerfile":                "FROM scratch\nCOPY bin/app /app\n",
		"cmd/main.go":               "package main\n\nfunc f() { _ = filepath.Join(\"cfg\", \"app\") }\n",
		"cmd/main_test.go":          "package main\n\nfunc g() { _ = filepath.Join(\"test\", \"data\") }\n",
		"test/data/helper/other.go": "package helper\n\nfunc h() { _ = filepath.Join(\"test\", \"data\") }\n",
		"README.md":                 "kubectl apply -f deploy/crds\n",
		"docs/a.md":                 "see the test/data directory\n",
	})
	_, proof, _ := treeRun{tg: treeTarget(true), derive: true}.run(t, from, to)
	if !attestable(proof) {
		t.Fatalf("not cleared: %+v", proof.To.Scan.TreeVerdicts)
	}
	if v := verdictOf(proof, "test"); v == nil || v.Checked < 4 {
		t.Fatalf("verdict %+v", v)
	}
}

// The tree must be proven at every tag of both lines.
func TestTreeProofEveryTag(t *testing.T) {
	from, to := both(map[string]string{"test/data/" + fixtureCRD: crd("Gamma", "v1")})
	to[".github/workflows/ci.yaml"] = "run: kubectl apply -f test/data\n"
	_, proof, _ := treeRun{tg: treeTarget(true), derive: true}.run(t, from, to)
	if attestable(proof) {
		t.Fatal("proven at one line only")
	}
	if v := verdictOf(PairProof{To: proof.From}, "test"); v == nil || v.Verdict != TreeCleared {
		t.Fatalf("the earlier release should be cleared: %+v", v)
	}
	// And the other way round.
	from, to = both(map[string]string{"test/data/" + fixtureCRD: crd("Gamma", "v1")})
	from[".github/workflows/ci.yaml"] = "run: kubectl apply -f test/data\n"
	_, proof, _ = treeRun{tg: treeTarget(true), derive: true}.run(t, from, to)
	if attestable(proof) {
		t.Fatal("proven at one line only")
	}
}

// A tree that is a listed install path (at any tag) is never cleared, and
// vendored code stays blocking (another component).
func TestTreeProofNeverClearsInstallOrVendored(t *testing.T) {
	tg := treeTarget(true)
	tg.Paths = append(tg.Paths, PathSpec{Path: "deploy/examples", Dir: true, Match: regexp.MustCompile(`^[^.][^/]*\.ya?ml$`)})
	from, to := both(map[string]string{
		"deploy/examples/crd.yaml":     crd("Beta", "v1"),
		"deploy/examples/sub/crd.yaml": crd("Gamma", "v1"),
		"vendor/x/" + fixtureCRD:       crd("Delta", "v1"),
	})
	pr, proof, _ := treeRun{tg: tg, derive: true}.run(t, from, to)
	if attestable(proof) {
		t.Fatal("cleared")
	}
	t.Logf("%s %s", pr.Status, pr.Reason)
	if v := verdictOf(proof, "deploy/examples"); v == nil || v.Verdict != TreeUnknown || v.Reason != TreeReasonInstallPath {
		t.Fatalf("install path: %+v", v)
	}
	if v := verdictOf(proof, "vendor"); v == nil || v.Verdict != TreeUnknown || v.Reason != TreeReasonOtherComponent {
		t.Fatalf("vendored: %+v", v)
	}
	// An exclusion of the target over the same directory is also left alone.
	tg = treeTarget(true)
	tg.Exclude = []Exclusion{{Path: "test/", Repo: tg.Repo, Reason: "r", Evidence: "e"}}
	from, to = both(map[string]string{"test/a/testdata/" + fixtureCRD: crd("Gamma", "v1")})
	_, proof, _ = treeRun{tg: tg, derive: true}.run(t, from, to)
	for _, v := range proof.To.Scan.TreeVerdicts {
		if v.Verdict == TreeCleared {
			t.Fatalf("a reviewed exclusion's tree is not derived: %+v", v)
		}
	}
}

// A fixture CRD under a cleared tree never enters the inventory: adding or
// removing it leaves the rules byte-equal.
func TestTreeProofFixtureNeverInInventory(t *testing.T) {
	withFix := func(fix bool) []byte {
		from := map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1beta1", "v1")}
		to := map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}
		if fix {
			from["test/data/"+fixtureCRD] = crd("Alpha", "v1beta1", "v1", "v2")
			to["test/data/"+fixtureCRD] = crd("Alpha", "v1beta1", "v1", "v2")
		}
		_, proof, out := treeRun{tg: treeTarget(true), derive: true}.run(t, from, to)
		if !attestable(proof) {
			t.Fatalf("fix=%v not attestable: %+v", fix, proof.To.Scan.TreeVerdicts)
		}
		b, err := json.Marshal(out.Entries)
		must(t, err)
		return b
	}
	if !bytes.Equal(withFix(true), withFix(false)) {
		t.Fatal("the fixture changed the derived rules")
	}
}

// Scans with no nominated tree are byte-identical with and without the
// option (published records do not move).
func TestTreeProofByteIdentity(t *testing.T) {
	from := map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1beta1", "v1")}
	to := map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}
	_, _, off := treeRun{tg: treeTarget(true)}.run(t, from, to)
	_, _, on := treeRun{tg: treeTarget(true), derive: true}.run(t, from, to)
	a, _ := json.Marshal(off)
	b, _ := json.Marshal(on)
	if !bytes.Equal(a, b) {
		t.Fatal("output moved for a tree-free scan")
	}
}

func TestNamesTree(t *testing.T) {
	rs := []string{"pkg", "testdata"}
	for w, want := range map[string]bool{
		"pkg/testdata":          true,
		"./pkg/testdata/x.yaml": true,
		"pkg/":                  true,
		"a/pkg/testdata":        true,
		"$(D)/pkg/testdata":     true,
		"pkg/*/x":               true,
		"testdata":              false,
		"pkg/other":             false,
		"other/testdata2":       false,
		"$(A)/$(B)":             true,
		"${{ w }}/foo":          false,
		"go/test":               false,
	} {
		if got := namesTree(w, rs); got != want {
			t.Errorf("namesTree(%q) = %v, want %v", w, got, want)
		}
	}
}

// No project name in the code or tests of this capability.
func TestTreeProofNamesNoProject(t *testing.T) {
	for _, f := range []string{"treeproof.go", "treeproof_test.go"} {
		raw, err := os.ReadFile(f)
		must(t, err)
		text := strings.ToLower(string(raw))
		for _, tg := range Targets {
			slug := strings.ToLower(tg.Project)
			if len(slug) < 5 {
				continue
			}
			if regexp.MustCompile(`\b` + regexp.QuoteMeta(slug) + `\b`).MatchString(text) {
				t.Errorf("%s names the project %q", f, slug)
			}
		}
	}
}
