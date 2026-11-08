// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"os"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// The fixture carries both the plain and the v-prefixed spelling of each tag
// (upstream publishes both); the target's tagPrefixes ["v"] select only the
// v-prefixed ones, and other prefixes (chart, olm, ...) are not releases.
// The tag list is a fixture of tag names only (testdata/tags), taken once from
// the public repository; commits are synthetic.
func mariadbTarget(t *testing.T) Target {
	t.Helper()
	for _, tg := range Targets {
		if tg.Project == "mariadb-operator" {
			return tg
		}
	}
	t.Fatal("no mariadb-operator target")
	return Target{}
}

func TestMariadbOperatorLinesFrom034(t *testing.T) {
	tg := mariadbTarget(t)
	if tg.MinFrom != [2]int{0, 34} || !tg.Attest {
		t.Fatalf("minFrom %v attest %v, want 0.34 and attest on", tg.MinFrom, tg.Attest)
	}
	raw, err := os.ReadFile("testdata/tags/mariadb-operator.txt")
	if err != nil {
		t.Fatal(err)
	}
	idx := extract.ReleaseIndex{Repo: extract.RepoRef{Key: tg.Repo}}
	for _, name := range strings.Fields(string(raw)) {
		idx.Tags = append(idx.Tags, extract.Tag{Name: name, Commit: commitOf(name)})
	}
	x := New(tg)
	pairs := x.Pairs(idx)
	if len(pairs) == 0 || pairs[0].From != "0.34.0" {
		t.Fatalf("pairs %+v", pairs)
	}
	var attestable, other []string
	for _, p := range pairs {
		fl, tl := x.lineFor(p.FromTag, p.FromCommit, p.From), x.lineFor(p.ToTag, p.ToCommit, p.To)
		hop := p.From + "->" + p.To
		if hopShape(tg.Component, fl, tl) == HopPreviousMinor {
			attestable = append(attestable, hop)
		} else {
			other = append(other, hop)
		}
	}
	want := "0.34.0->0.35.0 0.35.0->0.36.0 0.36.0->0.37.0 0.37.0->0.38.0"
	if got := strings.Join(attestable, " "); got != want {
		t.Fatalf("attestable hops %q, want %q", got, want)
	}
	if len(other) == 0 || other[0] != "0.38.0->25.0.0" {
		t.Fatalf("non-attestable hops %v: the major hop must follow 0.38", other)
	}
	for _, h := range other {
		if strings.HasPrefix(h, "0.3") && h != "0.38.0->25.0.0" {
			t.Fatalf("0.x hop %s outside the consecutive lines is attestable-shaped", h)
		}
	}
}

// The repository vendors an install manifest of another project under
// examples/: it defines that project's toolkit definitions, none of the
// operator's. The target excludes exactly that path; the exclusion must
// clear that one finding and no other.
func TestMariadbOperatorVendoredExampleExclusion(t *testing.T) {
	const dir = "examples/flux/clusters/production/flux-system/"
	const vendored = dir + "gotk-components.yaml"
	tg := mariadbTarget(t)
	if len(tg.Exclude) != 1 || tg.Exclude[0].Path != dir || tg.Exclude[0].Repo != tg.Repo || tg.Exclude[0].Copies || tg.Exclude[0].PrePatch != "" {
		t.Fatalf("exclude %+v: want exactly one plain directory entry %s", tg.Exclude, dir)
	}
	if got := tg.placeOf(vendored); got.kind != locReviewed || got.entry != dir {
		t.Fatalf("place %+v", got)
	}
	// The directory also holds the kustomization that lists the manifest:
	// the install-surface guard must not void the entry.
	kustomization := "resources:\n  - gotk-components.yaml\n"
	build := func(extra string) synthRepo {
		files := func(v string) map[string]string {
			f := map[string]string{"config/crd/bases/mariadb.yaml": crd("Alpha", v)}
			f[extra] = crd("Gamma", "v1")
			f[dir+"kustomization.yaml"] = kustomization
			return f
		}
		return newSynth(
			release{"v0.34.0", files("v1beta1")},
			release{"v0.35.0", files("v1beta1")},
		)
	}
	for _, in := range []string{vendored, dir + "other-name.yaml"} {
		_, proof := pairOf(t, runSynth(t, tg, build(in)), "0.34.0", "0.35.0")
		if !proof.Completeness.Scan || !proof.Completeness.Attestable {
			t.Fatalf("a definition file inside the excluded directory (%s) is excluded by design: %+v", in, proof.Completeness)
		}
		// Recorded, never blocking: the file is listed as excluded at the
		// directory with its definitions named.
		recorded := false
		for _, f := range proof.To.Scan.Findings {
			if f.Path == in && f.Class == ClassExcluded && f.Location == dir && len(f.CRDs) > 0 {
				recorded = true
			}
		}
		if !recorded {
			t.Fatalf("%s is not recorded as an excluded finding: %+v", in, proof.To.Scan.Findings)
		}
	}
	// ACCEPTED RISK, listed for the independent trust review: the scope is
	// the whole directory and has no version scope, so a later operator
	// definition placed in it (other-name.yaml above) would be hidden, and the
	// evidence covers v0.34.0 to v0.38.1 only.
	//
	// The guard still trips when an install surface reaches the directory, and
	// a definition file that the in-directory kustomization pulls in from
	// outside the directory is an extra file in the open tree.
	rootRef := "resources:\n  - flux/clusters/production/flux-system\n"
	for name, tc := range map[string]struct {
		extra     map[string]string
		wantVoid  bool
		attestOff bool
	}{
		"install surface lists the directory": {map[string]string{"examples/kustomization.yaml": rootRef}, true, true},
		"directory kustomization pulls another definition file": {map[string]string{
			dir + "kustomization.yaml": "resources:\n  - gotk-components.yaml\n  - ../../../../deploy/pulled-crds.yaml\n",
			"deploy/pulled-crds.yaml":  crd("Delta", "v1"),
		}, false, true},
	} {
		s := build(vendored)
		for i := range s.tags {
			for p, c := range tc.extra {
				s.files[s.tags[i].Commit+":"+p] = []byte(c)
			}
		}
		_, proof := pairOf(t, runSynth(t, tg, s), "0.34.0", "0.35.0")
		if (len(voidFindings(proof)) > 0) != tc.wantVoid || proof.Completeness.Attestable == tc.attestOff {
			t.Fatalf("%s: void %+v, completeness %+v", name, voidFindings(proof), proof.Completeness)
		}
	}
	// An extra definition file in any other directory still blocks, a
	// sibling environment included.
	for _, other := range []string{
		"examples/flux/clusters/staging/flux-system/gotk-components.yaml",
		"examples/other/crds.yaml",
		"deploy/extra-crds.yaml",
	} {
		_, proof := pairOf(t, runSynth(t, tg, build(other)), "0.34.0", "0.35.0")
		if proof.Completeness.Attestable {
			t.Fatalf("an extra definition at %s must still block attestation: %+v", other, proof.Completeness)
		}
	}
}
