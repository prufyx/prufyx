// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/extract"
)

// syntheticOwnership explicitly attributes the named fixture groups. These
// fixtures exercise source guards and removal semantics, not unknown identity.
// All other reviewed listings remain intact; no unknown group gets a fallback.
func syntheticOwnership(tg Target, groups ...string) customresources.Index {
	ps := customresources.Projects()
	for i := range ps {
		if ps[i].Slug == tg.Project {
			for _, g := range groups {
				ps[i].Groups = append(ps[i].Groups, customresources.Group{Name: g})
			}
			return customresources.NewIndex(ps)
		}
	}
	p := customresources.Project{Slug: tg.Project}
	for _, g := range groups {
		p.Groups = append(p.Groups, customresources.Group{Name: g})
	}
	return customresources.NewIndex(append(ps, p))
}

func fixtureExtractor(tg Target) *Extractor {
	x := New(tg)
	if tg.Project == "argo-cd" {
		x.WithIndex(syntheticOwnership(tg, group))
	}
	return x
}

func ownershipIndex(kinds []string, others ...customresources.Project) customresources.Index {
	ps := []customresources.Project{{Slug: "argo-cd", Groups: []customresources.Group{{Name: synthGroup, Kinds: kinds}}}}
	return customresources.NewIndex(append(ps, others...))
}

func ownershipRun(t *testing.T, tg Target, s synthRepo, ix customresources.Index) *extract.Output {
	t.Helper()
	repo, err := extract.ParseRepo(tg.Repo)
	must(t, err)
	x := New(tg).WithIndex(ix)
	out, err := extract.Run(context.Background(), x, ReleaseTags(x, s), s, extract.Options{Repo: repo, DerivedAt: derivedAt})
	must(t, err)
	return out
}

func ownershipPair(alphaFrom, alphaTo string, extra map[string]string) synthRepo {
	f := map[string]string{"deploy/crds/a.yaml": alphaFrom, "deploy/crds/b.yaml": crd("Beta", "v1")}
	to := map[string]string{"deploy/crds/a.yaml": alphaTo, "deploy/crds/b.yaml": crd("Beta", "v1")}
	for p, b := range extra {
		to[p] = b
	}
	return newSynth(release{"v1.0.0", f}, release{"v1.1.0", to})
}

func TestRemovalOwnershipMatrix(t *testing.T) {
	foreign := customresources.Project{Slug: "other", Groups: []customresources.Group{{Name: synthGroup, Kinds: []string{"Alpha"}}}}
	cases := []struct {
		name             string
		ix               customresources.Index
		emitted, foreign bool
	}{
		{"owned", ownershipIndex(nil), true, false},
		{"unlisted", customresources.NewIndex([]customresources.Project{{Slug: "argo-cd", Groups: []customresources.Group{{Name: "another.example.io"}}}}), false, false},
		{"ambiguous", ownershipIndex(nil, foreign), false, false},
		{"foreign", ownershipIndex([]string{"Beta"}, foreign), false, true},
		{"restricted-kind", ownershipIndex([]string{"Beta"}), false, false},
		{"case-sensitive-kind", ownershipIndex([]string{"alpha", "Beta"}), false, false},
		{"empty-kinds", ownershipIndex([]string{}), false, false},
		{"empty-index", customresources.NewIndex(nil), false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := ownershipRun(t, attestingTarget(), ownershipPair(crd("Alpha", "v1beta1", "v1"), crd("Alpha", "v1"), nil), tc.ix)
			p, proof := pairOf(t, out, "1.0.0", "1.1.0")
			if p.Status != extract.PairDerived || !proof.Completeness.Attestable {
				t.Fatalf("source proof changed: %+v %+v", p, proof.Completeness)
			}
			if tc.emitted {
				if len(out.Entries) != 1 || len(out.Attestations) != 1 {
					t.Fatalf("owned output %+v", out.Manifest)
				}
				e := out.Entries[0]
				if e.Rule.Subject.Component != attestingTarget().Component || e.Rule.SetCondition.Component != attestingTarget().Component || e.Rule.SetCondition.FactID != attestingTarget().FactID() || !reflect.DeepEqual(e.Rule.SetCondition.Members, []string{synthGroup + "/v1beta1/Alpha"}) || e.Rule.Range == nil || len(e.Rule.Evidence.Sources) == 0 {
					t.Fatalf("owned identity lost: %+v", e)
				}
			} else if tc.foreign {
				if len(out.Entries) != 0 || len(proof.Removals) != 0 || len(proof.From.Foreign) != 1 || strings.Contains(p.Attestation.Reason, "not attributed uniquely") {
					t.Fatalf("foreign accounting changed: %+v %+v", p, proof)
				}
			} else {
				if len(out.Entries) != 0 || len(proof.Removals) != 1 || len(out.Attestations) != 0 || !strings.Contains(p.Attestation.Reason, "not attributed uniquely to argo-cd: "+synthGroup+"/Alpha") {
					t.Fatalf("unowned removal admitted/lost: %+v %+v", p, proof)
				}
				if len(proof.From.CRDs) != 2 || len(proof.To.CRDs) != 2 || len(proof.From.Files) != 2 {
					t.Fatal("unowned source removed")
				}
			}
		})
	}
}

func TestRemovalOwnershipMixedAndQuiet(t *testing.T) {
	for _, quiet := range []bool{false, true} {
		t.Run(map[bool]string{true: "quiet", false: "mixed"}[quiet], func(t *testing.T) {
			early := crd("Alpha", "v1beta1", "v1")
			later := crd("Alpha", "v1")
			betaEarly := crd("Beta", "v1beta1", "v1")
			betaLater := crd("Beta", "v1")
			if quiet {
				later = early
				betaLater = betaEarly
			}
			s := newSynth(release{"v1.0.0", map[string]string{"deploy/crds/a.yaml": early, "deploy/crds/b.yaml": betaEarly}}, release{"v1.1.0", map[string]string{"deploy/crds/a.yaml": later, "deploy/crds/b.yaml": betaLater}})
			out := ownershipRun(t, attestingTarget(), s, ownershipIndex([]string{"Beta"}))
			p, proof := pairOf(t, out, "1.0.0", "1.1.0")
			if !proof.Completeness.Attestable {
				t.Fatalf("source incomplete: %+v", proof.Completeness)
			}
			if quiet {
				if len(out.Attestations) != 1 || len(out.Entries) != 0 {
					t.Fatal("quiet owned/unknown source failed")
				}
				return
			}
			if len(out.Entries) != 1 || !reflect.DeepEqual(out.Entries[0].Rule.SetCondition.Members, []string{synthGroup + "/v1beta1/Beta"}) || len(proof.Removals) != 2 || len(out.Attestations) != 0 || !strings.Contains(p.Attestation.Reason, "/Alpha") {
				t.Fatalf("mixed filtering loses scope: %+v %+v", p, proof)
			}
		})
	}
}

func TestRemovalOwnershipRefusalComposition(t *testing.T) {
	chart := "apiVersion: v2\nname: fixture\nversion: 1.0.0\ndependencies:\n- name: external\n  version: 1.0.0\n  repository: https://example.org/charts\n"
	s := ownershipPair(crd("Alpha", "v1beta1", "v1"), crd("Alpha", "v1"), map[string]string{"charts/fixture/Chart.yaml": chart})
	out := ownershipRun(t, attestingTarget(), s, ownershipIndex([]string{"Beta"}))
	p, proof := pairOf(t, out, "1.0.0", "1.1.0")
	if proof.Completeness.Attestable || !strings.Contains(p.Attestation.Reason, "external files") || !strings.Contains(p.Attestation.Reason, "not attributed uniquely") || len(proof.Removals) != 1 || len(out.Attestations) != 0 {
		t.Fatalf("refusal hidden: %+v %+v", p, proof.Completeness)
	}
	// An off target retains its original refusal too.
	out = ownershipRun(t, synthTarget(), s, ownershipIndex([]string{"Beta"}))
	p, _ = pairOf(t, out, "1.0.0", "1.1.0")
	if !strings.Contains(p.Attestation.Reason, "attest is off") || !strings.Contains(p.Attestation.Reason, "not attributed uniquely") {
		t.Fatalf("off refusal replaced: %+v", p)
	}
}

func TestRemovalOwnershipPreservesUnreadVeto(t *testing.T) {
	unread := "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: {{ .Values.name }}\n"
	s := ownershipPair(crd("Alpha", "v1beta1", "v1"), crd("Alpha", "v1"), map[string]string{"deploy/other.yaml": unread})
	out := ownershipRun(t, attestingTarget(), s, ownershipIndex([]string{"Beta"}))
	p, proof := pairOf(t, out, "1.0.0", "1.1.0")
	if p.Status != extract.PairWithheld || !strings.Contains(p.Reason, "a version the rules forbid may still be served there") || len(proof.Removals) != 1 {
		t.Fatalf("filter bypassed unread veto: %+v %+v", p, proof)
	}
}

func TestRemovalOwnershipAnchorAndPatch(t *testing.T) {
	beta := crd("Beta", "v1")
	for _, patchOnly := range []bool{false, true} {
		t.Run(map[bool]string{false: "anchor-fallback", true: "patch-only"}[patchOnly], func(t *testing.T) {
			early := map[string]string{"deploy/crds/b.yaml": beta}
			patch := map[string]string{"deploy/crds/b.yaml": beta, "deploy/crds/a.yaml": crd("Alpha", "v1beta1", "v1")}
			later := map[string]string{"deploy/crds/b.yaml": beta, "deploy/crds/a.yaml": crd("Alpha", "v1")}
			if !patchOnly {
				early["deploy/crds/a.yaml"] = crd("Alpha", "v1beta1", "v1")
				patch["deploy/crds/a.yaml"] = strings.Replace(crd("Alpha", "v1beta1", "v1"), "kind: Alpha", "kind: Other", 1)
			}
			s := newSynth(release{"v1.0.0", early}, release{"v1.0.1", patch}, release{"v1.1.0", later})
			out := ownershipRun(t, attestingTarget(), s, ownershipIndex([]string{"Alpha", "Beta"}))
			_, proof := pairOf(t, out, "1.0.0", "1.1.0")
			if len(out.Entries) != 1 || !reflect.DeepEqual(out.Entries[0].Rule.SetCondition.Members, []string{synthGroup + "/v1beta1/Alpha"}) {
				t.Fatalf("selected wrong source identity: %+v", out.Manifest)
			}
			if patchOnly && !proof.Lines.LineWide {
				t.Fatal("patch-only rule lost range")
			}
			if !patchOnly && (proof.Lines.LineWide || out.Entries[0].Rule.Range != nil) {
				t.Fatal("anchor fallback changed")
			}
		})
	}
}

func TestRemovalOwnershipIndexFreeze(t *testing.T) {
	tg := attestingTarget()
	s := ownershipPair(crd("Alpha", "v1beta1", "v1"), crd("Alpha", "v1"), nil)
	for _, prime := range []string{"source-identity", "inventory"} {
		t.Run(prime, func(t *testing.T) {
			x := New(tg)
			x.WithIndex(ownershipIndex(nil)) // Return need not be used for configuration.
			repo, err := extract.ParseRepo(tg.Repo)
			must(t, err)
			if prime == "source-identity" {
				x.SourceFiles()
			} else {
				_, err = x.inventory(s, repo, "v1.0.0", commitOf("v1.0.0"), "1.0.0")
				must(t, err)
			}
			x.WithIndex(customresources.NewIndex(nil))
			_, err = extract.Run(context.Background(), x, ReleaseTags(x, s), s, extract.Options{Repo: repo, DerivedAt: derivedAt})
			if err == nil || !strings.Contains(err.Error(), "index cannot change") {
				t.Fatalf("late index accepted: %v", err)
			}
			if owner, a := x.index.OwnerOf(synthGroup, "Alpha"); a != customresources.Owned || owner != "argo-cd" {
				t.Fatal("late index replaced original")
			}
		})
	}
}

func TestRemovalOwnershipPreservesCalendarVeto(t *testing.T) {
	tg := synthTarget()
	tg.Project = "kamaji"
	tg.Component = "pkg:github/clastix/kamaji"
	tg.Repo = "github.com/clastix/kamaji"
	tg.FactProject = "kamaji"
	tg.ReleaseScheme = SchemeCalverEdge
	tg.TagPrefixes = nil
	tg.MinFrom = [2]int{26, 3}
	// Calendar releases start at patch one, unlike semantic minor anchors.
	s := newSynth(release{"26.3.1-edge", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1beta1", "v1")}}, release{"26.4.1-edge", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}})
	out := ownershipRun(t, tg, s, customresources.NewIndex(nil))
	p, _ := pairOf(t, out, "26.3.1", "26.4.1")
	if p.Status != extract.PairWithheld || !strings.Contains(p.Reason, "release scheme") {
		t.Fatalf("filter bypassed calendar veto: %+v", p)
	}
}

func TestRookRequiredCSIHasNoRookRules(t *testing.T) {
	out := mustRun(t, "rook", extract.FixtureReader{Root: "testdata/oracle"})
	p, proof := pairOf(t, out, "1.17.0", "1.18.0")
	if p.Status != extract.PairDerived || len(out.Entries) != 0 || len(proof.Removals) != 5 || len(proof.UnlistedRemovals) != 0 || !strings.Contains(p.Attestation.Reason, "not attributed uniquely to rook") {
		t.Fatalf("CSI identity/proof changed: %+v %+v", p, proof)
	}
	if len(out.Attestations) != 0 || p.Attestation.Status != extract.PairNotAttested || !proof.Completeness.Attestable {
		t.Fatalf("bounded source completeness confused with family attestation: %+v %+v", p.Attestation, proof.Completeness)
	}
	want := map[string]bool{"CephConnection": true, "ClientProfileMapping": true, "ClientProfile": true, "Driver": true, "OperatorConfig": true}
	for _, rm := range proof.Removals {
		kind := strings.TrimPrefix(rm.Member, "csi.ceph.io/v1alpha1/")
		if !want[kind] || rm.Reason != ReasonAbsent {
			t.Fatalf("unexpected CSI proof removal: %+v", rm)
		}
		delete(want, kind)
	}
	if len(want) != 0 {
		t.Fatalf("missing CSI proof removals: %v", want)
	}
	for _, inv := range []*Inventory{proof.From, proof.To} {
		if len(inv.Files) != 2 || len(inv.CRDs) != len(proof.From.CRDs) || len(inv.Scan.Findings) != 0 {
			t.Fatalf("required CSI source not accounted: %+v", inv)
		}
	}
	// This retained two-anchor fixture contains no external chart dependency;
	// it cannot prove canonical all-release completeness or admission.
}
