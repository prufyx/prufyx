// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/rulecheck"
)

func attestingTarget(exclude ...Exclusion) Target {
	tg := synthTarget(exclude...)
	tg.Attest = true
	return tg
}

// communityTarget is a synthetic community catalog target. Even with the
// attest flag forced on (the loader refuses it), it never attests.
func communityTarget() Target {
	tg := synthTarget()
	tg.Catalog, tg.Attest = CatalogCommunity, true
	return tg
}

func attestationFor(t *testing.T, out *extract.Output, line string) *lineattest.LineAttestation {
	t.Helper()
	for i := range out.Attestations {
		if out.Attestations[i].Line == line {
			return &out.Attestations[i]
		}
	}
	return nil
}

func pairAttestation(t *testing.T, out *extract.Output, from, to string) *extract.PairAttestation {
	t.Helper()
	p, _ := pairOf(t, out, from, to)
	if p.Attestation == nil {
		t.Fatalf("pair %s -> %s has no attestation record", from, to)
	}
	return p.Attestation
}

// The synthetic Argo CD fixture: line 90.1 (two removals, both line-wide)
// and line 90.2 (quiet) are attested; each names every release of both
// lines it read.
func TestFixtureLinesAreAttested(t *testing.T) {
	out := fixtureOutput(t)
	if len(out.Attestations) != 2 || out.Manifest.Totals.Attestations != 2 {
		t.Fatalf("%d attestations", len(out.Attestations))
	}
	removal := attestationFor(t, out, "90.1")
	quiet := attestationFor(t, out, "90.2")
	if removal == nil || quiet == nil {
		t.Fatalf("attestations %+v", out.Attestations)
	}
	ids := []string{"argo-cd.crd-version-removal.gadgets-fixture-argoproj-io.90-0-0-to-90-1-0", "argo-cd.crd-version-removal.widgets-fixture-argoproj-io.90-0-0-to-90-1-0"}
	if removal.Component != "pkg:github/argoproj/argo-cd" || removal.FactFamily != lineattest.FamilyCustomResourceVersions || !slices.Equal(removal.RuleIDs, ids) {
		t.Fatalf("90.1 %+v", removal)
	}
	if len(quiet.RuleIDs) != 0 || quiet.RuleIDs == nil {
		t.Fatalf("quiet line lists %v", quiet.RuleIDs)
	}
	versions := func(rs []lineattest.Release) []string {
		var out []string
		for _, r := range rs {
			out = append(out, r.Version)
		}
		return out
	}
	if !slices.Equal(versions(removal.Releases.From), []string{"90.0.0"}) || !slices.Equal(versions(removal.Releases.To), []string{"90.1.0", "90.1.1"}) ||
		!slices.Equal(versions(quiet.Releases.From), []string{"90.1.0", "90.1.1"}) || !slices.Equal(versions(quiet.Releases.To), []string{"90.2.0"}) {
		t.Fatalf("releases %+v %+v", removal.Releases, quiet.Releases)
	}
	if !removal.CoversReleases("90.0.0", "90.1.1") || removal.CoversReleases("90.0.0", "90.1.2") {
		t.Fatal("release coverage")
	}
	if e := quiet.Evidence; e.Basis != "mechanical" || e.Extractor == nil || e.Extractor.ID != "crd.version-removal.argo-cd" || e.Extractor.Version != Version || len(e.Sources) != 2 {
		t.Fatalf("evidence %+v", e)
	}
	for _, p := range out.Manifest.Pairs {
		if p.Attestation == nil || p.Attestation.Status != extract.PairAttested || !slices.Equal(p.Attestation.Families, []string{lineattest.FamilyCustomResourceVersions}) {
			t.Fatalf("pair %s: %+v", p.From+"->"+p.To, p.Attestation)
		}
	}
	// The pack rule check agrees: exact sets, line-wide rules.
	raw, err := lineattest.Marshal(out.Attestations)
	must(t, err)
	var rules []json.RawMessage
	for _, e := range out.Entries {
		r, err := json.Marshal(e.Rule)
		must(t, err)
		rules = append(rules, r)
	}
	if res := rulecheck.ValidateLineAttestations(raw, rules, rulecheck.AttestationOptions{}); !res.Valid {
		t.Fatalf("rulecheck %+v", res.Findings)
	}
}

// Every pair the derivation does not establish completely, and every pair
// of another hop shape, is derived but not attested, with the reason.
func TestNotAttested(t *testing.T) {
	alpha := crd("Alpha", "v1beta1", "v1")
	cases := map[string]struct {
		tg       Target
		releases []release
		from, to string
		reason   string
	}{
		"target does not attest": {synthTarget(), []release{
			{"v1.0.0", map[string]string{"deploy/crds/a.yaml": alpha}}, {"v1.1.0", map[string]string{"deploy/crds/a.yaml": alpha}},
		}, "1.0.0", "1.1.0", "attest is off"},
		"community target": {communityTarget(), []release{
			{"v1.0.0", map[string]string{"deploy/crds/a.yaml": alpha}}, {"v1.1.0", map[string]string{"deploy/crds/a.yaml": alpha}},
		}, "1.0.0", "1.1.0", "community catalog"},
		"flapping version": {attestingTarget(), []release{
			{"v1.0.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1alpha1", "v1")}},
			{"v1.1.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}},
			{"v1.1.1", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1alpha1", "v1")}},
		}, "1.0.0", "1.1.0", "anchor pair only"},
		"extra definition outside the listed paths": {attestingTarget(), []release{
			{"v1.0.0", map[string]string{"deploy/crds/a.yaml": alpha, "deploy/other.yaml": crd("Beta", "v1")}},
			{"v1.1.0", map[string]string{"deploy/crds/a.yaml": alpha, "deploy/other.yaml": crd("Beta", "v1")}},
		}, "1.0.0", "1.1.0", "found extra"},
		"incomplete patch release": {attestingTarget(), []release{
			{"v1.0.0", map[string]string{"deploy/crds/a.yaml": alpha}},
			{"v1.0.1", map[string]string{"deploy/crds/a.yaml": "{{ template }}\n" + alpha}},
			{"v1.1.0", map[string]string{"deploy/crds/a.yaml": alpha}},
		}, "1.0.0", "1.1.0", "listed paths are not complete"},
		"definition removed": {attestingTarget(), []release{
			{"v1.0.0", map[string]string{"deploy/crds/a.yaml": alpha, "deploy/crds/b.yaml": crd("Beta", "v1")}},
			{"v1.1.0", map[string]string{"deploy/crds/a.yaml": alpha}},
		}, "1.0.0", "1.1.0", "no longer defines betas"},
		"new major": {attestingTarget(), []release{
			{"v1.9.0", map[string]string{"deploy/crds/a.yaml": alpha}}, {"v2.0.0", map[string]string{"deploy/crds/a.yaml": alpha}},
		}, "1.9.0", "2.0.0", "major hop"},
		"skipped minor": {attestingTarget(), []release{
			{"v1.1.0", map[string]string{"deploy/crds/a.yaml": alpha}}, {"v1.3.0", map[string]string{"deploy/crds/a.yaml": alpha}},
		}, "1.1.0", "1.3.0", "skipped-minor hop"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			out := runSynth(t, tc.tg, newSynth(tc.releases...))
			p, _ := pairOf(t, out, tc.from, tc.to)
			a := pairAttestation(t, out, tc.from, tc.to)
			if p.Status != extract.PairDerived || a.Status != extract.PairNotAttested || !strings.Contains(a.Reason, tc.reason) || len(out.Attestations) != 0 {
				t.Fatalf("pair %s %q attestation %+v (%d attestations)", p.Status, p.Reason, a, len(out.Attestations))
			}
		})
	}
	// A quiet consecutive pair of an attesting target is attested.
	out := runSynth(t, attestingTarget(), newSynth(
		release{"v1.0.0", map[string]string{"deploy/crds/a.yaml": alpha}}, release{"v1.1.0", map[string]string{"deploy/crds/a.yaml": alpha}},
	))
	if a := pairAttestation(t, out, "1.0.0", "1.1.0"); a.Status != extract.PairAttested || len(out.Attestations) != 1 {
		t.Fatalf("quiet pair %+v", a)
	}
}

// A withheld pair is never attested.
func TestWithheldPairIsNotAttested(t *testing.T) {
	out := runSynth(t, attestingTarget(), newSynth(
		release{"v1.0.0", map[string]string{"deploy/crds/a.yaml": "{{ template }}\n" + crd("Alpha", "v1")}},
		release{"v1.1.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}},
	))
	p, _ := pairOf(t, out, "1.0.0", "1.1.0")
	if p.Status != extract.PairWithheld || p.Attestation == nil || p.Attestation.Status != extract.PairNotAttested || len(out.Attestations) != 0 {
		t.Fatalf("pair %+v", p)
	}
}

// Registered Strimzi (0.51 -> 1.0: a new major with removed definitions)
// and unregistered Longhorn derive rules and attest nothing.
func TestRealTargetsAttestOnlyWhatTheyMay(t *testing.T) {
	out := mustRun(t, "strimzi", extract.FixtureReader{Root: strimziRoot})
	if len(out.Attestations) != 0 {
		t.Fatalf("strimzi attested %+v", out.Attestations)
	}
	for _, p := range out.Manifest.Pairs {
		if p.Attestation == nil || p.Attestation.Status != extract.PairNotAttested || p.Attestation.Reason == "" {
			t.Fatalf("strimzi pair %s: %+v", p.From+"->"+p.To, p.Attestation)
		}
	}
	tg, _ := TargetFor("longhorn")
	if tg.Attest || len(New(tg).AttestedFamilies()) != 0 {
		t.Fatal("longhorn attests")
	}
}

// attestPending lists the registered targets that do not attest yet: their
// set fact and groups are in the reviewed table (REGISTRY-WAVE-1, CRD-GEN wave 2) and the
// family admits their component, but the extractor attests their lines only
// after their own review of what a complete line means for the project
// (the attest flag of targets.json, a separate reviewed change).
var attestPending = []string{"antrea", "cert-manager", "cilium", "cloudnativepg", "contour", "crossplane", "dapr", "external-secrets", "karmada", "keda", "koordinator", "kuma", "kyverno", "longhorn", "metallb", "openkruise", "rook", "tekton", "velero", "volcano"}

// A target attests only when its project is in the reviewed custom-resource
// table (its set fact is registered), and never while it is listed as
// pending; the family covers exactly the registered CNCF catalog
// components. A community target never attests (the loader refuses it) and
// the family never admits its component: its line reviews have no
// knowledge target yet.
func TestAttestingTargetsAreTheRegisteredProjects(t *testing.T) {
	family, _ := lineattest.LookupFamily(lineattest.FamilyCustomResourceVersions)
	for _, tg := range Targets {
		p, registered := customresources.ProjectFor(tg.Project)
		if tg.Catalog == CatalogCommunity {
			if !registered || !p.Community() || tg.Attest || family.Admits(tg.Component) || slices.Contains(attestPending, tg.Project) {
				t.Fatalf("%s: community target: registered %v, attest %v, family admits %v", tg.Project, registered, tg.Attest, family.Admits(tg.Component))
			}
			continue
		}
		pending := slices.Contains(attestPending, tg.Project)
		if tg.Attest != (registered && !pending) || family.Admits(tg.Component) != registered {
			t.Fatalf("%s: attest %v, registered %v, pending %v, family admits %v", tg.Project, tg.Attest, registered, pending, family.Admits(tg.Component))
		}
		x := New(tg)
		if x.AttestedComponent() != tg.Component {
			t.Fatalf("%s attests %s", tg.Project, x.AttestedComponent())
		}
	}
}

// tampering wraps the extractor and changes the attestation it proposes.
type tampering struct {
	*Extractor
	change func(c *extract.AttestationCandidate)
}

func (x tampering) Extract(ctx context.Context, r extract.PinnedReader, pair extract.VersionPair) (extract.Extraction, error) {
	res, err := x.Extractor.Extract(ctx, r, pair)
	for i := range res.Attestations {
		x.change(&res.Attestations[i])
	}
	return res, err
}

// The framework refuses an attestation of another component, or one that
// names a release the extractor did not read at a recorded release tag.
func TestFrameworkChecksAttestedComponentAndReleases(t *testing.T) {
	alpha := crd("Alpha", "v1beta1", "v1")
	s := newSynth(release{"v1.0.0", map[string]string{"deploy/crds/a.yaml": alpha}}, release{"v1.1.0", map[string]string{"deploy/crds/a.yaml": alpha}},
		release{"v1.1.1", map[string]string{"deploy/crds/a.yaml": alpha}})
	repo, err := extract.ParseRepo(attestingTarget().Repo)
	must(t, err)
	for name, tc := range map[string]struct {
		change func(c *extract.AttestationCandidate)
		want   string
	}{
		"other component": {func(c *extract.AttestationCandidate) { c.Component = "pkg:github/strimzi/strimzi-kafka-operator" }, "the extractor attests"},
		"release not read": {func(c *extract.AttestationCandidate) {
			c.Releases.To = append(c.Releases.To, lineattest.Release{Version: "1.1.2", Commit: commitOf("v1.1.2")})
		}, "not a recorded release tag the extractor read"},
		"release at another commit": {func(c *extract.AttestationCandidate) { c.Releases.To[1].Commit = commitOf("v1.1.0") }, "not a recorded release tag"},
		"version of another tag":    {func(c *extract.AttestationCandidate) { c.Releases.To[0].Version = "1.1.5" }, "not a recorded release tag"},
		"no releases":               {func(c *extract.AttestationCandidate) { c.Releases = nil }, "releases is required"},
	} {
		t.Run(name, func(t *testing.T) {
			x := tampering{New(attestingTarget()), tc.change}
			_, err := extract.Run(context.Background(), x, s, s, extract.Options{Repo: repo, DerivedAt: derivedAt})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}
