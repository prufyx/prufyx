// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

func publishedSynthTarget() Target {
	tg := attestingTarget()
	tg.MinFrom = [2]int{0, 30}
	return tg
}

func publishedFiles() map[string]string {
	return map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1beta1", "v1")}
}

func publishedRepo(tags ...string) synthRepo {
	rs := make([]release, 0, len(tags))
	for _, tag := range tags {
		rs = append(rs, release{tag, publishedFiles()})
	}
	return newSynth(rs...)
}

// For a registered component, a pair of consecutive published lines is
// attested over skipped minor numbers, with the from-line carried by the
// attestation. A prerelease-only or alias-only line between does not break the
// hop, and the attestations validate.
func TestPublishedLinesAttestOverSkippedMinors(t *testing.T) {
	tg := publishedSynthTarget()
	defer lineattest.SetPublishedLineComponentsForTest(tg.Component)()
	out := runSynth(t, tg, publishedRepo("v25.8.0", "v25.10.1", "v25.10.2", "v26.1.0-rc1", "v26.2.0~1", "v26.3.0", "v26.6.0"))
	for _, c := range []struct{ from, to, line string }{
		{"25.8.0", "25.10.1", "25.10"}, {"25.10.1", "26.3.0", "26.3"}, {"26.3.0", "26.6.0", "26.6"},
	} {
		if a := pairAttestation(t, out, c.from, c.to); a.Status != extract.PairAttested {
			t.Fatalf("%s -> %s: %+v", c.from, c.to, a)
		}
		att := attestationFor(t, out, c.line)
		if att == nil || len(att.RuleIDs) != 0 || att.RuleIDs == nil {
			t.Fatalf("line %s: %+v", c.line, att)
		}
		if from, ok := att.FromLine(); !ok || from != lineOfFirst(att.Releases.From) {
			t.Fatalf("line %s: from-line %q %v", c.line, from, ok)
		}
	}
	if len(out.Attestations) != 3 {
		t.Fatalf("%d attestations", len(out.Attestations))
	}
	if _, err := lineattest.Marshal(out.Attestations); err != nil {
		t.Fatalf("attestations do not validate: %v", err)
	}
}

func lineOfFirst(rs []lineattest.Release) string {
	l, _ := lineattest.LineOf(rs[0].Version)
	return l
}

// A final release of a line between makes the skipped hop disappear: the pairs
// are the consecutive ones. Unregistered, the same tags attest nothing across
// a skipped line.
func TestPublishedLinesLateLineAndUnregistered(t *testing.T) {
	tg := publishedSynthTarget()
	unregistered := runSynth(t, tg, publishedRepo("v25.10.1", "v26.3.0"))
	if a := pairAttestation(t, unregistered, "25.10.1", "26.3.0"); a.Status != extract.PairNotAttested {
		t.Fatalf("an unregistered component attested a skipped-line hop: %+v", a)
	}
	defer lineattest.SetPublishedLineComponentsForTest(tg.Component)()
	out := runSynth(t, tg, publishedRepo("v25.10.1", "v26.1.0", "v26.3.0"))
	for _, p := range out.Manifest.Pairs {
		if p.From == "25.10.1" && p.To == "26.3.0" {
			t.Fatalf("a pair over a published line: %+v", p)
		}
	}
	if a := pairAttestation(t, out, "26.1.0", "26.3.0"); a.Status != extract.PairAttested {
		t.Fatalf("26.1 -> 26.3: %+v", a)
	}
}

// Cross-era and skipped semver minors are not attested; a removal is withheld.
func TestPublishedLinesEraGuardAndRemoval(t *testing.T) {
	tg := publishedSynthTarget()
	defer lineattest.SetPublishedLineComponentsForTest(tg.Component)()
	out := runSynth(t, tg, publishedRepo("v0.34.0", "v0.36.0", "v0.38.0", "v19.9.0", "v20.0.0", "v25.0.0", "v25.8.0"))
	for _, c := range []struct{ from, to, why string }{
		{"0.34.0", "0.36.0", "not the minor line after"},
		{"0.36.0", "0.38.0", "not the minor line after"},
		{"0.38.0", "19.9.0", "not the minor line after"},
		{"19.9.0", "20.0.0", "not the minor line after"},
	} {
		a := pairAttestation(t, out, c.from, c.to)
		if a.Status != extract.PairNotAttested {
			t.Errorf("%s -> %s: %+v", c.from, c.to, a)
		}
	}
	// 20.0 -> 25.0 is calendar era, consecutive published lines: attested.
	if a := pairAttestation(t, out, "20.0.0", "25.0.0"); a.Status != extract.PairAttested {
		t.Errorf("20.0 -> 25.0: %+v", a)
	}

	removal := runSynth(t, tg, newSynth(
		release{"v25.10.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1beta1", "v1")}},
		release{"v26.3.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}},
	))
	p, _ := pairOf(t, removal, "25.10.0", "26.3.0")
	if p.Status != extract.PairWithheld || !strings.Contains(p.Reason, "not derived") || len(removal.Entries) != 0 || len(removal.Attestations) != 0 {
		t.Fatalf("pair %s %q, %d rules, %d attestations", p.Status, p.Reason, len(removal.Entries), len(removal.Attestations))
	}
}

// An ambiguous middle line (padded beside canonical) blocks both neighbours.
func TestPublishedLinesAmbiguousMiddleBlocks(t *testing.T) {
	tg := publishedSynthTarget()
	defer lineattest.SetPublishedLineComponentsForTest(tg.Component)()
	out := runSynth(t, tg, publishedRepo("v25.10.0", "v26.02.0", "v26.2.1", "v26.3.0"))
	for _, p := range out.Manifest.Pairs {
		if p.Attestation != nil && p.Attestation.Status == extract.PairAttested {
			t.Errorf("an attested pair next to an ambiguous line: %+v", p)
		}
	}
}
