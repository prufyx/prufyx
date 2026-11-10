// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

const (
	notUnderDir = "patch-not-under-definition-dir"
	notListed   = "patch-name-not-in-inventory"
	notStrict   = "patch-not-strict"
)

// fragmentReasonCases: one patch fragment next to the synthetic layout
// (deploy/ is a declared definition kustomization directory, alphas is the
// listed definition). status, attestable and class are what the scan decided
// before the failed condition was recorded; the test pins them, and the
// reason code and detail.
var fragmentReasonCases = []struct {
	name       string
	path       string
	file       string
	status     string
	attestable bool
	class      string
	reason     string
	detail     string
}{
	{name: "accepted patch", path: "deploy/patches/webhook_in_alphas.yaml", file: webhookFragment, status: extract.PairDerived, attestable: true, class: ClassCRDPatch, reason: ReasonFragment, detail: "a patch fragment that only sets"},
	{name: "not strict", path: "deploy/patches/webhook_in_alphas.yaml", file: webhookFragment + "  versions:\n  - name: v2\n", status: extract.PairDerived, class: ClassUnread, reason: notStrict, detail: `not a patch fragment the scan accepts: document 1: spec key "versions"`},
	{name: "not strict and outside", path: "other/patches/webhook_in_alphas.yaml", file: webhookFragment + "  versions:\n  - name: v2\n", status: extract.PairDerived, class: ClassUnread, reason: notStrict + "+" + notUnderDir},
	{name: "outside a definition directory", path: "other/patches/webhook_in_alphas.yaml", file: webhookFragment, status: extract.PairDerived, class: ClassUnread, reason: notUnderDir, detail: "a patch fragment outside a declared definition kustomization directory"},
	{name: "name not in the inventory", path: "deploy/patches/other.yaml", file: strings.ReplaceAll(cainjectionFragment, "alphas.", "gammas."), status: extract.PairDerived, class: ClassUnread, reason: notListed, detail: "gammas.synth.example.io, which the listed paths do not define"},
	{name: "outside and name not in the inventory", path: "other/patches/other.yaml", file: strings.ReplaceAll(cainjectionFragment, "alphas.", "gammas."), status: extract.PairDerived, class: ClassUnread, reason: notUnderDir + "+" + notListed, detail: "outside a declared definition kustomization directory"},
}

func fragmentPair(t *testing.T, path, file string) (extract.PairRecord, PairProof) {
	t.Helper()
	alpha := crd("Alpha", "v1beta1", "v1")
	files := map[string]string{"deploy/kustomization.yaml": synthKustomization, path: file}
	return classPair(t, alpha, alpha, files, files)
}

// Each failed condition of a patch fragment is recorded as its own code; the
// pair status, the attestable outcome, the class and the detail are those
// the scan decided before the codes were recorded.
func TestFragmentFailedConditionRecorded(t *testing.T) {
	for _, c := range fragmentReasonCases {
		t.Run(c.name, func(t *testing.T) {
			p, proof := fragmentPair(t, c.path, c.file)
			attestable := proof.Completeness != nil && proof.Completeness.Attestable
			if p.Status != c.status || attestable != c.attestable {
				t.Fatalf("outcome changed: %s %q attestable=%v", p.Status, p.Reason, attestable)
			}
			for _, inv := range []*Inventory{proof.From, proof.To} {
				f := findingOf(inv.Scan, c.path)
				if f == nil || f.Class != c.class || f.Reason != c.reason || !strings.Contains(f.Detail, c.detail) {
					t.Fatalf("%s: finding %+v, want %s %s %q", inv.Tag, f, c.class, c.reason, c.detail)
				}
				if f.blocks() == c.attestable {
					t.Fatalf("%s: blocks() = %v", inv.Tag, f.blocks())
				}
				if copyRecordOf(inv.Scan, c.path) != nil {
					t.Fatalf("a finding is not a copy record")
				}
			}
		})
	}
}

// The codes are a fixed set, in the order not-strict, directory, name. By
// construction a reason may hold three; in practice it holds at most two,
// because a document that is not strict is recorded before its name is
// read, so not-strict and name never occur together (TestFragmentReasonCombinations); the recording is a function of the bytes and
// the declared directories, so reading twice gives the same record.
func TestFragmentReasonsBoundedAndDeterministic(t *testing.T) {
	order := []string{notStrict, notUnderDir, notListed}
	var first []string
	for round := 0; round < 2; round++ {
		var got []string
		for _, c := range fragmentReasonCases {
			_, proof := fragmentPair(t, c.path, c.file)
			f := findingOf(proof.To.Scan, c.path)
			if f == nil {
				t.Fatalf("%s: no finding", c.name)
			}
			parts := strings.Split(f.Reason, "+")
			idx := -1
			for _, p := range parts {
				if f.Reason != ReasonFragment && !slices.Contains(order, p) {
					t.Fatalf("%s: unknown code %q", c.name, p)
				}
				i := slices.Index(order, p)
				if i != -1 && i <= idx {
					t.Fatalf("%s: codes out of order: %s", c.name, f.Reason)
				}
				if i != -1 {
					idx = i
				}
			}
			if len(parts) > len(order) {
				t.Fatalf("%s: unbounded reason %q", c.name, f.Reason)
			}
			got = append(got, f.Reason)
		}
		if round == 0 {
			first = got
		} else if !reflect.DeepEqual(first, got) {
			t.Fatalf("not deterministic: %v vs %v", first, got)
		}
	}
}

// Many fragments in one tag: findings stay sorted by path, each with its own
// code, whatever the order they are listed in.
func TestFragmentReasonsOrdering(t *testing.T) {
	alpha := crd("Alpha", "v1beta1", "v1")
	files := map[string]string{"deploy/kustomization.yaml": synthKustomization}
	var want []string
	for i := 0; i < 12; i++ {
		p := fmt.Sprintf("deploy/patches/p%02d.yaml", i)
		files[p] = strings.ReplaceAll(cainjectionFragment, "alphas.", "gammas.")
		want = append(want, p)
		q := fmt.Sprintf("other/patches/q%02d.yaml", i)
		files[q] = webhookFragment
		want = append(want, q)
	}
	_, proof := classPair(t, alpha, alpha, files, files)
	var got, reasons []string
	for _, f := range proof.To.Scan.Findings {
		if strings.HasSuffix(f.Path, ".yaml") && (strings.HasPrefix(f.Path, "deploy/patches/") || strings.HasPrefix(f.Path, "other/patches/")) {
			got = append(got, f.Path)
			reasons = append(reasons, f.Reason)
		}
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("findings %v, want %v", got, want)
	}
	for i, p := range got {
		wantReason := notListed
		if strings.HasPrefix(p, "other/") {
			wantReason = notUnderDir
		}
		if reasons[i] != wantReason {
			t.Fatalf("%s: reason %q, want %q", p, reasons[i], wantReason)
		}
	}
}

// The combinations the scan really records: never more than two codes, and
// never not-strict together with the name code.
func TestFragmentReasonCombinations(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range fragmentReasonCases {
		_, proof := fragmentPair(t, c.path, c.file)
		f := findingOf(proof.To.Scan, c.path)
		if f == nil {
			t.Fatalf("%s: no finding", c.name)
		}
		parts := strings.Split(f.Reason, "+")
		if len(parts) > 2 {
			t.Fatalf("%s: %d codes in %q", c.name, len(parts), f.Reason)
		}
		if slices.Contains(parts, notStrict) && slices.Contains(parts, notListed) {
			t.Fatalf("%s: not-strict with the name code: %q", c.name, f.Reason)
		}
		seen[f.Reason] = true
	}
	want := []string{ReasonFragment, notStrict, notStrict + "+" + notUnderDir, notUnderDir, notListed, notUnderDir + "+" + notListed}
	for _, w := range want {
		if !seen[w] {
			t.Fatalf("combination %q not exercised: %v", w, seen)
		}
	}
	if len(seen) != len(want) {
		t.Fatalf("unexpected combinations: %v", seen)
	}
}

// An accepted transformer configuration carries its own code, not the one
// for a file that defines no definition, and does not block.
func TestKustomizeConfigReason(t *testing.T) {
	alpha := crd("Alpha", "v1beta1", "v1")
	files := map[string]string{"deploy/kustomization.yaml": synthKustomization, "deploy/kustomizeconfig.yaml": kustomizeConfig}
	p, proof := classPair(t, alpha, alpha, files, files)
	if p.Status != extract.PairDerived || proof.Completeness == nil || !proof.Completeness.Attestable {
		t.Fatalf("outcome changed: %s %q", p.Status, p.Reason)
	}
	for _, inv := range []*Inventory{proof.From, proof.To} {
		f := findingOf(inv.Scan, "deploy/kustomizeconfig.yaml")
		if f == nil || f.Class != ClassKustomizeConfig || f.Reason != ReasonKustomizeConfig || f.blocks() {
			t.Fatalf("%s: finding %+v", inv.Tag, f)
		}
	}
	// A refused configuration keeps its own, different code.
	bad := map[string]string{"deploy/kustomization.yaml": synthKustomization, "deploy/kustomizeconfig.yaml": strings.Replace(kustomizeConfig, "path: spec/conversion/webhook/clientConfig/service/namespace", "path: spec/versions/name", 1)}
	_, proof = classPair(t, alpha, alpha, bad, bad)
	f := findingOf(proof.To.Scan, "deploy/kustomizeconfig.yaml")
	if f == nil || f.Reason != ReasonConfigRefused || !f.blocks() {
		t.Fatalf("refused configuration: %+v", f)
	}
}
