// SPDX-License-Identifier: AGPL-3.0-only

package extractpack_test

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract/extractpack"
)

// Rendering a pack that a run adds nothing to reproduces the shipped packs
// byte for byte, so an apply never reformats what it does not change.
func TestRenderReproducesShippedPacks(t *testing.T) {
	for _, family := range []string{"cncf", "community"} {
		pack := packDir(t, family)
		raw, _ := os.ReadFile(pack)
		p, err := extractpack.ParsePack(raw)
		if err != nil {
			t.Fatal(err)
		}
		out, err := p.Render()
		if err != nil || !bytes.Equal(out, raw) {
			t.Fatalf("%s: render differs from the shipped pack (%v)", family, err)
		}
		if err := extractpack.AdmitFiles(pack, raw); err != nil {
			t.Fatalf("%s: the shipped pack is not admitted: %v", family, err)
		}
	}
}

// Without the real fact registry knowing a run's facts, the engine loader
// refuses the merged pack: the apply fails, names the facts, and the pack
// file is untouched. The feature-gate run is rewritten (digests following)
// over the kubelet flag-set fact, which no published rule consumes and the
// registry therefore does not declare.
func TestApplyRefusedByTheEngineLoader(t *testing.T) {
	for _, c := range []kase{cases[0]} {
		run := runDir(t, c, derivedAt)
		renameRunFacts(t, run, "_feature_gates_set", "_flags_set")
		pack := prunedPack(t, "cncf", run)
		pre, _ := os.ReadFile(pack)
		_, err := extractpack.Apply(extractpack.Options{PackPath: pack, RunDir: run})
		if !errors.Is(err, extractpack.ErrAdmission) || !strings.Contains(err.Error(), "hint:") {
			t.Fatalf("%s: %v", c.name, err)
		}
		assertUnchanged(t, pack, pre)
	}
}

// The feature-gate run is admitted by the real engine loader now that the
// registry declares the five feature-gate set facts it constrains.
func TestApplyOfTheFeatureGateRunAdmittedByTheEngineLoader(t *testing.T) {
	c := cases[0]
	run := runDir(t, c, derivedAt)
	ids := ruleIDs(t, run)
	pack := prunedPack(t, "cncf", run)
	rep, err := extractpack.Apply(extractpack.Options{PackPath: pack, RunDir: run})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Added) != len(ids) || !rep.Changed {
		t.Fatalf("%+v", rep)
	}
	raw, _ := os.ReadFile(pack)
	if err := extractpack.AdmitFiles(pack, raw); err != nil {
		t.Fatalf("the engine loader refuses the result: %v", err)
	}
}

// A run the engine loader admits: the served-API run without the one rule
// whose fact is not registered, and without its attestations (a line
// attestation must list every rule of its scope).
func TestApplyAdmittedByTheEngineLoader(t *testing.T) {
	c := cases[1]
	run := runDir(t, c, derivedAt)
	ids := ruleIDs(t, run)
	trimRun(t, run, map[string]bool{"kubernetes.served-api-removal.authentication-k8s-io-v1beta1.1-32-0-to-1-33-0": true}, true)
	pack := prunedPack(t, "cncf", run)
	rep, err := extractpack.Apply(extractpack.Options{PackPath: pack, RunDir: run})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Added) != len(ids)-1 || !rep.Changed || rep.SchemaFrom != rep.SchemaTo {
		t.Fatalf("%+v", rep)
	}
	raw, _ := os.ReadFile(pack)
	if err := extractpack.AdmitFiles(pack, raw); err != nil {
		t.Fatalf("the engine loader refuses the result: %v", err)
	}
}

// A community pack takes the same path: nothing in a CNCF-shaped set rule
// is admitted there, and the failure leaves the file alone.
func TestApplyToCommunityPackIsRefused(t *testing.T) {
	run := runDir(t, cases[2], derivedAt)
	pack := packDir(t, "community")
	pre, _ := os.ReadFile(pack)
	if _, err := extractpack.Apply(extractpack.Options{PackPath: pack, RunDir: run}); !errors.Is(err, extractpack.ErrAdmission) {
		t.Fatalf("%v", err)
	}
	assertUnchanged(t, pack, pre)
}

// Since the CRD facts are registered, the Strimzi run is admitted by the real
// engine loader untagged, with its schema moved to the level the loader wants.
func TestApplyStrimziAdmittedByTheEngineLoader(t *testing.T) {
	run := runDir(t, cases[2], derivedAt)
	pack := prunedPack(t, "cncf", run)
	rep, err := extractpack.Apply(extractpack.Options{PackPath: pack, RunDir: run})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Added) != len(ruleIDs(t, run)) || !rep.Changed {
		t.Fatalf("%+v", rep)
	}
	raw, _ := os.ReadFile(pack)
	if err := extractpack.AdmitFiles(pack, raw); err != nil {
		t.Fatal(err)
	}
	t.Logf("schema %s -> %s", rep.SchemaFrom, rep.SchemaTo)
}
