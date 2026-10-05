// SPDX-License-Identifier: AGPL-3.0-only

package extractpack_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/extractcli"
	"github.com/prufyx/prufyx/cli/internal/extract/supersedefixture"
)

var derivedAt = time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)

// kase is one extractor over its frozen fixture.
type kase struct {
	name, id, fixture string
}

var cases = []kase{
	{"feature-gates", "k8s.feature-gate-removal", "../k8sfeaturegates/testdata/fixture"},
	{"served-apis", "k8s.served-api-removal", "../k8sservedapis/testdata/fixture"}, // gitleaks:allow (fixture name, not a secret)
	{"strimzi", "crd.version-removal.strimzi", "../crdversions/testdata/strimzi"},
	{"argo-cd", "crd.version-removal.argo-cd", "../crdversions/testdata/fixture"},
}

// runDir runs the extractor over its fixture and writes the run directory,
// exactly as "extract run" does.
func runDir(t *testing.T, c kase, at time.Time) string {
	t.Helper()
	spec, ok := extractcli.Catalog()[c.id]
	if !ok {
		t.Fatalf("no extractor %s", c.id)
	}
	repo, err := extract.ParseRepo(spec.Repo)
	if err != nil {
		t.Fatal(err)
	}
	src := extract.FixtureReader{Root: c.fixture}
	out, err := extract.Run(context.Background(), spec.New(0), src, src, extract.Options{Repo: repo, DerivedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "run")
	if err := out.Write(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}

// packDir copies a real pack and the registry files the loader needs beside
// it into a new directory and returns the pack path.
func packDir(t *testing.T, family string) string {
	t.Helper()
	src, files := "../../cncfcheck/data/", []string{"rules.json", "landscape-projects.json", "priority-portfolio.json"}
	if family == "community" {
		src, files = "../../projectcheck/data/", []string{"rules.json", "projects.json"}
	}
	dir := t.TempDir()
	for _, f := range files {
		b, err := os.ReadFile(src + f)
		if err != nil {
			t.Fatal(err)
		}
		if family != "community" && f == "rules.json" {
			// The pack as it was before the served-API supersede, so that
			// the reviewed Kubernetes rules exist to be replaced.
			if b, err = supersedefixture.Reviewed(b); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, f), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "rules.json")
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatal(err)
	}
}

func writeCanon(t *testing.T, path string, v any) []byte {
	t.Helper()
	raw, err := extract.Canonical(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return raw
}

// trimRun rewrites a run directory so the extractor looks as if it no longer
// produced the given rules: they leave candidates.json and every pair's rule
// list, and the manifest's digests follow. With dropAttestations the
// attestation file goes too. The result is a consistent run.
func trimRun(t *testing.T, dir string, drop map[string]bool, dropAttestations bool) {
	t.Helper()
	var entries []map[string]any
	readJSON(t, filepath.Join(dir, "candidates.json"), &entries)
	kept := entries[:0]
	for _, e := range entries {
		if !drop[e["rule"].(map[string]any)["id"].(string)] {
			kept = append(kept, e)
		}
	}
	cand := writeCanon(t, filepath.Join(dir, "candidates.json"), kept)
	var m map[string]any
	readJSON(t, filepath.Join(dir, "manifest.json"), &m)
	for _, p := range m["pairs"].([]any) {
		pair := p.(map[string]any)
		var rules []any
		for _, r := range pair["rules"].([]any) {
			if !drop[r.(string)] {
				rules = append(rules, r)
			}
		}
		if rules == nil {
			rules = []any{}
		}
		pair["rules"] = rules
	}
	outs := m["outputs"].(map[string]any)
	outs["candidates.json"] = digestOf(cand)
	if dropAttestations {
		delete(outs, "attestations.json")
		_ = os.Remove(filepath.Join(dir, "attestations.json"))
	}
	writeCanon(t, filepath.Join(dir, "manifest.json"), m)
}

// ruleIDs lists the rule ids of a run directory.
func ruleIDs(t *testing.T, dir string) []string {
	t.Helper()
	var entries []map[string]any
	readJSON(t, filepath.Join(dir, "candidates.json"), &entries)
	var ids []string
	for _, e := range entries {
		ids = append(ids, e["rule"].(map[string]any)["id"].(string))
	}
	sort.Strings(ids)
	return ids
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameBytes(a, b []byte) bool { return bytes.Equal(a, b) }

func admitAll(string, []byte) error { return nil }

// factIDs lists the fact ids the rules of a run constrain.
func factIDs(t *testing.T, run string) map[string]bool {
	t.Helper()
	var entries []map[string]any
	readJSON(t, filepath.Join(run, "candidates.json"), &entries)
	out := map[string]bool{}
	for _, e := range entries {
		out[constrainedFact(e)] = true
	}
	return out
}

func constrainedFact(e map[string]any) string {
	r := e["rule"].(map[string]any)
	for _, k := range []string{"condition", "setCondition"} {
		if c, ok := r[k].(map[string]any); ok {
			if id, ok := c["factId"].(string); ok {
				return id
			}
		}
	}
	return ""
}

// prunedPack is packDir with the reviewed rules that collide with the run
// removed: those constraining a fact the run constrains, and those with the
// same component and target version as a rule of the run (an attestation
// must list every rule of its scope, and the engine refuses two rules for
// one fact). The knowledge gate's own tests do the same.
func prunedPack(t *testing.T, family, run string) string {
	t.Helper()
	pack := packDir(t, family)
	facts := factIDs(t, run)
	scopes := map[string]bool{}
	var entries []map[string]any
	readJSON(t, filepath.Join(run, "candidates.json"), &entries)
	for _, e := range entries {
		sub := e["rule"].(map[string]any)["subject"].(map[string]any)
		scopes[sub["component"].(string)+"\x00"+sub["to"].(string)] = true
	}
	mustModifyPack(t, pack, func(es []map[string]any) []map[string]any {
		var kept []map[string]any
		for _, e := range es {
			sub, _ := e["rule"].(map[string]any)["subject"].(map[string]any)
			if facts[constrainedFact(e)] || (sub != nil && scopes[asString(sub["component"])+"\x00"+asString(sub["to"])]) {
				continue
			}
			kept = append(kept, e)
		}
		return kept
	})
	return pack
}

func asString(v any) string { s, _ := v.(string); return s }
