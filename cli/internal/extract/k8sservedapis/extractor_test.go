// SPDX-License-Identifier: AGPL-3.0-only

package k8sservedapis

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
	"github.com/prufyx/prufyx/cli/internal/extract"
)

var update = flag.Bool("update", false, "rewrite the golden files")

const fixtureRoot = "testdata/fixture"

var derivedAt = time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)

type pinnedSource interface {
	extract.PinnedReader
	extract.TagSource
}

func k8sRepo(t *testing.T) extract.RepoRef {
	t.Helper()
	r, err := extract.ParseRepo(Repo)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func runOn(t *testing.T, r pinnedSource) *extract.Output {
	t.Helper()
	out, err := extract.Run(context.Background(), New(0), r, r, extract.Options{Repo: k8sRepo(t), DerivedAt: derivedAt})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func fixtureOutput(t *testing.T) *extract.Output {
	t.Helper()
	return runOn(t, extract.FixtureReader{Root: fixtureRoot})
}

func proofOf(t *testing.T, p extract.PairRecord) pairProof {
	t.Helper()
	raw, err := json.Marshal(p.Proof)
	if err != nil {
		t.Fatal(err)
	}
	var proof pairProof
	if err := json.Unmarshal(raw, &proof); err != nil {
		t.Fatal(err)
	}
	return proof
}

func pairTo(t *testing.T, out *extract.Output, to string) extract.PairRecord {
	t.Helper()
	for _, p := range out.Manifest.Pairs {
		if p.ToTag == to {
			return p
		}
	}
	t.Fatalf("no pair to %s", to)
	return extract.PairRecord{}
}

// Removals across two eras, quiet lines and a removal without an adapter fact.
func TestFixtureRemovalsAcrossEras(t *testing.T) {
	out := fixtureOutput(t)
	type want struct {
		to       string
		status   string
		removals []string
		rules    int
	}
	for _, w := range []want{
		{"v1.25.0", extract.PairDerived, []string{"autoscaling/v2beta1:HorizontalPodAutoscaler", "batch/v1beta1:CronJob", "policy/v1beta1:PodDisruptionBudget,PodSecurityPolicy"}, 4},
		{"v1.31.0", extract.PairDerived, nil, 0},
		{"v1.32.0", extract.PairDerived, []string{"flowcontrol.apiserver.k8s.io/v1beta3:FlowSchema,PriorityLevelConfiguration"}, 1},
		{"v1.33.0", extract.PairDerived, []string{"authentication.k8s.io/v1beta1:SelfSubjectReview"}, 1},
	} {
		p := pairTo(t, out, w.to)
		proof := proofOf(t, p)
		var got []string
		for _, r := range proof.Removals {
			got = append(got, r.Group+"/"+r.Version+":"+strings.Join(r.Kinds, ","))
		}
		if p.Status != w.status || !slices.Equal(got, w.removals) || len(p.Rules) != w.rules {
			t.Fatalf("%s: %s %v rules %d, want %v rules %d", w.to, p.Status, got, len(p.Rules), w.removals, w.rules)
		}
		if w.to == "v1.31.0" && proof.Removals == nil {
			t.Fatal("a quiet line must record an empty removal list, not null")
		}
	}
	p25 := proofOf(t, pairTo(t, out, "v1.25.0"))
	if !slices.Equal(p25.Unobserved, []string{"batch/v1beta1/JobTemplate", "policy/v1beta1/Eviction"}) || len(p25.ListInconsistencies) != 1 {
		t.Fatalf("1.25 notes: %v %v", p25.Unobserved, p25.ListInconsistencies)
	}
	for _, r := range p25.Removals {
		if r.Group == "policy" && (len(r.Facts) != 2 || len(r.Facts[0].Replacements)+len(r.Facts[1].Replacements) != 1) {
			t.Fatalf("policy replacements are per fact: %+v", r.Facts)
		}
	}
	p33 := proofOf(t, pairTo(t, out, "v1.33.0"))
	if len(p33.Removals[0].NoFactKinds) != 0 || len(p33.Removals[0].Facts) != 1 || p33.Removals[0].Replacements[0] != "v1" {
		t.Fatalf("1.33: %+v", p33.Removals[0])
	}
	p32 := proofOf(t, pairTo(t, out, "v1.32.0"))
	if len(p32.AlphaGone) == 0 {
		t.Fatal("alpha kinds that left the specification are recorded")
	}
}

func normalize(t *testing.T, files map[string][]byte) map[string][]byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(files[extract.FileManifest], &m); err != nil {
		t.Fatal(err)
	}
	code := m["extractor"].(map[string]any)["codeDigest"].(string)
	out := map[string][]byte{}
	for name, data := range files {
		out[name] = bytes.ReplaceAll(data, []byte(code), []byte("sha256:CODE"))
	}
	m["codeFiles"] = []any{}
	m["extractor"].(map[string]any)["codeDigest"] = "sha256:CODE"
	outputs := m["outputs"].(map[string]any)
	for name := range outputs {
		outputs[name] = "sha256:OUTPUT"
	}
	raw, err := extract.Canonical(m)
	if err != nil {
		t.Fatal(err)
	}
	out[extract.FileManifest] = raw
	return out
}

// TestGoldenFixtureOutput pins every output byte (the code digest, which
// changes with any source edit, masked). Run with -update after a deliberate
// output change, and bump Version.
func TestGoldenFixtureOutput(t *testing.T) {
	files, err := fixtureOutput(t).Files()
	if err != nil {
		t.Fatal(err)
	}
	got := normalize(t, files)
	dir := "testdata/golden"
	if *update {
		_ = os.RemoveAll(dir)
		for name, data := range got {
			p := filepath.Join(dir, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	var onDisk, names []string
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			onDisk = append(onDisk, filepath.ToSlash(rel))
		}
		return nil
	})
	for name := range got {
		names = append(names, name)
	}
	sort.Strings(names)
	sort.Strings(onDisk)
	if !slices.Equal(names, onDisk) {
		t.Fatalf("golden file set %v, output %v", onDisk, names)
	}
	for _, name := range names {
		want, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(want, got[name]) {
			t.Fatalf("%s differs from the golden file (run with -update after a deliberate change)", name)
		}
	}
}

func TestReproducible(t *testing.T) {
	a, err := fixtureOutput(t).Files()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		b, err := fixtureOutput(t).Files()
		if err != nil {
			t.Fatal(err)
		}
		if len(a) != len(b) {
			t.Fatal("file sets differ")
		}
		for name := range a {
			if !bytes.Equal(a[name], b[name]) {
				t.Fatalf("run %d: %s differs", i, name)
			}
		}
	}
}

func sha(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Every cited source is a file read at that commit with the digest of its
// bytes, the lifecycle span holds the removed methods of the rule's kinds,
// and every fixture file is listed in PROVENANCE.txt.
func TestProvenanceIsComplete(t *testing.T) {
	out := fixtureOutput(t)
	for _, e := range out.Entries {
		if e.Rule.Evidence.Basis != "mechanical" || e.Rule.Evidence.Extractor.ID != ID || len(e.Rule.Evidence.Sources) > 3 {
			t.Fatalf("%s: evidence %+v", e.Rule.ID, e.Rule.Evidence)
		}
		for _, s := range e.Rule.Evidence.Sources {
			path := strings.TrimPrefix(s.URL, "https://github.com/kubernetes/kubernetes/blob/"+s.Revision+"/")
			data, err := os.ReadFile(filepath.Join(fixtureRoot, Repo, "commits", s.Revision, filepath.FromSlash(path)))
			if err != nil || "sha256:"+sha(data) != s.ContentDigest {
				t.Fatalf("%s cites %s with a wrong digest (%v)", e.Rule.ID, path, err)
			}
			if strings.HasPrefix(s.ID, "lifecycle-") {
				lines := strings.Split(string(data), "\n")
				span := strings.Join(lines[s.StartLine-1:s.EndLine], "\n")
				for _, k := range kindsOf(e.Description) {
					if !strings.Contains(span, "(in *"+k+") APILifecycleRemoved()") {
						t.Fatalf("%s: span %d-%d lacks the removed method of %s", e.Rule.ID, s.StartLine, s.EndLine, k)
					}
				}
			}
		}
	}
	prov, err := os.ReadFile(filepath.Join(fixtureRoot, "PROVENANCE.txt"))
	if err != nil {
		t.Fatal(err)
	}
	_ = filepath.WalkDir(fixtureRoot, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Base(p) == "PROVENANCE.txt" || filepath.Base(p) == "tags.json" {
			return nil
		}
		rel := filepath.ToSlash(p)
		rel = rel[strings.Index(rel, "/commits/")+len("/commits/"):]
		commit, path, _ := strings.Cut(rel, "/")
		if !strings.Contains(string(prov), commit+" ") || !strings.Contains(string(prov), path) {
			t.Errorf("%s is not listed in PROVENANCE.txt", rel)
		}
		if strings.HasSuffix(p, ".go") && !strings.Contains(string(mustRead(t, p)), "Licensed under the Apache License") {
			t.Errorf("%s lacks the upstream license header", p)
		}
		return nil
	})
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// kindsOf extracts the kinds of a rule description ("stops serving A or B through").
func kindsOf(desc string) []string {
	_, rest, _ := strings.Cut(desc, "stops serving ")
	list, _, _ := strings.Cut(rest, " through ")
	list = strings.ReplaceAll(list, " or ", ", ")
	return strings.Split(list, ", ")
}

// The rules have the shape of the reviewed API-removal rules in the pack:
// same facts, same ranges and range bases, same anchor, for the rules both
// derive.
func TestRulesHaveTheReviewedShape(t *testing.T) {
	raw, err := os.ReadFile("../../cncfcheck/data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	var pack struct {
		Entries []extract.Entry `json:"entries"`
	}
	if err := json.Unmarshal(raw, &pack); err != nil {
		t.Fatal(err)
	}
	byFact := map[string]extract.Entry{}
	for _, e := range pack.Entries {
		if e.Rule.Condition != nil && strings.HasSuffix(e.Rule.Condition.FactID, "_removed_gvk_present") {
			byFact[e.Rule.Condition.FactID] = e
		}
	}
	checked := 0
	for _, e := range fixtureOutput(t).Entries {
		rev, ok := byFact[e.Rule.Condition.FactID]
		if !ok {
			t.Fatalf("%s: fact %s is not a reviewed removal fact", e.Rule.ID, e.Rule.Condition.FactID)
		}
		a, b := e.Rule, rev.Rule
		if a.Operator != b.Operator || a.Subject != b.Subject || *a.Condition.BoolValue != *b.Condition.BoolValue || a.Condition.Side != b.Condition.Side {
			t.Fatalf("%s differs from %s in operator, subject or condition", a.ID, b.ID)
		}
		if b.Range != nil {
			if a.Range == nil || a.Range.From != b.Range.From || a.Range.To != b.Range.To {
				t.Fatalf("%s: range %+v, reviewed %+v", a.ID, a.Range, b.Range)
			}
			for i := range b.Range.Bounds {
				if a.Range.Bounds[i].Bound != b.Range.Bounds[i].Bound || a.Range.Bounds[i].Basis != b.Range.Bounds[i].Basis {
					t.Fatalf("%s: bound %d", a.ID, i)
				}
			}
		}
		if len(a.Evidence.Sources) > 8 {
			t.Fatalf("%s cites %d sources", a.ID, len(a.Evidence.Sources))
		}
		checked++
	}
	if checked != 6 {
		t.Fatalf("checked %d rules", checked)
	}
}

// The fact table is the adapter's: same facts, and the same facts per line.
func TestFactsMatchTheAdapter(t *testing.T) {
	var ours []string
	for _, f := range AdapterFacts() {
		ours = append(ours, f.Fact)
	}
	sort.Strings(ours)
	ours = slices.Compact(ours)
	if all := cncfprepare.KubernetesRemovedAPIAllFacts(); !slices.Equal(ours, all) {
		t.Fatalf("extractor facts %v, adapter facts %v", ours, all)
	}
	for line := 22; line <= 37; line++ {
		var mine []string
		for _, f := range AdapterFacts() {
			if f.Line == line && line != 32 {
				mine = append(mine, f.Fact)
			}
		}
		from, to := "1."+strconv.Itoa(line-1)+".0", "1."+strconv.Itoa(line)+".0"
		got := cncfprepare.KubernetesRemovedAPIFacts(from, to)
		sort.Strings(got)
		sort.Strings(mine)
		if line != 32 && !slices.Equal(got, mine) {
			t.Fatalf("line %d: extractor %v, adapter %v", line, mine, got)
		}
	}
}

func TestPairsUseOnlyFinalConsecutiveMinorTags(t *testing.T) {
	sha := func(n int) string {
		return strings.Repeat("a", 40-len(strings.Repeat("0", n))) + strings.Repeat("0", n)
	}
	index := extract.ReleaseIndex{Repo: k8sRepo(t), Tags: []extract.Tag{
		{Name: "v1.18.0", Commit: sha(1)}, {Name: "v1.19.0", Commit: sha(2)}, {Name: "v1.20.0", Commit: sha(3)},
		{Name: "v1.21.0", Commit: sha(4)}, {Name: "v1.21.1", Commit: sha(5)}, {Name: "v1.22.0-rc.0", Commit: sha(6)},
		{Name: "v1.23.0", Commit: sha(7)}, {Name: "v2.20.0", Commit: sha(8)}, {Name: "v1.24.0", Commit: "short"},
	}}
	var keys []string
	for _, p := range New(0).Pairs(index) {
		keys = append(keys, p.Key())
	}
	if !slices.Equal(keys, []string{"1.19.0->1.20.0", "1.20.0->1.21.0"}) {
		t.Fatalf("pairs %v", keys)
	}
}

// ---- withholding ----

func copyFixture(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir(fixtureRoot, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(fixtureRoot, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.Create(target)
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func commitDir(root string, minor int) string {
	return filepath.Join(root, "github.com/kubernetes/kubernetes/commits", fmt.Sprintf("%040d", (100+minor)*100))
}

// withheldAfter mutates the fixture (edit gets the directories of the
// earlier and the later commit of the pair minor -> minor+1) and returns the
// reason that pair is withheld.
func withheldAfter(t *testing.T, minor int, edit func(from, to string)) string {
	t.Helper()
	root := copyFixture(t)
	edit(commitDir(root, minor), commitDir(root, minor+1))
	out := runOn(t, extract.FixtureReader{Root: root})
	p := pairTo(t, out, "v1."+strconv.Itoa(minor+1)+".0")
	if p.Status != extract.PairWithheld || len(p.Rules) != 0 {
		t.Fatalf("pair to 1.%d: %s %v", minor+1, p.Status, p.Rules)
	}
	for _, e := range out.Entries {
		if e.Rule.Subject.To == p.To {
			t.Fatalf("withheld pair still has rule %s", e.Rule.ID)
		}
	}
	return p.Reason
}

func editFile(t *testing.T, path string, edit func(string) string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(edit(string(data))), 0o644); err != nil {
		t.Fatal(err)
	}
}

const spec = "api/openapi-spec/swagger.json"

func TestUnparseableAndMissingInputsWithhold(t *testing.T) {
	life := "staging/src/k8s.io/api/batch/v1beta1/zz_generated.prerelease-lifecycle.go"
	for name, c := range map[string]struct {
		minor int
		edit  func(dir string)
		want  string
	}{
		"syntax error": {24, func(d string) {
			editFile(t, filepath.Join(d, life), func(s string) string { return s + "\nfunc (" })
		}, "zz_generated.prerelease-lifecycle.go"},
		"computed release": {24, func(d string) {
			editFile(t, filepath.Join(d, life), func(s string) string {
				return strings.Replace(s, "return 1, 25", "return 1, 24+1", 1)
			})
		}, "not the generated form"},
		"wrong package": {24, func(d string) {
			editFile(t, filepath.Join(d, life), func(s string) string { return strings.Replace(s, "package v1beta1", "package v1beta2", 1) })
		}, "not the version directory"},
		"no group name": {24, func(d string) {
			editFile(t, filepath.Join(d, filepath.Dir(life), "register.go"), func(s string) string { return strings.Replace(s, "const GroupName", "const Group", 1) })
		}, "no GroupName"},
		"register missing": {24, func(d string) {
			if err := os.Remove(filepath.Join(d, filepath.Dir(life), "register.go")); err != nil {
				t.Fatal(err)
			}
		}, "no register.go"},
		"spec missing": {24, func(d string) {
			if err := os.Remove(filepath.Join(d, spec)); err != nil {
				t.Fatal(err)
			}
		}, "does not exist"},
		"spec truncated": {24, func(d string) {
			editFile(t, filepath.Join(d, spec), func(s string) string { return s[:len(s)/2] })
		}, "swagger.json"},
		"api root missing": {24, func(d string) {
			if err := os.RemoveAll(filepath.Join(d, "staging/src/k8s.io/api")); err != nil {
				t.Fatal(err)
			}
		}, "does not exist"},
		"no lifecycle files": {24, func(d string) {
			_ = filepath.WalkDir(d, func(p string, e os.DirEntry, err error) error {
				if err == nil && !e.IsDir() && strings.HasSuffix(p, "zz_generated.prerelease-lifecycle.go") {
					_ = os.Remove(p)
				}
				return nil
			})
		}, "no lifecycle files"},
	} {
		t.Run(name, func(t *testing.T) {
			reason := withheldAfter(t, c.minor, func(from, _ string) { c.edit(from) })
			if !strings.Contains(reason, c.want) {
				t.Fatalf("reason %q lacks %q", reason, c.want)
			}
		})
	}
}

func TestCrossCheckDisagreementWithholds(t *testing.T) {
	for name, c := range map[string]struct {
		edit func(from, to string)
		want string
	}{
		"declared removal missing from the earlier spec": {func(from, to string) {
			editFile(t, filepath.Join(to, spec), func(s string) string {
				return strings.Replace(s, `"definitions": {`, `"definitions": {
    "x.CronJob": {"x-kubernetes-group-version-kind": [{"group": "batch", "kind": "CronJob", "version": "v1beta1"}]},`, 1)
			})
			editFile(t, filepath.Join(from, spec), func(s string) string {
				return regexp.MustCompile(`"kind": "CronJob",(\s+)"version": "v1beta1"`).ReplaceAllString(s, `"kind": "CronJobX",${1}"version": "v1beta1"`)
			})
		}, "batch/v1beta1/CronJob is declared removed in 1.25 but is not in the v1.24.0 specification"},
		"declared removal still in the later spec": {func(_, to string) {
			editFile(t, filepath.Join(to, spec), func(s string) string {
				return strings.Replace(s, `"definitions": {`, `"definitions": {
    "x.CronJob": {"x-kubernetes-group-version-kind": [{"group": "batch", "kind": "CronJob", "version": "v1beta1"}]},`, 1)
			})
		}, "batch/v1beta1/CronJob is declared removed in 1.25 but is still in the v1.25.0 specification"},
		"kind disappears without a lifecycle removal": {func(from, _ string) {
			editFile(t, filepath.Join(from, spec), func(s string) string {
				return strings.Replace(s, `"definitions": {`, `"definitions": {
    "x.Gone": {"x-kubernetes-group-version-kind": [{"group": "batch", "kind": "Gone", "version": "v1"}]},`, 1)
			})
		}, "batch/v1/Gone is in the v1.24.0 specification and gone from v1.25.0, but no lifecycle file removes it in 1.25"},
	} {
		t.Run(name, func(t *testing.T) {
			if reason := withheldAfter(t, 24, c.edit); !strings.Contains(reason, c.want) {
				t.Fatalf("reason %q lacks %q", reason, c.want)
			}
		})
	}
}

// A reader that fails (other than not-found) aborts the run: it is not a
// withheld pair.
type failingReader struct{ extract.FixtureReader }

func (f failingReader) Read(repo extract.RepoRef, commit, p string) ([]byte, error) {
	if strings.HasSuffix(p, "swagger.json") {
		return nil, errors.New("disk on fire")
	}
	return f.FixtureReader.Read(repo, commit, p)
}

func TestUnreadableFileAborts(t *testing.T) {
	r := failingReader{extract.FixtureReader{Root: fixtureRoot}}
	if _, err := extract.Run(context.Background(), New(0), r, r, extract.Options{Repo: k8sRepo(t), DerivedAt: derivedAt}); err == nil || !strings.Contains(err.Error(), "disk on fire") {
		t.Fatalf("err %v", err)
	}
}

func TestOracleAgreesOnFixture(t *testing.T) {
	out := fixtureOutput(t)
	dir := filepath.Join(t.TempDir(), "run")
	if err := out.Write(dir); err != nil {
		t.Fatal(err)
	}
	expected := mustRead(t, "testdata/oracle-fixture.json")
	diffs, err := Oracle(dir, expected)
	if err != nil || len(diffs) != 0 {
		t.Fatalf("oracle: %v %v", err, diffs)
	}
	var exp Expected
	if err := json.Unmarshal(expected, &exp); err != nil {
		t.Fatal(err)
	}
	exp.Removals[0].Kinds = []string{"Nope"}
	exp.Removals = append([]ExpectedRemoval{exp.Removals[0]}, exp.Removals[2:]...)
	exp.Removals = append(exp.Removals, ExpectedRemoval{Line: "1.99", Group: "x", Version: "v1"}, ExpectedRemoval{Line: "1.25", Group: "apps", Version: "v1beta1"})
	raw, _ := json.Marshal(exp)
	diffs, err = Oracle(dir, raw)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(diffs, "\n")
	for _, want := range []string{"KINDS 1.25", "MISSING 1.99 x/v1", "MISSING 1.25 apps/v1beta1", "EXTRA 1.25"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in\n%s", want, joined)
		}
	}
}
