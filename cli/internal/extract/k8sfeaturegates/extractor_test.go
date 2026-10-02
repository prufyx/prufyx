// SPDX-License-Identifier: AGPL-3.0-only

package k8sfeaturegates

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
	"github.com/prufyx/prufyx/cli/internal/extract"
)

var update = flag.Bool("update", false, "rewrite the golden files")

const fixtureRoot = "testdata/fixture"

var derivedAt = time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)

func k8sRepo(t *testing.T) extract.RepoRef {
	t.Helper()
	r, err := extract.ParseRepo(Repo)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func runOn(t *testing.T, r interface {
	extract.PinnedReader
	extract.TagSource
}, concurrency int) *extract.Output {
	t.Helper()
	out, err := extract.Run(context.Background(), New(concurrency), r, r, extract.Options{Repo: k8sRepo(t), DerivedAt: derivedAt})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func fixtureOutput(t *testing.T, concurrency int) *extract.Output {
	t.Helper()
	return runOn(t, extract.FixtureReader{Root: fixtureRoot}, concurrency)
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

func removedNames(t *testing.T, p extract.PairRecord) []string {
	t.Helper()
	var names []string
	for _, g := range proofOf(t, p).Removed {
		names = append(names, g.Name)
	}
	return names
}

// The fixture holds trimmed real registries of three formats:
//
//   - 1.22 -> 1.23: unversioned FeatureSpec maps; pkg/features relists the
//     generic API server gates by selector;
//   - 1.31 -> 1.32: constants in kube_features.go, versioned specs in
//     versioned_kube_features.go, client-go gates in their own Feature type,
//     upstream's generated lists under test/featuregates_linter;
//   - 1.36 -> 1.37: VersionedSpecs only, a dependency map, component-base
//     logs and zpages gates, generated lists under test/compatibility_lifecycle.
func TestFixtureRemovalsAcrossRegistryEras(t *testing.T) {
	out := fixtureOutput(t, 0)
	want := map[string][]string{
		"1.23.0": {"BoundServiceAccountTokenVolume", "StartupProbe"},
		"1.32.0": {"CloudDualStackNodeIPs", "HPAContainerMetrics", "KMSv2", "ServerSideApply"},
		"1.37.0": {"APIServerTracing", "AnyVolumeDataSource", "AuthorizeWithSelectors", "SidecarContainers"},
	}
	if len(out.Manifest.Pairs) != 3 {
		t.Fatalf("pairs %+v", out.Manifest.Pairs)
	}
	for _, p := range out.Manifest.Pairs {
		if p.Status != extract.PairDerived {
			t.Fatalf("%s withheld: %s", p.To, p.Reason)
		}
		if got := removedNames(t, p); !slices.Equal(got, want[p.To]) {
			t.Fatalf("%s removed %v, want %v", p.To, got, want[p.To])
		}
		if len(p.Rules) != len(Components) {
			t.Fatalf("%s: %d rules", p.To, len(p.Rules))
		}
	}
	// One rule per component per pair, each forbidding exactly the removed
	// gates of its pair on its own component's set.
	for _, e := range out.Entries {
		sc := e.Rule.SetCondition
		if !slices.Equal(sc.Members, want[e.Rule.Subject.To]) || e.Rule.Operator != "forbid_set_member" || sc.Side != "proposed" || e.RequiredFacts[0].ID != sc.FactID {
			t.Fatalf("rule %s: %+v", e.Rule.ID, e.Rule)
		}
	}
	// Gates the generic API server declares are cited where their
	// constant is declared, not where pkg/features relists them.
	for _, p := range out.Manifest.Pairs {
		for _, g := range proofOf(t, p).Removed {
			wantPath := "pkg/features/kube_features.go"
			if slices.Contains([]string{"KMSv2", "ServerSideApply", "APIServerTracing", "AuthorizeWithSelectors"}, g.Name) {
				wantPath = "staging/src/k8s.io/apiserver/pkg/features/kube_features.go"
			}
			if g.Declared.Path != wantPath || len(g.Registered) == 0 {
				t.Fatalf("%s declared at %+v registered %+v", g.Name, g.Declared, g.Registered)
			}
		}
	}
	// Pre-release and patch tags never form a pair.
	for _, p := range out.Manifest.Pairs {
		if strings.Contains(p.ToTag, "-") || p.FromTag == "v1.36.1" {
			t.Fatalf("pair from a non-final tag: %+v", p)
		}
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

// TestGoldenFixtureOutput pins every output byte (with the code digest,
// which changes with any source edit, masked). Run with -update after a
// deliberate output change, and bump Version.
func TestGoldenFixtureOutput(t *testing.T) {
	files, err := fixtureOutput(t, 0).Files()
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
	var onDisk []string
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			onDisk = append(onDisk, filepath.ToSlash(rel))
		}
		return nil
	})
	var names []string
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

func TestReproducibleAcrossRunsAndConcurrency(t *testing.T) {
	a, err := fixtureOutput(t, 1).Files()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []int{1, 8, 32} {
		b, err := fixtureOutput(t, c).Files()
		if err != nil {
			t.Fatal(err)
		}
		if len(a) != len(b) {
			t.Fatal("file sets differ")
		}
		for name := range a {
			if !bytes.Equal(a[name], b[name]) {
				t.Fatalf("concurrency %d: %s differs", c, name)
			}
		}
	}
}

func readTSV(t *testing.T, data []byte) map[string]string {
	t.Helper()
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		parts := strings.Split(sc.Text(), "\t")
		if len(parts) != 3 {
			t.Fatalf("read log line %q", sc.Text())
		}
		out[parts[0]] = parts[1]
	}
	return out
}

func sha(data []byte) string {
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}

func fixtureFile(t *testing.T, commit, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtureRoot, Repo, "commits", commit, filepath.FromSlash(path)))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Every cited source is a file the extractor read at that commit, with the
// digest of its bytes, and every declaration span holds the gates it is
// cited for; every Go file of the walk is in the read log.
func TestProvenanceIsComplete(t *testing.T) {
	out := fixtureOutput(t, 0)
	files, err := out.Files()
	if err != nil {
		t.Fatal(err)
	}
	logs := map[string]map[string]string{}
	for name, data := range files {
		if c, ok := strings.CutPrefix(name, extract.DirReads+"/"); ok {
			logs[strings.TrimSuffix(c, ".tsv")] = readTSV(t, data)
		}
	}
	for commit, log := range logs {
		for p, digest := range log {
			if sha(fixtureFile(t, commit, p)) != digest {
				t.Fatalf("%s:%s logged with a wrong digest", commit, p)
			}
		}
	}
	for _, e := range out.Entries {
		for _, s := range e.Rule.Evidence.Sources {
			path := strings.TrimPrefix(s.URL, "https://github.com/kubernetes/kubernetes/blob/"+s.Revision+"/")
			if logs[s.Revision][path] == "" || "sha256:"+logs[s.Revision][path] != s.ContentDigest {
				t.Fatalf("%s cites %s@%s not in the read log", e.Rule.ID, path, s.Revision)
			}
			lines := strings.Split(string(fixtureFile(t, s.Revision, path)), "\n")
			span := strings.Join(lines[s.StartLine-1:s.EndLine], "\n")
			switch {
			case strings.HasPrefix(s.ID, "gate-declarations-"):
				found := 0
				for _, m := range e.Rule.SetCondition.Members {
					if strings.Contains(span, `"`+m+`"`) {
						found++
					}
				}
				if found == 0 {
					t.Fatalf("%s: declaration span %s %d-%d names no forbidden gate", e.Rule.ID, path, s.StartLine, s.EndLine)
				}
			case strings.HasPrefix(s.ID, "unrecognized-gate-"):
				if !strings.Contains(span, unrecognizedGateMsg) {
					t.Fatalf("%s: error span %q", e.Rule.ID, span)
				}
			case strings.HasPrefix(s.ID, "gate-registry-"):
				if s.StartLine != 1 || s.EndLine != extract.CountLines(fixtureFile(t, s.Revision, path)) {
					t.Fatalf("%s: registry source must cite the whole file", e.Rule.ID)
				}
			default:
				t.Fatalf("unexpected source %s", s.ID)
			}
		}
		// Each forbidden gate is declared inside one of the cited spans.
		for _, m := range e.Rule.SetCondition.Members {
			covered := false
			for _, s := range e.Rule.Evidence.Sources {
				if !strings.HasPrefix(s.ID, "gate-declarations-") {
					continue
				}
				path := strings.TrimPrefix(s.URL, "https://github.com/kubernetes/kubernetes/blob/"+s.Revision+"/")
				lines := strings.Split(string(fixtureFile(t, s.Revision, path)), "\n")
				for _, l := range lines[s.StartLine-1 : s.EndLine] {
					if strings.Contains(l, `"`+m+`"`) {
						covered = true
					}
				}
			}
			if !covered {
				t.Fatalf("%s: %s is not inside a cited declaration span", e.Rule.ID, m)
			}
		}
	}
	for _, p := range out.Manifest.Pairs {
		proof := proofOf(t, p)
		goFiles := 0
		for path := range logs[p.ToCommit] {
			if strings.HasSuffix(path, ".go") {
				goFiles++
			}
		}
		if goFiles != proof.To.GoFiles || proof.To.GoFiles == 0 {
			t.Fatalf("%s: %d Go files walked, %d logged", p.ToTag, proof.To.GoFiles, goFiles)
		}
		for _, f := range proof.From.DeclarationFiles {
			if logs[p.FromCommit][f.Path] != f.SHA256 {
				t.Fatalf("%s: declaration file %s not logged", p.FromTag, f.Path)
			}
		}
		for _, g := range proof.Removed {
			if slices.Contains(proof.To.Names, g.Name) || !slices.Contains(proof.From.Declared, g.Name) {
				t.Fatalf("%s: removal %s contradicts the recorded name lists", p.ToTag, g.Name)
			}
		}
	}
}

func TestComponentsMatchTheAdapterFacts(t *testing.T) {
	var adapter []string
	for _, f := range cncfprepare.KubernetesComponentConfigSetFacts() {
		if strings.HasSuffix(f, "_feature_gates_set") {
			adapter = append(adapter, f)
		}
	}
	var ours []string
	for _, c := range Components {
		ours = append(ours, c.Fact)
	}
	sort.Strings(adapter)
	sort.Strings(ours)
	if !slices.Equal(adapter, ours) {
		t.Fatalf("extractor facts %v, adapter facts %v", ours, adapter)
	}
}

func TestPairsUseOnlyFinalConsecutiveMinorTags(t *testing.T) {
	sha := func(n int) string { return fmt.Sprintf("%040d", n) }
	ix := extract.ReleaseIndex{Repo: k8sRepo(t), Tags: []extract.Tag{
		{Name: "v1.21.0", Commit: sha(21)}, {Name: "v1.22.0", Commit: sha(22)}, {Name: "v1.23.0", Commit: sha(23)},
		{Name: "v1.24.0-rc.0", Commit: sha(240)}, {Name: "v1.24.1", Commit: sha(241)}, {Name: "v1.25.0", Commit: sha(25)},
		{Name: "v1.26.0", Commit: "not-a-sha"}, {Name: "v1.27.0", Commit: sha(27)}, {Name: "v1.28.0", Commit: sha(28)},
		{Name: "v01.29.0", Commit: sha(29)}, {Name: "v1.029.0", Commit: sha(29)}, {Name: "1.29.0", Commit: sha(29)}, {Name: "v1.29.0", Commit: sha(29)},
		{Name: "v2.0.0", Commit: sha(200)}, {Name: "v2.1.0", Commit: sha(201)}, {Name: "v1.30.0 ", Commit: sha(30)},
	}}
	var got []string
	for _, p := range New(0).Pairs(ix) {
		got = append(got, p.FromTag+">"+p.ToTag+"@"+p.FromCommit[36:]+">"+p.ToCommit[36:])
	}
	want := []string{"v1.22.0>v1.23.0@0022>0023", "v1.27.0>v1.28.0@0027>0028", "v1.28.0>v1.29.0@0028>0029"}
	if !slices.Equal(got, want) {
		t.Fatalf("pairs %v, want %v", got, want)
	}
}

func TestChunksBoundMembersAndDeclarationFiles(t *testing.T) {
	var removed []*gateDecl
	for i := 0; i < 70; i++ {
		removed = append(removed, &gateDecl{Name: fmt.Sprintf("G%03d", i), Declared: pos{Path: "pkg/features/kube_features.go", Line: i + 1}})
	}
	got := chunks(removed)
	if len(got) != 2 || len(got[0]) != maxMembers || len(got[1]) != 70-maxMembers {
		t.Fatalf("member split %d/%d", len(got[0]), len(got[1]))
	}
	removed = nil
	for i := 0; i < 5; i++ {
		removed = append(removed, &gateDecl{Name: fmt.Sprintf("G%d", i), Declared: pos{Path: fmt.Sprintf("f%d.go", i), Line: 1}})
	}
	got = chunks(removed)
	if len(got) != 2 || len(got[0]) != maxDeclFiles || len(got[1]) != 2 {
		t.Fatalf("file split %v", got)
	}
}

// --- synthetic trees for the completeness rules ---

const (
	fromSHA = "1000000000000000000000000000000000000000"
	toSHA   = "2000000000000000000000000000000000000000"
)

const goodFeatureGate = `package featuregate

import "fmt"

type Feature string

func check(k string) error { return fmt.Errorf("unrecognized feature gate: %s", k) }
`

func features(names ...string) string {
	var b strings.Builder
	b.WriteString("package features\n\nimport \"k8s.io/component-base/featuregate\"\n\nconst (\n")
	for _, n := range names {
		fmt.Fprintf(&b, "\t%s featuregate.Feature = %q\n", n, n)
	}
	b.WriteString(")\n\nvar defaultKubernetesFeatureGates = map[featuregate.Feature]featuregate.FeatureSpec{\n")
	for _, n := range names {
		fmt.Fprintf(&b, "\t%s: {},\n", n)
	}
	b.WriteString("}\n")
	return b.String()
}

func baseTree(gates ...string) map[string]string {
	return map[string]string{
		"pkg/features/kube_features.go": features(gates...),
		featuregateFile:                 goodFeatureGate,
		"cmd/kubelet/kubelet.go":        "package main\n\nfunc main() {}\n",
	}
}

func syntheticRepo(t *testing.T, from, to map[string]string) extract.FixtureReader {
	t.Helper()
	root := t.TempDir()
	base := filepath.Join(root, Repo)
	for commit, files := range map[string]map[string]string{fromSHA: from, toSHA: to} {
		for p, c := range files {
			full := filepath.Join(base, "commits", commit, filepath.FromSlash(p))
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	tags := fmt.Sprintf(`{"v1.36.0": %q, "v1.37.0": %q}`, fromSHA, toSHA)
	if err := os.WriteFile(filepath.Join(base, "tags.json"), []byte(tags), 0o644); err != nil {
		t.Fatal(err)
	}
	return extract.FixtureReader{Root: root}
}

func onlyPair(t *testing.T, out *extract.Output) extract.PairRecord {
	t.Helper()
	if len(out.Manifest.Pairs) != 1 {
		t.Fatalf("pairs %+v", out.Manifest.Pairs)
	}
	return out.Manifest.Pairs[0]
}

func TestSyntheticRemovalIsDerived(t *testing.T) {
	out := runOn(t, syntheticRepo(t, baseTree("Alpha", "Beta", "Gamma"), baseTree("Alpha", "Beta")), 0)
	p := onlyPair(t, out)
	if p.Status != extract.PairDerived || !slices.Equal(removedNames(t, p), []string{"Gamma"}) || len(out.Entries) != len(Components) {
		t.Fatalf("pair %+v", p)
	}
	for _, e := range out.Entries {
		if !slices.Equal(e.Rule.SetCondition.Members, []string{"Gamma"}) {
			t.Fatalf("members %v", e.Rule.SetCondition.Members)
		}
	}
}

func TestAbsenceMustBeProvenOrNoRule(t *testing.T) {
	from := baseTree("Alpha", "Beta", "Gamma")
	with := func(extra map[string]string, drop ...string) map[string]string {
		to := baseTree("Alpha", "Beta")
		for _, d := range drop {
			delete(to, d)
		}
		for p, c := range extra {
			to[p] = c
		}
		return to
	}
	for name, tc := range map[string]struct {
		from, to map[string]string
		reason   string
	}{
		"unparseable file anywhere in the walk": {from, with(map[string]string{"pkg/kubelet/broken.go": "package kubelet\n\nfunc {"}), "parsing pkg/kubelet/broken.go"},
		"map key that cannot be resolved":       {from, with(map[string]string{"staging/src/k8s.io/other/pkg/x/x.go": "package x\n\nimport (\n\t\"example.com/ext\"\n\t\"k8s.io/component-base/featuregate\"\n)\n\nvar m = map[featuregate.Feature]featuregate.FeatureSpec{ext.Gate: {}}\n"}), "cannot be resolved"},
		"map key computed by a call":            {from, with(map[string]string{"pkg/x/x.go": "package x\n\nimport \"k8s.io/component-base/featuregate\"\n\nvar m = map[featuregate.Feature]featuregate.FeatureSpec{name(): {}}\n\nfunc name() featuregate.Feature { return \"\" }\n"}), "cannot be resolved"},
		"no recognised unrecognised-gate error": {from, with(map[string]string{featuregateFile: "package featuregate\n\ntype Feature string\n"}), "does not reject unrecognised gates"},
		"feature gate implementation missing":   {from, with(map[string]string{"staging/src/k8s.io/x/x.go": "package x\n"}, featuregateFile), "does not reject unrecognised gates"},
		"required root missing":                 {from, with(nil, featuregateFile, "cmd/kubelet/kubelet.go"), "required directory staging/ is missing"},
		"generated list names an unknown gate":  {from, with(map[string]string{"test/compatibility_lifecycle/reference/versioned_feature_list.yaml": "- name: Alpha\n- name: Gamma\n"}), "lists Gamma"},
		"generated list unreadable":             {from, with(map[string]string{"test/compatibility_lifecycle/reference/versioned_feature_list.yaml": "- name: [\n"}), "parsing test/compatibility_lifecycle"},
		"from registry key unresolved": {map[string]string{
			"pkg/features/kube_features.go": "package features\n\nimport \"k8s.io/component-base/featuregate\"\n\nvar m = map[featuregate.Feature]featuregate.FeatureSpec{Missing: {}, \"Gamma\": {}}\n",
			featuregateFile:                 goodFeatureGate,
		}, with(nil), "declared registry at v1.36.0 is not complete"},
		"from registry dynamic key": {map[string]string{
			"pkg/features/kube_features.go": "package features\n\nimport \"k8s.io/component-base/featuregate\"\n\nfunc add(f featuregate.Feature) any {\n\treturn map[featuregate.Feature]featuregate.FeatureSpec{f: {}, \"Gamma\": {}}\n}\n",
			featuregateFile:                 goodFeatureGate,
		}, with(nil), "not a static name"},
		"no declared gate at from": {map[string]string{"pkg/features/kube_features.go": "package features\n", featuregateFile: goodFeatureGate}, with(nil), "no feature gate is declared"},
	} {
		t.Run(name, func(t *testing.T) {
			out := runOn(t, syntheticRepo(t, tc.from, tc.to), 0)
			p := onlyPair(t, out)
			if p.Status != extract.PairWithheld || len(out.Entries) != 0 || len(out.Vectors) != 0 || !strings.Contains(p.Reason, tc.reason) {
				t.Fatalf("status=%s reason=%q entries=%d", p.Status, p.Reason, len(out.Entries))
			}
		})
	}
}

// failingReader fails every read of one path, as a mirror does for a blob
// that was never materialized.
type failingReader struct {
	extract.FixtureReader
	path string
}

func (f failingReader) Read(repo extract.RepoRef, commit, p string) ([]byte, error) {
	if p == f.path && commit == toSHA {
		return nil, errors.New("file contents are not materialized")
	}
	return f.FixtureReader.Read(repo, commit, p)
}

func TestUnreadableFileWithholds(t *testing.T) {
	to := baseTree("Alpha")
	to["cmd/kube-proxy/proxy.go"] = "package main\n"
	fr := syntheticRepo(t, baseTree("Alpha", "Gamma"), to)
	out := runOn(t, failingReader{fr, "cmd/kube-proxy/proxy.go"}, 0)
	if p := onlyPair(t, out); p.Status != extract.PairWithheld || !strings.Contains(p.Reason, "reading cmd/kube-proxy/proxy.go") || len(out.Entries) != 0 {
		t.Fatalf("pair %+v", p)
	}
}

func TestGateDeclaredElsewhereIsNotRemoved(t *testing.T) {
	to := baseTree("Alpha")
	for name, extra := range map[string]map[string]string{
		"moved to another package's spec map": {"pkg/kubelet/features.go": "package kubelet\n\nimport fg \"k8s.io/component-base/featuregate\"\n\nconst G fg.Feature = \"Gamma\"\n\nvar m = map[fg.Feature]fg.VersionedSpecs{G: nil}\n"},
		"kept as a typed constant only":       {"staging/src/k8s.io/thing/pkg/x/x.go": "package x\n\nimport \"k8s.io/component-base/featuregate\"\n\nconst Gamma featuregate.Feature = \"Gamma\"\n"},
		"spelled as a converted literal":      {"plugin/pkg/p.go": "package p\n\nimport \"k8s.io/component-base/featuregate\"\n\nfunc f() any { return featuregate.Feature(\"Gamma\") }\n"},
		"resolved through another package":    {"pkg/a/a.go": "package a\n\nimport (\n\tb \"k8s.io/kubernetes/pkg/b\"\n\t\"k8s.io/component-base/featuregate\"\n)\n\nvar m = map[featuregate.Feature]featuregate.FeatureSpec{b.G: {}}\n", "pkg/b/b.go": "package b\n\nconst G = \"Gamma\"\n"},
	} {
		t.Run(name, func(t *testing.T) {
			tree := map[string]string{}
			for p, c := range to {
				tree[p] = c
			}
			for p, c := range extra {
				tree[p] = c
			}
			out := runOn(t, syntheticRepo(t, baseTree("Alpha", "Gamma"), tree), 0)
			p := onlyPair(t, out)
			if p.Status != extract.PairDerived || len(removedNames(t, p)) != 0 || len(out.Entries) != 0 {
				t.Fatalf("pair %+v removed %v", p, removedNames(t, p))
			}
		})
	}
	// Directories the build ignores do not keep a gate alive.
	for _, dir := range []string{"vendor", "testdata", "_output", ".git"} {
		tree := baseTree("Alpha")
		tree["pkg/"+dir+"/x.go"] = "package x\n\nimport \"k8s.io/component-base/featuregate\"\n\nconst Gamma featuregate.Feature = \"Gamma\"\n"
		out := runOn(t, syntheticRepo(t, baseTree("Alpha", "Gamma"), tree), 0)
		if got := removedNames(t, onlyPair(t, out)); !slices.Equal(got, []string{"Gamma"}) {
			t.Fatalf("%s: removed %v", dir, got)
		}
	}
	// A test file is not built into a component.
	tree := baseTree("Alpha")
	tree["pkg/x/x_test.go"] = "package x\n\nimport \"k8s.io/component-base/featuregate\"\n\nconst Gamma featuregate.Feature = \"Gamma\"\n"
	if got := removedNames(t, onlyPair(t, runOn(t, syntheticRepo(t, baseTree("Alpha", "Gamma"), tree), 0))); !slices.Equal(got, []string{"Gamma"}) {
		t.Fatalf("test file: removed %v", got)
	}
}

// A gate only some other package declares at the earlier release is not a
// declared component gate there, so its disappearance is not a removal.
func TestOnlyDeclarationDirectoriesDeclare(t *testing.T) {
	from := baseTree("Alpha")
	from["pkg/kubelet/f.go"] = "package kubelet\n\nimport \"k8s.io/component-base/featuregate\"\n\nvar m = map[featuregate.Feature]featuregate.FeatureSpec{\"Elsewhere\": {}}\n"
	from["staging/src/k8s.io/apiserver/pkg/features/kube_features.go"] = strings.Replace(features("Delta"), "package features", "package features", 1)
	out := runOn(t, syntheticRepo(t, from, baseTree("Alpha")), 0)
	if got := removedNames(t, onlyPair(t, out)); !slices.Equal(got, []string{"Delta"}) {
		t.Fatalf("removed %v", got)
	}
	for _, dir := range []string{"pkg/features", "staging/src/k8s.io/apiserver/pkg/features", "staging/src/k8s.io/client-go/features", "staging/src/k8s.io/component-base/metrics/features", "staging/src/k8s.io/component-base/logs/api/v1"} {
		if !isDeclarationDir(dir) {
			t.Fatalf("%s is a declaration directory", dir)
		}
	}
	for _, dir := range []string{"pkg/kubelet", "pkg/features/sub", "staging/src/k8s.io/apiserver/pkg/features/x", "cmd/kubeadm/app/features", "staging/src/k8s.io/component-base/featuregate"} {
		if isDeclarationDir(dir) {
			t.Fatalf("%s is not a declaration directory", dir)
		}
	}
}

func TestOracleAgreesOnFixture(t *testing.T) {
	out := fixtureOutput(t, 0)
	dir := filepath.Join(t.TempDir(), "run")
	if err := out.Write(dir); err != nil {
		t.Fatal(err)
	}
	expected, err := os.ReadFile("testdata/oracle-fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	diffs, err := Oracle(dir, expected)
	if err != nil || len(diffs) != 0 {
		t.Fatalf("oracle: %v %v", err, diffs)
	}
	// Each kind of disagreement is reported.
	var exp Expected
	if err := json.Unmarshal(expected, &exp); err != nil {
		t.Fatal(err)
	}
	exp.Removals = append(exp.Removals[1:], ExpectedRemoval{Gate: "AppArmor", RemovedIn: "1.23"}, ExpectedRemoval{Gate: "NotAGate", RemovedIn: "1.32"}, ExpectedRemoval{Gate: "X", RemovedIn: "1.30"})
	exp.Removals[0].DeclLine++
	exp.Rules = append(exp.Rules, ExpectedRule{Name: "extra", From: "1.31.0", To: "1.32.0", Gates: []string{"AnyVolumeDataSource"}, Components: []string{"kubelet"}})
	raw, _ := json.Marshal(exp)
	diffs, err = Oracle(dir, raw)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(diffs, "\n")
	for _, want := range []string{"EXTRA ", "LOCATION ", "MISSING AppArmor removed in 1.23: extractor finds it still present at v1.23.0", "MISSING NotAGate removed in 1.32: extractor finds it not declared at v1.31.0", "MISSING X removed in 1.30: the run has no pair", "RULE extra: no kubelet rule"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in\n%s", want, joined)
		}
	}
}
