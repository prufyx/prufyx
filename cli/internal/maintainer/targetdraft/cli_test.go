// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"}, args...)...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "GIT_CONFIG_NOSYSTEM=1"}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
}

// knativeRepo writes the knative fixture as a real git repository with real
// symbolic links and the six tags.
func knativeRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	m := loadDir(t, "testdata/knative/tree", "testdata/knative/links.txt")
	for p, b := range m.files {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for p, target := range m.links {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, full); err != nil {
			t.Fatal(err)
		}
	}
	git(t, dir, "init", "-q")
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", "fixture")
	for _, tag := range knativeTags {
		git(t, dir, "tag", tag)
	}
	return dir
}

func TestGitSourceEqualsMemorySource(t *testing.T) {
	repo := knativeRepo(t)
	rules := rulesFrom(t, "testdata/knative/rules.json")
	fromGit := mustGenerate(t, knativeInput(t, GitSource{Dir: repo}, rules))
	fromMem := mustGenerate(t, knativeInput(t, knativeSource(t, nil), rules))
	if !bytes.Equal(fromGit.A, fromMem.A) || !bytes.Equal(fromGit.B, fromMem.B) || fromGit.Report.FactsDigest != fromMem.Report.FactsDigest {
		t.Fatal("git source and memory source disagree")
	}
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(fromGit.Report.Tags[0].Commit) {
		t.Fatalf("commit %q", fromGit.Report.Tags[0].Commit)
	}
	if _, _, err := (GitSource{Dir: repo}).Open("--upload-pack=x"); err == nil {
		t.Fatal("an option-shaped tag was accepted")
	}
	if _, _, err := (GitSource{Dir: repo}).Open("v9.9.9"); err == nil {
		t.Fatal("a missing tag was accepted")
	}
}

func TestRunWritesDraftAndComparesToReviewed(t *testing.T) {
	repo := knativeRepo(t)
	out := filepath.Join(t.TempDir(), "draft")
	args := []string{"generate", "--dir", repo, "--slug", "knative", "--name", "Knative", "--repo", "github.com/knative/serving",
		"--tags", strings.Join(knativeTags, ","), "--rules", "testdata/knative/rules.json", "--out", out,
		"--compare-a", "testdata/knative/golden-a.json", "--compare-b", "testdata/knative/golden-b.json"}
	var so, se bytes.Buffer
	if code := Run(args, &so, &se); code != 0 {
		t.Fatalf("exit %d: %s %s", code, so.String(), se.String())
	}
	for _, f := range []string{"a/target-knative.json", "a/table-row.json", "b/target-knative.json", "b/changelog.md", "report.json"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Errorf("missing %s", f)
		}
	}
	// A second run into the same, now non-empty, directory is refused.
	if code := Run(args, &so, &se); code != 2 {
		t.Fatalf("non-empty out: exit %d", code)
	}
	// A reviewed file that differs is reported with exit 1.
	bad := filepath.Join(t.TempDir(), "bad.json")
	raw := readFile(t, "testdata/knative/golden-b.json")
	if err := os.WriteFile(bad, bytes.Replace(raw, []byte(`"minFrom": "0.46"`), []byte(`"minFrom": "0.47"`), 1), 0o644); err != nil {
		t.Fatal(err)
	}
	so.Reset()
	args2 := append(append([]string{}, args[:len(args)-4]...), "--out", filepath.Join(t.TempDir(), "d2"), "--compare-b", bad)
	if code := Run(args2, &so, &se); code != 1 || !strings.Contains(so.String(), "DIFF B: field minFrom") {
		t.Fatalf("exit %d: %s", code, so.String())
	}
	// A judgment without a rule is a typed stop and writes nothing.
	so.Reset()
	d3 := filepath.Join(t.TempDir(), "d3")
	if code := Run([]string{"generate", "--dir", repo, "--slug", "knative", "--name", "Knative", "--repo", "github.com/knative/serving",
		"--tags", strings.Join(knativeTags, ","), "--out", d3}, &so, &se); code != 1 || !strings.Contains(so.String(), "STOP unpinned-exclusion") {
		t.Fatalf("exit %d: %s", code, so.String())
	}
	if _, err := os.Stat(d3); err == nil {
		t.Error("a stop wrote a draft")
	}
}

func TestRunUsageErrors(t *testing.T) {
	for _, args := range [][]string{nil, {"other"}, {"generate"}, {"generate", "--dir", "x", "--slug", "s", "--name", "n", "--repo", "github.com/o/r", "--tags", "v1.0.0", "--out", "o", "extra"}} {
		var so, se bytes.Buffer
		if code := Run(args, &so, &se); code != 2 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
}

func TestShrunkWindowWarnsAndStrictStops(t *testing.T) {
	src := knativeSource(t, func(tag string, m *memTree) {
		if tag == "v0.46.9" {
			delete(m.files, "config/core/300-resources/route.yaml")
		}
	})
	rules := "testdata/knative/rules.json"
	args := func(out string, extra ...string) []string {
		return append([]string{"generate", "--dir", "x", "--slug", "knative", "--name", "Knative", "--repo", "github.com/knative/serving",
			"--tags", strings.Join(knativeTags, ","), "--rules", rules, "--out", out}, extra...)
	}
	open := func(string) Source { return src }
	var so, se bytes.Buffer
	out := filepath.Join(t.TempDir(), "d")
	if code := run(args(out), &so, &se, open); code != 0 || !strings.Contains(so.String(), "WARNING window-shrunk") {
		t.Fatalf("exit %d: %s %s", code, so.String(), se.String())
	}
	rep := readFile(t, filepath.Join(out, "report.json"))
	if !bytes.Contains(rep, []byte("WARNING window-shrunk")) {
		t.Error("the report carries no warning")
	}
	so.Reset()
	out2 := filepath.Join(t.TempDir(), "d2")
	if code := run(args(out2, "--strict-window"), &so, &se, open); code != 1 || !strings.Contains(so.String(), "STOP window-shortened") {
		t.Fatalf("exit %d: %s", code, so.String())
	}
	if _, err := os.Stat(out2); err == nil {
		t.Error("a stop wrote a draft")
	}
}

func TestFailedRunLeavesOutEmpty(t *testing.T) {
	repo := knativeRepo(t)
	base := []string{"generate", "--dir", repo, "--slug", "knative", "--name", "Knative", "--repo", "github.com/knative/serving",
		"--tags", strings.Join(knativeTags, ","), "--rules", "testdata/knative/rules.json"}
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, bytes.Replace(readFile(t, "testdata/knative/golden-b.json"), []byte(`"minFrom": "0.46"`), []byte(`"minFrom": "0.47"`), 1), 0o644); err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	out := filepath.Join(parent, "draft")
	var so, se bytes.Buffer
	if code := Run(append(append([]string{}, base...), "--out", out, "--compare-b", bad), &so, &se); code != 1 {
		t.Fatalf("mismatch: exit %d", code)
	}
	if ents, _ := os.ReadDir(parent); len(ents) != 0 {
		t.Errorf("a compare mismatch left %d entries beside --out", len(ents))
	}
	// An I/O error while writing: --out is a path below a regular file.
	blocker := filepath.Join(parent, "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := Run(append(append([]string{}, base...), "--out", filepath.Join(blocker, "draft")), &so, &se); code != 2 {
		t.Fatalf("io error: exit %d", code)
	}
	// An existing empty --out stays empty when the run fails.
	empty := filepath.Join(parent, "empty")
	if err := os.Mkdir(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	if code := Run(append(append([]string{}, base...), "--out", empty, "--compare-b", bad), &so, &se); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if ents, _ := os.ReadDir(empty); len(ents) != 0 {
		t.Errorf("--out holds %d entries after a failed run", len(ents))
	}
}

func TestRawByteDifferenceIsReported(t *testing.T) {
	repo := knativeRepo(t)
	golden := readFile(t, "testdata/knative/golden-b.json")
	spaced := filepath.Join(t.TempDir(), "spaced.json")
	if err := os.WriteFile(spaced, bytes.Replace(golden, []byte(`["v"]`), []byte(`[ "v" ]`), 1), 0o644); err != nil {
		t.Fatal(err)
	}
	var so, se bytes.Buffer
	code := Run([]string{"generate", "--dir", repo, "--slug", "knative", "--name", "Knative", "--repo", "github.com/knative/serving",
		"--tags", strings.Join(knativeTags, ","), "--rules", "testdata/knative/rules.json", "--out", filepath.Join(t.TempDir(), "d"), "--compare-b", spaced}, &so, &se)
	if code != 1 || !strings.Contains(so.String(), "bytes differ") {
		t.Fatalf("exit %d: %s", code, so.String())
	}
}

// Only the facts digest differs: the targets are equal, so the target
// comparison is silent, and the report comparison must fail the run.
func TestCompareReportCatchesFactsOnlyDifference(t *testing.T) {
	const route = "config/core/300-resources/route.yaml"
	two := func(m *memTree) {
		replaceCRD(m, route, "    storage: true\n", "    storage: true\n  - name: v1beta1\n    served: true\n    storage: false\n")
	}
	baseSrc := knativeSource(t, func(_ string, m *memTree) { two(m) })
	seededSrc := knativeSource(t, func(tag string, m *memTree) {
		two(m)
		if tag == "v0.51.0" {
			replaceCRD(m, route, "  - name: v1beta1\n    served: true\n    storage: false\n", "")
		}
	})
	args := func(out string, extra ...string) []string {
		return append([]string{"generate", "--dir", "x", "--slug", "knative", "--name", "Knative", "--repo", "github.com/knative/serving",
			"--tags", strings.Join(knativeTags, ","), "--rules", "testdata/knative/rules.json", "--out", out}, extra...)
	}
	var so, se bytes.Buffer
	d1 := filepath.Join(t.TempDir(), "base")
	if code := run(args(d1), &so, &se, func(string) Source { return baseSrc }); code != 0 {
		t.Fatalf("base: exit %d %s %s", code, so.String(), se.String())
	}
	reviewedReport := filepath.Join(d1, "report.json")
	targetA, targetB := filepath.Join(d1, "a", "target-knative.json"), filepath.Join(d1, "b", "target-knative.json")
	so.Reset()
	code := run(args(filepath.Join(t.TempDir(), "seeded"), "--compare-a", targetA, "--compare-b", targetB, "--compare-report", reviewedReport), &so, &se, func(string) Source { return seededSrc })
	if code != 1 || !strings.Contains(so.String(), "DIFF facts") || strings.Contains(so.String(), "DIFF A") || strings.Contains(so.String(), "DIFF B") {
		t.Fatalf("exit %d: %s", code, so.String())
	}
	so.Reset()
	if code := run(args(filepath.Join(t.TempDir(), "same"), "--compare-a", targetA, "--compare-b", targetB, "--compare-report", reviewedReport), &so, &se, func(string) Source { return baseSrc }); code != 0 {
		t.Fatalf("equal facts: exit %d %s", code, so.String())
	}
}
