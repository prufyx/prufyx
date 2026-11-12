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
