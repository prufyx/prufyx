// SPDX-License-Identifier: AGPL-3.0-only

package chartversions

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/maintainer/factorymirror"
)

const fixtureRepo = "github.com/acme/widget"

func gitEnv() []string {
	return append(os.Environ(),
		"GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid",
		"GIT_AUTHOR_DATE=2020-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2020-01-01T00:00:00Z")
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = gitEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// release is one tagged commit of the fixture chart repository.
type release struct {
	tag   string
	files map[string]string // path -> content
}

func chartYAML(name, version, appVersion string) string {
	return "apiVersion: v2\nname: " + name + "\ndescription: a test chart\nversion: " + version + "\nappVersion: " + appVersion + "\n"
}

// buildMirror creates a bare upstream with one commit per release, mirrors it
// (including the Chart.yaml blobs) and returns the mirror state directory.
func buildMirror(t *testing.T, releases []release, materialize bool) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	root := t.TempDir()
	bare := filepath.Join(root, filepath.FromSlash(fixtureRepo)+".git")
	if err := os.MkdirAll(bare, 0o755); err != nil {
		t.Fatal(err)
	}
	runGit(t, bare, "init", "-q", "--bare", "-b", "main")
	runGit(t, bare, "config", "uploadpack.allowFilter", "true")
	runGit(t, bare, "config", "uploadpack.allowAnySHA1InWant", "true")
	work := filepath.Join(t.TempDir(), "work")
	runGit(t, filepath.Dir(bare), "clone", "-q", bare, work)
	runGit(t, work, "checkout", "-q", "-b", "main")
	var wants []factorymirror.Want
	for _, r := range releases {
		for name, content := range r.files {
			p := filepath.Join(work, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		runGit(t, work, "add", "-A")
		runGit(t, work, "commit", "-q", "--allow-empty", "-m", r.tag)
		runGit(t, work, "tag", r.tag)
		commit := runGit(t, work, "rev-parse", "HEAD")
		wants = append(wants, factorymirror.Want{Repo: fixtureRepo, Commit: commit, Paths: []string{"chart/Chart.yaml", "elsewhere/Chart.yaml"}})
	}
	runGit(t, work, "push", "-q", "-f", "origin", "main", "--tags")
	repo, err := factorymirror.ParseRepo(fixtureRepo)
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(t.TempDir(), "state")
	opts := factorymirror.Options{StateDir: state, Repos: []factorymirror.Repo{repo}, RemoteBase: "file://" + root + "/", AllowFileRemote: true,
		Now: func() time.Time { return time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC) }, Concurrency: 1}
	if materialize {
		opts.Wants = wants
	}
	if _, err := factorymirror.Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	return state
}

func standardReleases() []release {
	return []release{
		{"v1.2.0", map[string]string{"chart/Chart.yaml": chartYAML("widget", "1.2.0", `"1.30.0"`)}},
		{"v1.3.0", map[string]string{"chart/Chart.yaml": chartYAML("widget", "1.3.0", "v1.31.0")}},
		{"v1.3.1-rc.1", map[string]string{"chart/Chart.yaml": chartYAML("widget", "1.3.1-rc.1", "1.31.1")}},
		{"v1.4.0", map[string]string{"chart/Chart.yaml": chartYAML("widget", "1.4.0", "latest")}},
		{"unrelated-1.0.0", map[string]string{"chart/Chart.yaml": chartYAML("widget", "1.0.0", "1.0.0")}},
	}
}

func fixtureMapping() *Mapping {
	return &Mapping{Schema: MappingSchema, Entries: []Entry{{
		Component: "pkg:github/acme/widget", Chart: "widget", Repo: fixtureRepo, ChartPath: "chart", TagPattern: "v{version}",
	}}}
}

func openReader(t *testing.T, state string) Reader {
	t.Helper()
	r, err := factorymirror.OpenReader(state)
	if err != nil {
		t.Fatal(err)
	}
	return extract.MirrorReader{R: r}
}
