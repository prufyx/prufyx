// SPDX-License-Identifier: AGPL-3.0-only

package gitops

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/intake"
)

func openFixture(t *testing.T, name string, subdirs ...string) (intake.Workspace, string) {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	args := []string{root}
	if len(subdirs) > 0 {
		args = nil
		for _, s := range subdirs {
			args = append(args, filepath.Join(root, s))
		}
	}
	ws, err := intake.Open(args, intake.Options{Permissions: intake.RefuseWritable})
	if err != nil {
		t.Fatal(err)
	}
	return ws, root
}

// memory builds a workspace from file contents without touching the disk. The
// repository root is "repo".
func memory(t *testing.T, files map[string]string) intake.Workspace {
	t.Helper()
	var all intake.Workspace
	for name, text := range files {
		w, err := intake.Decode("repo/"+name, []byte(text))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		all.Documents = append(all.Documents, w.Documents...)
		all.Omissions = append(all.Omissions, w.Omissions...)
		all.Auxiliary = append(all.Auxiliary, w.Auxiliary...)
		all.Encrypted = append(all.Encrypted, w.Encrypted...)
		all.Files = append(all.Files, intake.FileRecord{Display: "repo/" + name})
	}
	return all
}

func analyze(t *testing.T, files map[string]string, self ...string) Repo {
	t.Helper()
	return Analyze(memory(t, files), Options{Root: "repo", SelfRepoURLs: self})
}

func gapReasons(gaps []Gap) []string {
	var out []string
	for _, g := range gaps {
		out = append(out, g.Reason)
	}
	return out
}

func hasGap(gaps []Gap, reason, detail string) bool {
	for _, g := range gaps {
		if g.Reason == reason && strings.Contains(g.Detail, detail) {
			return true
		}
	}
	return false
}

func envByName(t *testing.T, repo Repo, name string) Environment {
	t.Helper()
	for _, e := range repo.Environments {
		if e.Name == name {
			return e
		}
	}
	t.Fatalf("no environment %q in %v", name, envNames(repo))
	return Environment{}
}

func envNames(repo Repo) []string {
	var out []string
	for _, e := range repo.Environments {
		out = append(out, e.Name)
	}
	return out
}

func marshal(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func writeFile(t *testing.T, path, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Manifests used by the in-memory tests.
const gitRepo = `apiVersion: source.toolkit.fluxcd.io/v1
kind: GitRepository
metadata: {name: fleet, namespace: flux-system}
spec: {url: "ssh://git@git.example.test/team/fleet"}
`

func fluxRoot(name, path string) string {
	return `apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata: {name: ` + name + `, namespace: flux-system}
spec:
  path: ` + path + `
  sourceRef: {kind: GitRepository, name: fleet}
`
}

func helmRelease(name, version string) string {
	v := ""
	if version != "" {
		v = "\n      version: " + version
	}
	return `apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata: {name: ` + name + `, namespace: apps}
spec:
  chart:
    spec:
      chart: ` + name + v + `
      sourceRef: {kind: HelmRepository, name: charts}
`
}

const helmRepo = `apiVersion: source.toolkit.fluxcd.io/v1
kind: HelmRepository
metadata: {name: charts, namespace: apps}
spec: {url: "https://charts.example.test"}
`
