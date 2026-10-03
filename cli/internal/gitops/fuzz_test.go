// SPDX-License-Identifier: AGPL-3.0-only

package gitops

import (
	"bytes"
	"encoding/json"
	"runtime"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/intake"
)

// FuzzGitops feeds arbitrary bytes, split over three files, to the decoder
// and then to Analyze. It must not panic, must stay within a bounded amount of
// allocation and must keep every gap detail within its limit.
func FuzzGitops(f *testing.F) {
	seeds := []string{
		gitRepo + "---\n" + fluxRoot("root", "./app") + "---\n" + helmRelease("web", "1.0.0") + "---\n" + helmRepo,
		"apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata: {name: a}\nspec:\n  sources:\n    - {repoURL: 'https://example.test/r', path: ., helm: {values: 'a: 1', valueFiles: [x]}}\n    - {chart: c, repoURL: u, targetRevision: '*'}\n",
		"resources: [., ../.., a, https://example.test/x]\nimages: [{name: a, newTag: b}]\npatches: [{target: {kind: HelmRelease, name: a}, patch: '[{op: replace, path: /spec/chart/spec/version, value: 1}]'}]\n",
		"apiVersion: v2\nname: c\ndependencies: [{name: a, version: '1', repository: u}, {name: b}, 7]\n",
		"apiVersion: argoproj.io/v1alpha1\nkind: ApplicationSet\nmetadata: {name: s}\nspec: {}\n",
		"apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: d}\nspec: {template: {spec: {containers: [{image: 'a/b:c@sha256:0'}, 3, {image: ''}]}}}\n",
		"apiVersion: kustomize.toolkit.fluxcd.io/v1\nkind: Kustomization\nmetadata: {name: k, namespace: n}\nspec: {path: ../.., sourceRef: {kind: Bucket, name: b}}\n",
		"sops: {mac: x, version: 1}\napiVersion: v1\nkind: ConfigMap\nmetadata: {name: e}\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var before runtime.MemStats
		runtime.ReadMemStats(&before)
		third := len(data) / 3
		parts := map[string][]byte{
			"repo/clusters/a.yaml":        data[:third],
			"repo/app/kustomization.yaml": data[third : 2*third],
			"repo/app/Chart.yaml":         data[2*third:],
			"repo/app/b.yaml":             data,
		}
		var ws intake.Workspace
		for _, name := range []string{"repo/clusters/a.yaml", "repo/app/kustomization.yaml", "repo/app/Chart.yaml", "repo/app/b.yaml"} {
			w, err := intake.Decode(name, parts[name])
			if err != nil {
				continue
			}
			ws.Documents = append(ws.Documents, w.Documents...)
			ws.Omissions = append(ws.Omissions, w.Omissions...)
			ws.Auxiliary = append(ws.Auxiliary, w.Auxiliary...)
			ws.Encrypted = append(ws.Encrypted, w.Encrypted...)
			ws.Files = append(ws.Files, intake.FileRecord{Display: name})
		}
		repo := Analyze(ws, Options{Root: "repo", SelfRepoURLs: []string{"https://example.test/r"}})
		check := func(gaps []Gap) {
			for _, g := range gaps {
				if len(g.Detail) > MaxFieldBytes || g.Reason == "" {
					t.Fatalf("bad gap %+v", g)
				}
			}
		}
		check(repo.Gaps)
		for _, e := range repo.Environments {
			check(e.Gaps)
			if len(e.Releases) > MaxReleases || len(e.Images) > MaxImages {
				t.Fatal("bound exceeded")
			}
		}
		if _, err := json.Marshal(repo); err != nil {
			t.Fatal(err)
		}
		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		if delta := after.TotalAlloc - before.TotalAlloc; delta > 64<<20 {
			t.Fatalf("allocated %d bytes for %d input bytes", delta, bytes.Count(data, nil))
		}
	})
}
