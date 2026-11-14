// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

func TestLiteralKustomizationAllowedPins(t *testing.T) {
	for _, tc := range []struct {
		pin  literalKustomizationPin
		data string
	}{
		{literalKustomizationPins[0], redisKustomizationV023},
		{literalKustomizationPins[1], redisKustomizationV024},
		{literalKustomizationPins[2], redisKustomizationV024},
		{literalKustomizationPins[3], redisKustomizationV026},
		{literalKustomizationPins[4], redisKustomizationV027},
	} {
		t.Run(tc.pin.Tag, func(t *testing.T) {
			if !literalKustomizationAllowed(redisLiteralContext(tc.pin), []byte(tc.data)) {
				t.Fatal("pinned literal Kustomization was refused")
			}
		})
	}
}

func TestLiteralKustomizationAllowedRefusesUnsafeInputs(t *testing.T) {
	pin := literalKustomizationPins[0]
	valid := redisLiteralContext(pin)
	for name, mutate := range map[string]func(*literalKustomizationContext, *string){
		"quoted scalar": func(_ *literalKustomizationContext, data *string) {
			*data = "value: \"# " + literalKustomizationAction + "\"\n"
		},
		"block scalar": func(_ *literalKustomizationContext, data *string) {
			*data = "value: |\n  # " + literalKustomizationAction + "\n"
		},
		"malformed YAML": func(_ *literalKustomizationContext, data *string) {
			*data = "key: [\n# " + literalKustomizationAction + "\n"
		},
		"multiline action": func(_ *literalKustomizationContext, data *string) {
			*data = strings.Replace(redisKustomizationV023, literalKustomizationAction, "{{ .ProjectName\n}}", 1)
		},
		"trim": func(_ *literalKustomizationContext, data *string) {
			*data = strings.Replace(redisKustomizationV023, literalKustomizationAction, "{{- .ProjectName }}", 1)
		},
		"pipeline": func(_ *literalKustomizationContext, data *string) {
			*data = strings.Replace(redisKustomizationV023, literalKustomizationAction, "{{ .ProjectName | lower }}", 1)
		},
		"duplicate marker": func(_ *literalKustomizationContext, data *string) {
			*data = redisKustomizationV023 + "# " + literalKustomizationAction + "\n"
		},
		"unknown marker": func(_ *literalKustomizationContext, data *string) {
			*data = strings.Replace(redisKustomizationV023, literalKustomizationAction, "{{ .Other }}", 1)
		},
		"wrong path":     func(ctx *literalKustomizationContext, _ *string) { ctx.Path = "config/crd/bases/kustomization.yaml" },
		"wrong commit":   func(ctx *literalKustomizationContext, _ *string) { ctx.Commit = strings.Repeat("0", 40) },
		"wrong tag":      func(ctx *literalKustomizationContext, _ *string) { ctx.Tag = "v0.23.1" },
		"wrong hash":     func(ctx *literalKustomizationContext, _ *string) { ctx.MakefileSHA256 = strings.Repeat("0", 64) },
		"unsafe context": func(ctx *literalKustomizationContext, _ *string) { ctx.Project = "other" },
		"unsafe referrer": func(ctx *literalKustomizationContext, _ *string) {
			ctx.Referrers = append(ctx.Referrers, literalKustomizationReferrer{Path: "chart/templates/x.yaml", Kind: "template"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, data := valid, redisKustomizationV023
			mutate(&ctx, &data)
			if literalKustomizationAllowed(ctx, []byte(data)) {
				t.Fatal("unsafe input was accepted")
			}
		})
	}
}

func TestLiteralKustomizationCommentOnlyRefusesTemplateSyntaxOutsideComments(t *testing.T) {
	for name, data := range map[string]string{
		"quoted scalar":    "value: \"# " + literalKustomizationAction + "\"\n",
		"block scalar":     "value: |\n  # " + literalKustomizationAction + "\n",
		"malformed YAML":   "key: [\n# " + literalKustomizationAction + "\n",
		"multiline action": strings.Replace(redisKustomizationV023, literalKustomizationAction, "{{ .ProjectName\n}}", 1),
		"trim":             strings.Replace(redisKustomizationV023, literalKustomizationAction, "{{- .ProjectName }}", 1),
		"pipeline":         strings.Replace(redisKustomizationV023, literalKustomizationAction, "{{ .ProjectName | lower }}", 1),
		"duplicate marker": redisKustomizationV023 + "# " + literalKustomizationAction + "\n",
		"unknown marker":   strings.Replace(redisKustomizationV023, literalKustomizationAction, "{{ .Other }}", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if literalKustomizationCommentOnly([]byte(data)) {
				t.Fatal("unsafe template syntax was accepted")
			}
		})
	}
}

func TestLiteralKustomizationDeclaration(t *testing.T) {
	raw := []byte(`{"schema":"prufyx.io/crd-version-target/v1","target":{"project":"redis-operator","catalog":"community","name":"redis-operator","repo":"github.com/ot-container-kit/redis-operator","component":"pkg:github/ot-container-kit/redis-operator","factProject":"redis_operator","tagPrefixes":["v"],"minFrom":"0.22","paths":[{"path":"config/crd/bases","directory":true,"match":"^[^.][^/]*\\.ya?ml$","guard":"(?i)crd"}],"exclude":[],"literalKustomization":{"path":"config/rbac/kustomization.yaml","makefile":"Makefile","default":"config/default/kustomization.yaml"}}}`)
	tg, err := LoadTarget("target-redis-operator.json", raw)
	if err != nil || tg.LiteralKustomization == nil {
		t.Fatalf("literal declaration: target=%+v err=%v", tg.LiteralKustomization, err)
	}
	bad := strings.Replace(string(raw), "config/rbac/kustomization.yaml", "charts/x/kustomization.yaml", 1)
	if _, err := LoadTarget("target-redis-operator.json", []byte(bad)); err == nil {
		t.Fatal("unreviewed literal declaration was accepted")
	}
}

func TestLiteralKustomizationReferrers(t *testing.T) {
	const commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	repo, err := extract.ParseRepo(literalKustomizationRepo)
	if err != nil {
		t.Fatal(err)
	}
	files := memReader{commit + ":config/default/kustomization.yaml": []byte("resources:\n- ../rbac\n")}
	entries := []extract.TreeEntry{{Path: "config/default/kustomization.yaml", Type: "blob", Mode: "100644"}}
	refs, err := literalKustomizationReferrers(files, repo, commit, entries, "config/rbac/kustomization.yaml", "config/default/kustomization.yaml")
	if err != nil || len(refs) != 1 || refs[0] != (literalKustomizationReferrer{Path: "config/default/kustomization.yaml", Kind: "kustomize"}) {
		t.Fatalf("refs=%+v err=%v", refs, err)
	}
	files[commit+":charts/x/Chart.yaml"] = []byte("dependencies:\n- repository: file://../../config/rbac\n")
	entries = append(entries, extract.TreeEntry{Path: "charts/x/Chart.yaml", Type: "blob", Mode: "100644"})
	refs, err = literalKustomizationReferrers(files, repo, commit, entries, "config/rbac/kustomization.yaml", "config/default/kustomization.yaml")
	if err != nil || refs != nil {
		t.Fatalf("renderer refs=%+v err=%v", refs, err)
	}
}

func TestLiteralKustomizationSkipsOnlyProvenScanFile(t *testing.T) {
	info := summarize(kindData, []byte(redisKustomizationV023))
	fd, found, err := New(Target{}).classifyFile(nil, extract.RepoRef{}, "", scanFile{path: literalKustomizationPath, literal: true}, info, nil, nil)
	if err != nil || found || fd.Path != literalKustomizationPath {
		t.Fatalf("finding=%+v found=%t err=%v", fd, found, err)
	}
}

func TestLiteralKustomizationProofUsesPinnedSourceBytes(t *testing.T) {
	const commit = "ce3ffdb7ed430dc86d2208385d9516d7c19d52ba"
	repo, err := extract.ParseRepo(literalKustomizationRepo)
	if err != nil {
		t.Fatal(err)
	}
	read := func(p string) []byte {
		b, err := os.ReadFile(filepath.Join("testdata/literal-kustomization/v023", filepath.FromSlash(p)))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	files := memReader{}
	paths := []string{"Makefile", "config/default/kustomization.yaml", "config/rbac/kustomization.yaml"}
	entries := make([]extract.TreeEntry, 0, len(paths))
	for _, p := range paths {
		files[commit+":"+p] = read(p)
		entries = append(entries, extract.TreeEntry{Path: p, Type: "blob", Mode: "100644"})
	}
	tg := Target{Project: literalKustomizationProject, Repo: literalKustomizationRepo, LiteralKustomization: &LiteralKustomization{Path: literalKustomizationPath, Makefile: "Makefile", Default: "config/default/kustomization.yaml"}}
	ok, err := New(tg).literalKustomizationProof(files, repo, commit, "v0.23.0", entries)
	if err != nil || !ok[literalKustomizationPath] {
		t.Fatalf("proof=%v err=%v", ok, err)
	}
	info := summarize(kindData, files[commit+":"+literalKustomizationPath])
	_, found, err := New(Target{}).classifyFile(nil, repo, commit, scanFile{path: literalKustomizationPath}, info, nil, nil)
	if err != nil || !found {
		t.Fatalf("unproved file found=%t err=%v", found, err)
	}
	files[commit+":Makefile"] = append(files[commit+":Makefile"], 'x')
	if got, err := New(tg).literalKustomizationProof(files, repo, commit, "v0.23.0", entries); err != nil || got != nil {
		t.Fatalf("changed source proof=%v err=%v", got, err)
	}
	delete(files, commit+":Makefile")
	if _, err := New(tg).literalKustomizationProof(files, repo, commit, "v0.23.0", entries); err == nil {
		t.Fatal("missing source read was accepted")
	}
}

func TestLiteralKustomizationProofRefusesAdditionalInstallSurfaces(t *testing.T) {
	const commit = "ce3ffdb7ed430dc86d2208385d9516d7c19d52ba"
	repo, err := extract.ParseRepo(literalKustomizationRepo)
	if err != nil {
		t.Fatal(err)
	}
	read := func(p string) []byte {
		b, err := os.ReadFile(filepath.Join("testdata/literal-kustomization/v023", filepath.FromSlash(p)))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for name, extra := range map[string]struct {
		path string
		data string
	}{
		"Makefile": {"examples/Makefile", "install:\n\tkustomize build ../config/rbac\n"},
		"shell":    {"hack/install.sh", "#!/bin/sh\nkustomize build ../config/rbac\n"},
		"Helm":     {"charts/x/Chart.yaml", "dependencies:\n- repository: file://../../config/rbac\n"},
	} {
		t.Run(name, func(t *testing.T) {
			files := memReader{}
			paths := []string{"Makefile", "config/default/kustomization.yaml", "config/rbac/kustomization.yaml"}
			entries := make([]extract.TreeEntry, 0, len(paths)+1)
			for _, p := range paths {
				files[commit+":"+p] = read(p)
				entries = append(entries, extract.TreeEntry{Path: p, Type: "blob", Mode: "100644"})
			}
			files[commit+":"+extra.path] = []byte(extra.data)
			entries = append(entries, extract.TreeEntry{Path: extra.path, Type: "blob", Mode: "100644"})
			tg := Target{Project: literalKustomizationProject, Repo: literalKustomizationRepo, LiteralKustomization: &LiteralKustomization{Path: literalKustomizationPath, Makefile: "Makefile", Default: "config/default/kustomization.yaml"}}
			proof, err := New(tg).literalKustomizationProof(files, repo, commit, "v0.23.0", entries)
			if err != nil || proof != nil {
				t.Fatalf("proof=%v err=%v", proof, err)
			}
		})
	}
}

func redisLiteralContext(pin literalKustomizationPin) literalKustomizationContext {
	return literalKustomizationContext{
		Project: literalKustomizationProject, Repo: literalKustomizationRepo, Tag: pin.Tag, Commit: pin.Commit, Path: literalKustomizationPath,
		MakefileSHA256: pin.Makefile, DefaultSHA256: pin.Default,
		Referrers: []literalKustomizationReferrer{{Path: "config/default/kustomization.yaml", Kind: "kustomize"}},
	}
}

const redisKustomizationV023 = `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- auth_proxy_client_clusterrole.yaml
- auth_proxy_role.yaml
- auth_proxy_role_binding.yaml
- auth_proxy_service.yaml
- leader_election_role.yaml
- leader_election_role_binding.yaml
- redis_editor_role.yaml
- redis_viewer_role.yaml
- rediscluster_editor_role.yaml
- rediscluster_viewer_role.yaml
- role.yaml
- role_binding.yaml
- serviceaccount.yaml
# For each CRD, "Admin", "Editor" and "Viewer" roles are scaffolded by
# default, aiding admins in cluster management. Those roles are
# not used by the {{ .ProjectName }} itself. You can comment the following lines
# if you do not want those helpers be installed with your Project.
`

const redisKustomizationV024 = redisKustomizationV023 + `
patches:
  - target:
      group: rbac.authorization.k8s.io
      version: v1
      kind: ClusterRole
      name: manager-role
    patch: |
      - op: add
        path: /metadata/labels
        value:
          rbac.authorization.k8s.io/aggregate-to-admin: "true"
`

const redisKustomizationV026 = `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
# The following RBAC and Service protect the /metrics endpoint when the
# operator is started with --metrics-secure (controller-runtime's built-in
# authn/authz filter). They replace the deprecated kube-rbac-proxy sidecar.
- metrics_auth_role.yaml
- metrics_auth_role_binding.yaml
- metrics_reader_role.yaml
- metrics_service.yaml
- leader_election_role.yaml
- leader_election_role_binding.yaml
- redis_editor_role.yaml
- redis_viewer_role.yaml
- rediscluster_editor_role.yaml
- rediscluster_viewer_role.yaml
- role.yaml
- role_binding.yaml
- serviceaccount.yaml
# For each CRD, "Admin", "Editor" and "Viewer" roles are scaffolded by
# default, aiding admins in cluster management. Those roles are
# not used by the {{ .ProjectName }} itself. You can comment the following lines
# if you do not want those helpers be installed with your Project.

patches:
  - target:
      group: rbac.authorization.k8s.io
      version: v1
      kind: ClusterRole
      name: manager-role
    patch: |
      - op: add
        path: /metadata/labels
        value:
          rbac.authorization.k8s.io/aggregate-to-admin: "true"
`

const redisKustomizationV027 = `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
# The following RBAC and Service protect the /metrics endpoint when the
# operator is started with --metrics-secure (controller-runtime's built-in
# authn/authz filter). They replace the deprecated kube-rbac-proxy sidecar.
- metrics_auth_role.yaml
- metrics_auth_role_binding.yaml
- metrics_reader_role.yaml
- metrics_service.yaml
- leader_election_role.yaml
- leader_election_role_binding.yaml
- redis_editor_role.yaml
- redis_viewer_role.yaml
- rediscluster_editor_role.yaml
- rediscluster_viewer_role.yaml
- aggregate_view_role.yaml
- aggregate_edit_role.yaml
- role.yaml
- role_binding.yaml
- serviceaccount.yaml
# For each CRD, "Admin", "Editor" and "Viewer" roles are scaffolded by
# default, aiding admins in cluster management. Those roles are
# not used by the {{ .ProjectName }} itself. You can comment the following lines
# if you do not want those helpers be installed with your Project.
`
