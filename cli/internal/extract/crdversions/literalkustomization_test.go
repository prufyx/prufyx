// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"strings"
	"testing"
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
