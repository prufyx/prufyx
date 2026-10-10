// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"fmt"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// The kubebuilder layout of the synthetic project: deploy/kustomization.yaml
// lists the listed definition, so deploy/ is a declared definition
// kustomization directory.
const synthKustomization = "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n- crds/a.yaml\n# patches:\n#- path: patches/webhook_in_alphas.yaml\n#  target:\n#    kind: CustomResourceDefinition\nconfigurations:\n- kustomizeconfig.yaml\n"

const (
	cainjectionFragment = "# The following patch adds a directive for certmanager to inject CA into the CRD\napiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  annotations:\n    cert-manager.io/inject-ca-from: $(CERTIFICATE_NAMESPACE)/$(CERTIFICATE_NAME)\n  name: alphas.synth.example.io\n"
	webhookFragment     = "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: alphas.synth.example.io\nspec:\n  preserveUnknownFields: false\n  conversion:\n    strategy: Webhook\n    webhook:\n      clientConfig:\n        caBundle: Cg==\n        service:\n          namespace: system\n          name: webhook-service\n          path: /convert\n          port: 443\n      conversionReviewVersions:\n      - v1\n"
	webhookV1beta1      = "apiVersion: apiextensions.k8s.io/v1beta1\nkind: CustomResourceDefinition\nmetadata:\n  name: alphas.synth.example.io\nspec:\n  conversion:\n    strategy: Webhook\n    webhookClientConfig:\n      caBundle: Cg==\n      service:\n        namespace: system\n        name: webhook-service\n        path: /convert\n    conversionReviewVersions: [\"v1beta1\"]\n"
	kustomizeConfig     = "nameReference:\n- kind: Service\n  version: v1\n  fieldSpecs:\n  - kind: CustomResourceDefinition\n    version: v1\n    group: apiextensions.k8s.io\n    path: spec/conversion/webhook/clientConfig/service/name\n\nnamespace:\n- kind: CustomResourceDefinition\n  group: apiextensions.k8s.io\n  path: spec/conversion/webhook/clientConfig/service/namespace\n  create: false\n\nvarReference:\n- path: metadata/annotations\n"
)

// legacyCRD renders one apiextensions.k8s.io/v1beta1 definition of the
// synthetic group, with a versions list (the last version stored; ":off"
// not served).
func legacyCRD(kind string, versions ...string) string {
	plural := strings.ToLower(kind) + "s"
	var b strings.Builder
	fmt.Fprintf(&b, "apiVersion: apiextensions.k8s.io/v1beta1\nkind: CustomResourceDefinition\nmetadata:\n  name: %s.%s\nspec:\n  group: %s\n  names:\n    kind: %s\n    plural: %s\n  scope: Namespaced\n  validation:\n    openAPIV3Schema:\n      type: object\n", plural, synthGroup, synthGroup, kind, plural)
	if len(versions) > 0 {
		first, _ := strings.CutSuffix(versions[0], ":off")
		fmt.Fprintf(&b, "  version: %s\n  versions:\n", first)
	}
	for i, v := range versions {
		name, off := strings.CutSuffix(v, ":off")
		fmt.Fprintf(&b, "  - name: %s\n    served: %v\n    storage: %v\n", name, !off, i == len(versions)-1)
	}
	return b.String()
}

// Kubebuilder patch fragments, transformer configurations and v1beta1
// copies: each is recognised only in its precise shape, and anything that
// can change the versions a definition serves (or that the scan cannot
// tell) keeps the file unread or a reference, which blocks attestation.
func TestKubebuilderScaffolding(t *testing.T) {
	// The listed definition serves v1beta1 and v1 at 1.0.0 and v1 at 1.1.0;
	// extra(versions) gives the files of a tag, from the versions it
	// serves.
	type files func(versions ...string) map[string]string
	same := func(m map[string]string) files {
		return func(...string) map[string]string { return m }
	}
	withKust := func(m map[string]string) files {
		return func(...string) map[string]string {
			out := map[string]string{"deploy/kustomization.yaml": synthKustomization}
			for k, v := range m {
				out[k] = v
			}
			return out
		}
	}
	cases := []struct {
		name       string
		extra      files
		status     string
		attestable bool
		class      string // the class of the one finding ("" none blocks)
		path       string // the file of that finding
		reason     string
	}{
		// Patch fragments.
		{name: "cainjection fragment", extra: withKust(map[string]string{"deploy/patches/cainjection_in_alphas.yaml": cainjectionFragment}), status: extract.PairDerived, attestable: true, class: ClassCRDPatch, path: "deploy/patches/cainjection_in_alphas.yaml", reason: "alphas.synth.example.io"},
		{name: "webhook fragment", extra: withKust(map[string]string{"deploy/patches/webhook_in_alphas.yaml": webhookFragment}), status: extract.PairDerived, attestable: true, class: ClassCRDPatch, path: "deploy/patches/webhook_in_alphas.yaml"},
		{name: "v1beta1 webhook fragment", extra: withKust(map[string]string{"deploy/patches/webhook_in_alphas.yaml": webhookV1beta1}), status: extract.PairDerived, attestable: true, class: ClassCRDPatch, path: "deploy/patches/webhook_in_alphas.yaml"},
		{name: "two fragments in one file", extra: withKust(map[string]string{"deploy/patches/conversion.yaml": webhookFragment + "---\n" + cainjectionFragment}), status: extract.PairDerived, attestable: true, class: ClassCRDPatch, path: "deploy/patches/conversion.yaml"},
		{name: "transformer configuration", extra: withKust(map[string]string{"deploy/kustomizeconfig.yaml": kustomizeConfig}), status: extract.PairDerived, attestable: true, class: ClassKustomizeConfig, path: "deploy/kustomizeconfig.yaml"},
		{name: "the whole kubebuilder layout", extra: withKust(map[string]string{"deploy/kustomizeconfig.yaml": kustomizeConfig, "deploy/patches/webhook_in_alphas.yaml": webhookFragment, "deploy/patches/cainjection_in_alphas.yaml": cainjectionFragment}), status: extract.PairDerived, attestable: true},

		// Adversarial fragments: each must block.
		{name: "fragment adding a version", extra: withKust(map[string]string{"deploy/patches/webhook_in_alphas.yaml": webhookFragment + "  versions:\n  - name: v2\n    served: true\n    storage: false\n"}), status: extract.PairWithheld, path: "deploy/patches/webhook_in_alphas.yaml", reason: `spec key "versions"`},
		{name: "fragment unserving a version", extra: withKust(map[string]string{"deploy/patches/served.yaml": "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: alphas.synth.example.io\nspec:\n  versions:\n  - name: v1\n    served: false\n"}), status: extract.PairWithheld, path: "deploy/patches/served.yaml", reason: `spec key "versions"`},
		{name: "fragment with a v1beta1 version", extra: withKust(map[string]string{"deploy/patches/version.yaml": "apiVersion: apiextensions.k8s.io/v1beta1\nkind: CustomResourceDefinition\nmetadata:\n  name: alphas.synth.example.io\nspec:\n  version: v2\n"}), status: extract.PairWithheld, reason: "deploy/patches/version.yaml is unread"},
		{name: "fragment changing the group", extra: withKust(map[string]string{"deploy/patches/group.yaml": "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: alphas.synth.example.io\nspec:\n  group: other.example.io\n"}), status: extract.PairWithheld, path: "deploy/patches/group.yaml", reason: `spec key "group"`},
		{name: "fragment deleting the definition", extra: withKust(map[string]string{"deploy/patches/delete.yaml": "$patch: delete\napiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: alphas.synth.example.io\n"}), status: extract.PairWithheld, path: "deploy/patches/delete.yaml", reason: `key "$patch"`},
		{name: "fragment replacing the version list", extra: withKust(map[string]string{"deploy/patches/retain.yaml": "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: alphas.synth.example.io\nspec:\n  $retainKeys:\n  - conversion\n  conversion:\n    strategy: None\n"}), status: extract.PairWithheld, path: "deploy/patches/retain.yaml", reason: `spec key "$retainKeys"`},
		{name: "fragment with an unknown conversion key", extra: withKust(map[string]string{"deploy/patches/conv.yaml": "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: alphas.synth.example.io\nspec:\n  conversion:\n    strategy: Webhook\n    versions: [v2]\n"}), status: extract.PairWithheld, path: "deploy/patches/conv.yaml", reason: `key "versions"`},
		{name: "fragment with another metadata key", extra: withKust(map[string]string{"deploy/patches/meta.yaml": "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: alphas.synth.example.io\n  finalizers: [x]\n"}), status: extract.PairWithheld, path: "deploy/patches/meta.yaml", reason: `metadata key "finalizers"`},
		{name: "fragment of an unlisted definition", extra: withKust(map[string]string{"deploy/patches/other.yaml": strings.ReplaceAll(cainjectionFragment, "alphas.", "gammas.")}), status: extract.PairWithheld, path: "deploy/patches/other.yaml", reason: "gammas.synth.example.io, which the listed paths do not define"},
		{name: "templated fragment", extra: withKust(map[string]string{"deploy/patches/t.yaml": strings.Replace(webhookFragment, "caBundle: Cg==", `caBundle: "{{caBundle}}"`, 1)}), status: extract.PairWithheld, reason: "deploy/patches/t.yaml is unread"},
		{name: "fragment with a non-mapping document", extra: withKust(map[string]string{"deploy/patches/two.yaml": cainjectionFragment + "---\n- a\n"}), status: extract.PairWithheld, path: "deploy/patches/two.yaml", reason: "document 2: not a mapping"},
		{name: "fragment outside a definition kustomization directory", extra: same(map[string]string{"other/patches/webhook_in_alphas.yaml": webhookFragment}), status: extract.PairWithheld, reason: "other/patches/webhook_in_alphas.yaml is unread"},
		{name: "kustomization that does not list the definitions", extra: same(map[string]string{"deploy/kustomization.yaml": "resources:\n- other.yaml\n", "deploy/patches/webhook_in_alphas.yaml": webhookFragment}), status: extract.PairWithheld, reason: "deploy/patches/webhook_in_alphas.yaml is unread"},
		{name: "kustomization at the repository root", extra: same(map[string]string{"kustomization.yaml": "resources:\n- deploy/crds/a.yaml\n", "patches/webhook_in_alphas.yaml": webhookFragment}), status: extract.PairWithheld, reason: "patches/webhook_in_alphas.yaml is unread"},

		// Adversarial transformer configurations.
		{name: "transformer configuration reaching the versions", extra: withKust(map[string]string{"deploy/kustomizeconfig.yaml": strings.Replace(kustomizeConfig, "path: spec/conversion/webhook/clientConfig/service/namespace", "path: spec/versions/name", 1)}), status: extract.PairDerived, class: ClassReference, path: "deploy/kustomizeconfig.yaml", reason: `path "spec/versions/name"`},
		{name: "transformer configuration of another group", extra: withKust(map[string]string{"deploy/kustomizeconfig.yaml": strings.Replace(kustomizeConfig, "  group: apiextensions.k8s.io\n  path: spec/conversion/webhook/clientConfig/service/namespace", "  path: spec/conversion/webhook/clientConfig/service/namespace", 1)}), status: extract.PairDerived, class: ClassReference, path: "deploy/kustomizeconfig.yaml", reason: "without the apiextensions.k8s.io group"},
		{name: "transformer configuration with other transformers", extra: withKust(map[string]string{"deploy/kustomizeconfig.yaml": kustomizeConfig + "replicas:\n- kind: CustomResourceDefinition\n  path: spec/versions\n"}), status: extract.PairDerived, class: ClassReference, path: "deploy/kustomizeconfig.yaml", reason: `key "replicas"`},
		{name: "transformer configuration naming the kind as a reference", extra: withKust(map[string]string{"deploy/kustomizeconfig.yaml": "nameReference:\n- kind: CustomResourceDefinition\n  fieldSpecs:\n  - kind: Deployment\n    path: spec/template\n"}), status: extract.PairDerived, class: ClassReference, path: "deploy/kustomizeconfig.yaml", reason: "a referenced kind"},
		{name: "transformer configuration reaching every kind's versions", extra: withKust(map[string]string{"deploy/kustomizeconfig.yaml": kustomizeConfig + "- path: spec/versions/0/name\n"}), status: extract.PairDerived, class: ClassReference, path: "deploy/kustomizeconfig.yaml", reason: `path "spec/versions/0/name"`},
		{name: "transformer configuration outside a definition kustomization directory", extra: same(map[string]string{"other/kustomizeconfig.yaml": kustomizeConfig}), status: extract.PairDerived, class: ClassReference, path: "other/kustomizeconfig.yaml", reason: "defines none at the top level"},

		// Kustomization patches that are fragments or conversion operations.
		{name: "kustomization patch that is a fragment", extra: same(map[string]string{
			"deploy/kustomization.yaml":             "resources:\n- crds/a.yaml\npatches:\n- path: patches/webhook_in_alphas.yaml\n  target:\n    kind: CustomResourceDefinition\n    name: alphas.synth.example.io\n",
			"deploy/patches/webhook_in_alphas.yaml": webhookFragment,
		}), status: extract.PairDerived, attestable: true},
		{name: "kustomization patch that is a fragment adding a version", extra: same(map[string]string{
			"deploy/kustomization.yaml": "resources:\n- other.yaml\npatches:\n- path: patches/add.yaml\n  target:\n    kind: CustomResourceDefinition\n    name: alphas.synth.example.io\n",
			"deploy/patches/add.yaml":   "- op: add\n  path: /spec/versions/-\n  value: {name: v2, served: true, storage: false}\n",
		}), status: extract.PairDerived, class: ClassReference, path: "deploy/kustomization.yaml", reason: "outside version schemas, conversion settings"},
		{name: "kustomization conversion operation", extra: same(map[string]string{
			"deploy/kustomization.yaml":      "resources:\n- crds/a.yaml\npatches:\n- path: patches/conversion.yaml\n  target:\n    kind: CustomResourceDefinition\n",
			"deploy/patches/conversion.yaml": "- op: add\n  path: /spec/conversion\n  value:\n    strategy: Webhook\n- op: replace\n  path: /spec/preserveUnknownFields\n  value: false\n",
		}), status: extract.PairDerived, attestable: true},
		{name: "kustomization conversion-like path", extra: same(map[string]string{
			"deploy/kustomization.yaml":      "resources:\n- crds/a.yaml\npatches:\n- path: patches/conversion.yaml\n  target:\n    kind: CustomResourceDefinition\n",
			"deploy/patches/conversion.yaml": "- op: add\n  path: /spec/preserveUnknownFields/x\n  value: false\n",
		}), status: extract.PairDerived, class: ClassReference, path: "deploy/kustomization.yaml", reason: "outside version schemas"},

		// Kustomization entries that select without a literal kind, and empty field spec values.
		{name: "kustomization patch selecting by name", extra: same(map[string]string{
			"deploy/kustomization.yaml": "resources:\n- crds/a.yaml\npatches:\n- path: patches/p.yaml\n  target:\n    name: alphas.synth.example.io\n",
			"deploy/patches/p.yaml":     "- op: replace\n  path: /spec/versions/0/served\n  value: false\n",
		}), status: extract.PairDerived, class: ClassReference, path: "deploy/kustomization.yaml", reason: "without naming a kind other than"},
		{name: "kustomization patch selecting by group", extra: same(map[string]string{
			"deploy/kustomization.yaml": "resources:\n- crds/a.yaml\npatches:\n- path: patches/p.yaml\n  target:\n    group: apiextensions.k8s.io\n",
			"deploy/patches/p.yaml":     "- op: replace\n  path: /spec/versions/0/served\n  value: false\n",
		}), status: extract.PairDerived, class: ClassReference, path: "deploy/kustomization.yaml", reason: "without naming a kind other than"},
		{name: "kustomization patch selecting by kind regex", extra: same(map[string]string{
			"deploy/kustomization.yaml": "resources:\n- crds/a.yaml\npatches:\n- path: patches/p.yaml\n  target:\n    kind: CustomResourceDefinitio.\n",
			"deploy/patches/p.yaml":     "- op: replace\n  path: /spec/versions/0/served\n  value: false\n",
		}), status: extract.PairDerived, class: ClassReference, path: "deploy/kustomization.yaml", reason: "without naming a kind other than"},
		{name: "kustomization patch selecting by label selector", extra: same(map[string]string{
			"deploy/kustomization.yaml": "resources:\n- crds/a.yaml\npatches:\n- path: patches/p.yaml\n  target:\n    labelSelector: app=x\n",
			"deploy/patches/p.yaml":     "- op: replace\n  path: /spec/versions/0/served\n  value: false\n",
		}), status: extract.PairDerived, class: ClassReference, path: "deploy/kustomization.yaml", reason: "without naming a kind other than"},
		{name: "kustomization patch selecting with an empty target", extra: same(map[string]string{
			"deploy/kustomization.yaml": "resources:\n- crds/a.yaml\npatches:\n- path: patches/p.yaml\n  target:\n    {}\n",
			"deploy/patches/p.yaml":     "- op: replace\n  path: /spec/versions/0/served\n  value: false\n",
		}), status: extract.PairDerived, class: ClassReference, path: "deploy/kustomization.yaml", reason: "without naming a kind other than"},
		{name: "kustomization patch with an alternation kind", extra: same(map[string]string{
			"deploy/kustomization.yaml": "resources:\n- crds/a.yaml\npatches:\n- path: patches/p.yaml\n  target:\n    kind: Deployment|CustomResourceDefinition\n",
			"deploy/patches/p.yaml":     "- op: replace\n  path: /spec/versions/0/served\n  value: false\n",
		}), status: extract.PairDerived, class: ClassReference, path: "deploy/kustomization.yaml", reason: "without naming a kind other than"},
		{name: "kustomization replacement selecting by name", extra: same(map[string]string{
			"deploy/kustomization.yaml": "resources:\n- crds/a.yaml\nreplacements:\n- source:\n    kind: ConfigMap\n    name: c\n  targets:\n  - select:\n      name: alphas.synth.example.io\n    fieldPaths:\n    - spec.group\n",
			"deploy/patches/p.yaml":     "- op: replace\n  path: /spec/versions/0/served\n  value: false\n",
		}), status: extract.PairDerived, class: ClassReference, path: "deploy/kustomization.yaml", reason: "replacements target"},
		{name: "kustomization replacements file", extra: same(map[string]string{
			"deploy/kustomization.yaml": "resources:\n- crds/a.yaml\nreplacements:\n- path: r.yaml\n",
			"deploy/patches/p.yaml":     "- op: replace\n  path: /spec/versions/0/served\n  value: false\n",
		}), status: extract.PairDerived, class: ClassReference, path: "deploy/kustomization.yaml", reason: "replacements entry"},
		{name: "kustomization patch and replacement of a literal other kind", extra: same(map[string]string{
			"deploy/kustomization.yaml": "resources:\n- crds/a.yaml\npatches:\n- path: patches/p.yaml\n  target:\n    kind: Deployment\n    name: x\nreplacements:\n- source:\n    kind: ConfigMap\n  targets:\n  - select:\n      kind: Deployment\n    fieldPaths:\n    - spec.replicas\n",
		}), status: extract.PairDerived, attestable: true},
		{name: "transformer configuration with an empty kind", extra: same(map[string]string{
			"deploy/kustomization.yaml":   "resources:\n- crds/a.yaml\nnamespace: other.example.io\nconfigurations:\n- kustomizeconfig.yaml\n",
			"deploy/kustomizeconfig.yaml": strings.Replace(kustomizeConfig, "  create: false\n", "  create: false\n- kind: \"\"\n  path: spec/group\n", 1),
		}), status: extract.PairDerived, class: ClassReference, path: "deploy/kustomizeconfig.yaml", reason: "an empty kind"},

		// Transformer configurations that never contain the kind name.
		{name: "kind-less configuration reaching the versions", extra: withKust(map[string]string{"deploy/kustomizeconfig.yaml": "namespace:\n- path: spec/versions\n  create: false\n"}), status: extract.PairDerived, class: ClassReference, path: "deploy/kustomizeconfig.yaml", reason: `path "spec/versions"`},
		{name: "kind-less configuration reaching the group", extra: withKust(map[string]string{"deploy/kustomizeconfig.yaml": "namespace:\n- path: spec/group\n"}), status: extract.PairDerived, class: ClassReference, path: "deploy/kustomizeconfig.yaml", reason: `path "spec/group"`},
		{name: "kind-less configuration under another file name", extra: same(map[string]string{
			"deploy/kustomization.yaml": "resources:\n- crds/a.yaml\nconfigurations:\n- cfg/names.yaml\n",
			"deploy/cfg/names.yaml":     "commonLabels:\n- path: spec/versions/0/name\n",
		}), status: extract.PairDerived, class: ClassReference, path: "deploy/cfg/names.yaml", reason: "spec/versions/0/name"},
		{name: "unparseable configuration", extra: withKust(map[string]string{"deploy/kustomizeconfig.yaml": "namespace: [\n"}), status: extract.PairDerived, class: ClassReference, path: "deploy/kustomizeconfig.yaml", reason: "not strictly decodable"},
		{name: "configurations entry that is remote", extra: same(map[string]string{
			"deploy/kustomization.yaml": "resources:\n- crds/a.yaml\nconfigurations:\n- https://example.invalid/c.yaml\n",
		}), status: extract.PairDerived, class: ClassReference, path: "deploy/kustomization.yaml", reason: "not a local file"},
		{name: "kind-less metadata-only configuration", extra: withKust(map[string]string{"deploy/kustomizeconfig.yaml": "commonLabels:\n- path: metadata/labels\n  create: true\nvarReference:\n- path: metadata/annotations\n"}), status: extract.PairDerived, attestable: true, class: ClassKustomizeConfig, path: "deploy/kustomizeconfig.yaml"},

		// v1beta1 copies.
		{name: "v1beta1 copy", extra: func(v ...string) map[string]string {
			return map[string]string{"deploy/v1beta1/a.yaml": legacyCRD("Alpha", v...)}
		}, status: extract.PairDerived, attestable: true, class: ClassLegacyCopy, path: "deploy/v1beta1/a.yaml"},
		{name: "v1beta1 copy with a single version", extra: func(v ...string) map[string]string {
			if len(v) > 1 {
				return map[string]string{"deploy/v1beta1/a.yaml": legacyCRD("Alpha", v...)}
			}
			return map[string]string{"deploy/v1beta1/a.yaml": strings.Replace(legacyCRD("Alpha"), "  scope: Namespaced\n", "  scope: Namespaced\n  version: "+v[0]+"\n", 1)}
		}, status: extract.PairDerived, attestable: true, class: ClassLegacyCopy, path: "deploy/v1beta1/a.yaml"},
		{name: "v1beta1 copy beside a v1 definition", extra: func(v ...string) map[string]string {
			return map[string]string{"install.yaml": "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: x\n---\n" + crd("Alpha", v...) + "---\n" + legacyCRD("Alpha", v...)}
		}, status: extract.PairDerived, attestable: true, class: ClassLegacyCopy, path: "install.yaml"},
		{name: "v1beta1 copy serving another version", extra: func(v ...string) map[string]string {
			return map[string]string{"deploy/v1beta1/a.yaml": legacyCRD("Alpha", append([]string{"v2"}, v...)...)}
		}, status: extract.PairWithheld, reason: "deploy/v1beta1/a.yaml defines alphas.synth.example.io differently from the listed paths"},
		{name: "v1beta1 copy not serving a version", extra: func(v ...string) map[string]string {
			// The first served version is not served; the last entry
			// stays the storage version.
			off := append([]string{v[0] + ":off"}, v[1:]...)
			if len(v) == 1 {
				off = append(off, "v0")
			}
			return map[string]string{"deploy/v1beta1/a.yaml": legacyCRD("Alpha", off...)}
		}, status: extract.PairWithheld, reason: "defines alphas.synth.example.io differently"},
		{name: "v1beta1 copy of an unlisted definition", extra: same(map[string]string{"deploy/v1beta1/g.yaml": legacyCRD("Gamma", "v1")}), status: extract.PairDerived, class: ClassExtra, path: "deploy/v1beta1/g.yaml"},
		{name: "v1beta1 version not first in the list", extra: same(map[string]string{"deploy/v1beta1/a.yaml": strings.Replace(legacyCRD("Alpha", "v1beta1", "v1"), "  version: v1beta1\n", "  version: v1\n", 1)}), status: extract.PairWithheld, reason: "deploy/v1beta1/a.yaml is unread (the file document 1: spec.version v1 of alphas.synth.example.io is not the first entry"},
		{name: "v1beta1 with two storage versions", extra: same(map[string]string{"deploy/v1beta1/a.yaml": strings.Replace(legacyCRD("Alpha", "v1beta1", "v1"), "storage: false", "storage: true", 1)}), status: extract.PairWithheld, reason: "2 storage versions"},
		{name: "v1beta1 without served flags", extra: same(map[string]string{"deploy/v1beta1/a.yaml": strings.Replace(legacyCRD("Alpha", "v1"), "    served: true\n", "", 1)}), status: extract.PairWithheld, reason: "does not state served and storage"},
		{name: "v1beta1 with neither version nor versions", extra: same(map[string]string{"deploy/v1beta1/a.yaml": legacyCRD("Alpha")}), status: extract.PairWithheld, reason: "neither spec.version nor spec.versions"},
		{name: "v1beta2 definition", extra: same(map[string]string{"deploy/v1beta1/a.yaml": strings.Replace(legacyCRD("Alpha", "v1"), "apiextensions.k8s.io/v1beta1", "apiextensions.k8s.io/v1beta2", 1)}), status: extract.PairWithheld, reason: "deploy/v1beta1/a.yaml is unread"},
		{name: "templated v1beta1 copy", extra: same(map[string]string{"deploy/v1beta1/a.yaml": "{{- if .Values.crds }}\n" + legacyCRD("Alpha", "v1")}), status: extract.PairWithheld, reason: "deploy/v1beta1/a.yaml is unread"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			from := map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1beta1", "v1")}
			to := map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}
			for p, c := range tc.extra("v1beta1", "v1") {
				from[p] = c
			}
			for p, c := range tc.extra("v1") {
				to[p] = c
			}
			s := newSynth(release{"v1.0.0", from}, release{"v1.1.0", to})
			out := runSynth(t, synthTarget(), s)
			p, proof := pairOf(t, out, "1.0.0", "1.1.0")
			if tc.status == extract.PairWithheld {
				if p.Status != extract.PairWithheld || !strings.Contains(p.Reason, tc.reason) || (tc.path != "" && !strings.Contains(p.Reason, tc.path+" is unread")) {
					t.Fatalf("pair %s %q, want withheld %q (%s)", p.Status, p.Reason, tc.reason, tc.path)
				}
				return
			}
			if p.Status != tc.status || proof.Completeness.Attestable != tc.attestable || len(p.Rules) != 1 {
				t.Fatalf("pair %s %q rules %v completeness %+v findings %+v", p.Status, p.Reason, p.Rules, proof.Completeness, proof.To.Scan.Findings)
			}
			for _, inv := range []*Inventory{proof.From, proof.To} {
				var found *Finding
				for i, f := range inv.Scan.Findings {
					if tc.class != "" && f.Path == tc.path {
						found = &inv.Scan.Findings[i]
						continue
					}
					if f.blocks() {
						t.Fatalf("%s: unexpected finding %+v", inv.Tag, f)
					}
				}
				if tc.class == "" {
					continue
				}
				if found == nil || found.Class != tc.class || !strings.Contains(found.Detail, tc.reason) {
					t.Fatalf("%s: finding %+v, want %s %q (findings %+v)", inv.Tag, found, tc.class, tc.reason, inv.Scan.Findings)
				}
				if found.blocks() == tc.attestable {
					t.Fatalf("%s: finding %+v blocks %v", inv.Tag, found, found.blocks())
				}
			}
			if !tc.attestable && (proof.Completeness.Scan || !strings.Contains(strings.Join(proof.Completeness.Reasons, "\n"), "found "+tc.class)) {
				t.Fatalf("completeness %+v", proof.Completeness)
			}
		})
	}
}

// A recognised file under a reviewed exclusion keeps its class; under a
// default-excluded directory it is recorded with its location. Neither
// blocks.
func TestKubebuilderScaffoldingLocations(t *testing.T) {
	files := map[string]string{
		"deploy/crds/a.yaml":                         crd("Alpha", "v1"),
		"deploy/kustomization.yaml":                  synthKustomization,
		"deploy/test/patches/webhook_in_alphas.yaml": webhookFragment,
		"deploy/v1beta1/a.yaml":                      legacyCRD("Alpha", "v1"),
	}
	s := newSynth(release{"v1.0.0", files}, release{"v1.1.0", files})
	out := runSynth(t, synthTarget(Exclusion{Path: "deploy/v1beta1/", Reason: "copies for clusters before 1.16"}), s)
	_, proof := pairOf(t, out, "1.0.0", "1.1.0")
	got := map[string]string{}
	for _, f := range proof.To.Scan.Findings {
		got[f.Path] = f.Class + "|" + f.Location
	}
	want := map[string]string{"deploy/test/patches/webhook_in_alphas.yaml": ClassCRDPatch + "|default: test", "deploy/v1beta1/a.yaml": ClassLegacyCopy + "|deploy/v1beta1/"}
	if fmt.Sprint(got) != fmt.Sprint(want) || !proof.Completeness.Scan {
		t.Fatalf("findings %v, want %v; completeness %+v", got, want, proof.Completeness)
	}
}

// The readers on their own: every accepted shape, and the refusals that
// keep a file unread.
func TestFragmentReaders(t *testing.T) {
	for _, tc := range []struct {
		doc  string
		want string // "" accepted, else a substring of the refusal
	}{
		{cainjectionFragment, ""},
		{webhookFragment, ""},
		{webhookV1beta1, ""},
		{"apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: alphas.synth.example.io\nspec:\n  conversion:\n    strategy: Webhook\n    webhook:\n      clientConfig:\n        url: https://example.invalid/convert\n", ""},
		{"apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  labels:\n    a: b\n  name: alphas.synth.example.io\n", ""},
		{"apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: alphas.synth.example.io\nstatus: {}\n", `key "status"`},
		{"apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata: {}\n", "metadata.name"},
		{"apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\n", "no metadata"},
		{"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n", "apiVersion"},
		{"apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinitionList\nmetadata:\n  name: x\n", "kind"},
		{"apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: x\n  labels:\n    a: 1\n", "metadata.labels"},
		{"apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: x\nspec:\n  preserveUnknownFields: \"no\"\n", "preserveUnknownFields"},
		{"apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: x\nspec:\n  conversion:\n    strategy: Other\n", "strategy"},
		{"apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: x\nspec:\n  conversion:\n    webhook:\n      clientConfig:\n        service:\n          port: \"443\"\n", "service.port"},
		{"apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: x\nspec:\n  conversion:\n    webhook:\n      clientConfig:\n        service:\n          selector: {}\n", `service key "selector"`},
		{"apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: x\nspec:\n  conversion:\n    webhook:\n      conversionReviewVersions: [1]\n", "conversionReviewVersions"},
		{"apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: x\nspec:\n  names:\n    kind: Other\n", `spec key "names"`},
		{"apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: x\nspec:\n  scope: Cluster\n", `spec key "scope"`},
	} {
		_, values, err := decodeStrict([]byte(tc.doc))
		must(t, err)
		fr := readFragments(values)
		if (tc.want == "") != (fr.problem == "") || !strings.Contains(fr.problem, tc.want) {
			t.Errorf("readFragments(%q) = %q, want %q", tc.doc, fr.problem, tc.want)
		}
	}
	if fr := readFragments(nil); fr.problem == "" {
		t.Error("no document accepted")
	}
	// A kustomization's strategic merge patch: accepted only as a fragment
	// of a listed definition, never when it touches the versions.
	inv := &Inventory{CRDs: []CRD{{Name: "alphas.synth.example.io"}}}
	for _, tc := range []struct {
		data string
		want bool
	}{
		{webhookFragment, true},
		{cainjectionFragment + "---\n" + webhookV1beta1, true},
		{webhookFragment + "  versions:\n  - name: v2\n    served: true\n    storage: false\n", false},
		{strings.ReplaceAll(webhookFragment, "alphas.", "gammas."), false},
		{strings.Replace(webhookFragment, "Cg==", `"{{ .Values.ca }}"`, 1), false},
		{"- op: add\n  path: /spec/versions/-\n", false},
	} {
		if got := fragmentPatch([]byte(tc.data), inv); got != tc.want {
			t.Errorf("fragmentPatch(%q) = %v, want %v", tc.data, got, tc.want)
		}
	}
}
