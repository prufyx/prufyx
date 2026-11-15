// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"strings"
	"testing"
)

// The fixtures and rows below are copied verbatim from the extractor's own
// patch-fragment tests (extract/crdversions, TestFragmentReaders): the
// generator's predicate must reach the same verdict on each. The extractor's
// predicate is not exported, so this is a pinned copy run only through the
// generator: it will NOT catch a later change of the extractor's shape.

const (
	cainjectionFragment = "# The following patch adds a directive for certmanager to inject CA into the CRD\napiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  annotations:\n    cert-manager.io/inject-ca-from: $(CERTIFICATE_NAMESPACE)/$(CERTIFICATE_NAME)\n  name: alphas.synth.example.io\n"
	webhookFragment     = "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: alphas.synth.example.io\nspec:\n  preserveUnknownFields: false\n  conversion:\n    strategy: Webhook\n    webhook:\n      clientConfig:\n        caBundle: Cg==\n        service:\n          namespace: system\n          name: webhook-service\n          path: /convert\n          port: 443\n      conversionReviewVersions:\n      - v1\n"
	webhookV1beta1      = "apiVersion: apiextensions.k8s.io/v1beta1\nkind: CustomResourceDefinition\nmetadata:\n  name: alphas.synth.example.io\nspec:\n  conversion:\n    strategy: Webhook\n    webhookClientConfig:\n      caBundle: Cg==\n      service:\n        namespace: system\n        name: webhook-service\n        path: /convert\n    conversionReviewVersions: [\"v1beta1\"]\n"
)

func TestFragmentDocEqualsTheExtractorFixtures(t *testing.T) {
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
		values, err := fragDecodeStrict([]byte(tc.doc))
		if err != nil {
			t.Fatalf("%q: %v", tc.doc, err)
		}
		why := ""
		if len(values) == 0 {
			why = "no document"
		}
		for i, v := range values {
			if w := fragmentDoc(v); w != "" {
				why = w
				_ = i
				break
			}
		}
		if (tc.want == "") != (why == "") || !strings.Contains(why, tc.want) {
			t.Errorf("fragmentDoc(%q) = %q, want %q", tc.doc, why, tc.want)
		}
		// The same verdict through the whole content predicate (the fixtures
		// that name the kind; a template-free fixture needs no more).
		if strings.Contains(tc.doc, "CustomResourceDefinition") {
			if got := isPatchFragment([]byte(tc.doc)); got != (tc.want == "") {
				t.Errorf("isPatchFragment(%q) = %v, want %v", tc.doc, got, tc.want == "")
			}
		}
	}
	if got := isPatchFragment(nil); got {
		t.Error("no document accepted")
	}
	// The extractor's kustomization patch rows that depend on the bytes only
	// (the rows that depend on the inventory are decided by the extractor).
	for _, tc := range []struct {
		data string
		want bool
	}{
		{webhookFragment, true},
		{cainjectionFragment + "---\n" + webhookV1beta1, true},
		{webhookFragment + "  versions:\n  - name: v2\n    served: true\n    storage: false\n", false},
		{strings.Replace(webhookFragment, "Cg==", `"{{ .Values.ca }}"`, 1), false},
		{"- op: add\n  path: /spec/versions/-\n", false},
	} {
		if got := isPatchFragment([]byte(tc.data)); got != tc.want {
			t.Errorf("isPatchFragment(%q) = %v, want %v", tc.data, got, tc.want)
		}
	}
}
