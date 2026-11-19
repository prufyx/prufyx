// SPDX-License-Identifier: AGPL-3.0-only

package intake

import (
	"errors"
	"strings"
	"testing"
)

const crdHead = "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: alertmanagerconfigs.monitoring.coreos.com\n"

func crdWithSchema(properties string) string {
	return crdHead + "spec:\n  group: monitoring.coreos.com\n  versions:\n  - name: v1alpha1\n    schema:\n      openAPIV3Schema:\n        type: object\n        properties:\n" + properties
}

// Published CRDs declare a deprecated field and its replacement whose names
// differ only in case (the Prometheus operator CRDs: proxyURL and proxyUrl,
// once per http config). Those are different property names, not a duplicate
// key.
func TestDecodeCRDPropertiesDifferingInCase(t *testing.T) {
	var b strings.Builder
	for _, name := range []string{"slackConfigs", "pushoverConfigs", "webhookConfigs"} {
		b.WriteString("          " + name + ":\n            type: object\n            properties:\n              proxyURL: {type: string}\n              proxyUrl: {type: string}\n")
	}
	workspace, err := Decode("crd.yaml", []byte(crdWithSchema(b.String())))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(workspace.Documents) != 1 || len(workspace.Omissions) != 0 || workspace.Documents[0].Kind != "CustomResourceDefinition" {
		t.Fatalf("documents %d omissions %v", len(workspace.Documents), workspace.Omissions)
	}
}

// The relaxation is limited to the property names of a CRD schema and never
// admits an exact duplicate.
func TestDecodeCaseKeysStillRefused(t *testing.T) {
	cases := map[string]string{
		"configmap data":          "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\ndata:\n  proxyURL: a\n  proxyUrl: b\n",
		"configmap metadata":      "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n  labels:\n    A: a\n    a: b\n",
		"non crd properties":      "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\nproperties:\n  proxyURL: a\n  proxyUrl: b\n",
		"crd metadata labels":     crdHead + "  labels:\n    A: a\n    a: b\nspec: {group: g}\n",
		"crd outside schema":      crdHead + "spec:\n  group: g\n  properties:\n    proxyURL: a\n    proxyUrl: b\n",
		"crd schema non-props":    crdWithSchema("          a: {type: string}\n") + "        x-note:\n          K: 1\n          k: 2\n",
		"exact duplicate":         crdWithSchema("          proxyURL: {type: string}\n          proxyURL: {type: string}\n"),
		"other kind with crd api": "apiVersion: apiextensions.k8s.io/v1\nkind: Other\nmetadata: {name: a}\nspec:\n  openAPIV3Schema:\n    properties:\n      proxyURL: a\n      proxyUrl: b\n",
	}
	for name, in := range cases {
		if _, err := Decode("x.yaml", []byte(in)); !errors.Is(err, ErrDecode) {
			t.Errorf("%s: err %v, want ErrDecode", name, err)
		}
	}
}

// A file that parses but is refused for a structural reason is never reported
// as unrendered templates, even when template syntax appears in it; a file
// the YAML reader cannot parse because of template syntax still is.
func TestDecodeRefusalReasonIsTrue(t *testing.T) {
	structural := "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\ndata:\n  proxyURL: a\n  proxyUrl: b\n---\napiVersion: v1\nkind: ConfigMap\nmetadata: {name: b}\ndata:\n  dash: '{\"t\": \"{{ $x }}\"}'\n"
	if workspace, err := Decode("s.yaml", []byte(structural)); !errors.Is(err, ErrDecode) || len(workspace.Omissions) != 0 {
		t.Fatalf("structural refusal: err %v omissions %v", err, workspace.Omissions)
	}
	deep := "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\ndata: " + strings.Repeat("[", MaxManifestDepth+2) + strings.Repeat("]", MaxManifestDepth+2) + "\nx: '{{ .Values.x }}'\n"
	if _, err := Decode("d.yaml", []byte(deep)); !errors.Is(err, ErrDecode) {
		t.Fatalf("depth refusal: err %v", err)
	}
	for name, in := range map[string]string{
		"helm value":  "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Values.name }}\n",
		"helm if":     "{{- if .Values.on }}\napiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\n{{- end }}\n",
		"after a crd": crdWithSchema("          a: {type: string}\n") + "---\nmetadata:\n  name: {{ .Values.n }}\n",
	} {
		workspace, err := Decode("t.yaml", []byte(in))
		if err != nil || len(workspace.Omissions) != 1 || workspace.Omissions[0].Reason != ReasonUnparseable {
			t.Errorf("%s: err %v omissions %v", name, err, workspace.Omissions)
		}
	}
}
