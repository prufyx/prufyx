// SPDX-License-Identifier: AGPL-3.0-only

package intake

import "testing"

// An omitted document records whether it holds a template control action
// it does not open and close within one value.
func TestOmissionOpenAction(t *testing.T) {
	for name, tc := range map[string]struct {
		raw  string
		open bool
	}{
		"if left open":              {"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\ndata: {x: \"{{- if .Values.on }}\"}\n", true},
		"end of an earlier action":  {"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\ndata: {x: \"{{- end }}\"}\n", true},
		"else alone":                {"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\ndata: {x: \"{{ else }}\"}\n", true},
		"range in a block scalar":   {"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\ndata:\n  x: |\n    {{- range .Values.jobs }}\n", true},
		"with in a key":             {"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\ndata: {\"{{ with .x }}\": y}\n", true},
		"define and block":          {"x: \"{{ define \\\"a\\\" }}{{ block \\\"b\\\" . }}{{ end }}\"\n", true},
		"not Kubernetes shaped":     {"x: \"{{- if .Values.on }}\"\n", true},
		"closed in one value":       {"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\ndata:\n  x: |\n    {{- if .on }}a{{- else if .b }}b{{- else }}c{{- end }}\n", false},
		"open and closed per value": {"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\ndata: {x: \"{{ range .a }}{{ end }}\", y: \"{{ with .b }}{{ end }}\"}\n", false},
		"no action":                 {"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: '{{ .Release.Name }}'}\n", false},
	} {
		t.Run(name, func(t *testing.T) {
			workspace, err := Decode("input", []byte(tc.raw))
			if err != nil || len(workspace.Omissions) != 1 || workspace.Omissions[0].OpenAction != tc.open {
				t.Fatalf("err %v omissions %+v", err, workspace.Omissions)
			}
		})
	}
}
