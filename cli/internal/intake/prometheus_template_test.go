package intake

import (
	"reflect"
	"testing"
)

const promRuleHead = "apiVersion: monitoring.coreos.com/v1\nkind: PrometheusRule\nmetadata: {name: r}\nspec:\n  groups:\n  - name: g\n    rules:\n    - alert: A\n      expr: up == 0\n"

// Prometheus alert templates in a rule's annotation and label values are not
// unrendered Helm; anything else templated still is.
func TestDecodePrometheusRuleTemplates(t *testing.T) {
	doc := []string{"doc 0/-1 monitoring.coreos.com/v1 PrometheusRule /r"}
	omit := []string{"omit 0/-1 TEMPLATED"}
	cases := map[string]struct {
		in   string
		want []string
	}{
		"labels in annotation":     {promRuleHead + "      annotations:\n        summary: \"{{ $labels.instance }} down\"\n", doc},
		"value with pipe":          {promRuleHead + "      annotations:\n        summary: '{{ $value | humanizePercentage }} high, {{ $labels.job }}'\n", doc},
		"block scalar annotation":  {promRuleHead + "      annotations:\n        description: |\n          {{ $labels.pod }} at {{ $value }}\n", doc},
		"label value":              {promRuleHead + "      labels:\n        team: '{{ $labels.team }}'\n", doc},
		"humanize after value":     {promRuleHead + "      annotations:\n        summary: '{{ $value | humanize }} and {{ $value | printf \"%.2f\" }}'\n", doc},
		"nindent after labels":     {promRuleHead + "      annotations:\n        summary: '{{ $labels.x | nindent 4 }}'\n", omit},
		"toYaml after labels":      {promRuleHead + "      annotations:\n        summary: '{{ $labels | toYaml }}'\n", omit},
		"second function helm":     {promRuleHead + "      annotations:\n        summary: '{{ $labels.x | humanize | nindent 2 }}'\n", omit},
		"helm value in annotation": {promRuleHead + "      annotations:\n        summary: \"{{ .Values.x }}\"\n", omit},
		"helm after prom action":   {promRuleHead + "      annotations:\n        summary: \"{{ $labels.a }}{{ .Values.x }}\"\n", omit},
		"helm word inside action":  {promRuleHead + "      annotations:\n        summary: \"{{ $value | include \\\"x\\\" . }}\"\n", omit},
		"values via variable":      {promRuleHead + "      annotations:\n        summary: \"{{ $labels.a | .Values.b }}\"\n", omit},
		"if block in annotation":   {promRuleHead + "      annotations:\n        summary: \"{{- if .Values.on }}x\"\n", omit},
		"prom if still flagged":    {promRuleHead + "      annotations:\n        summary: \"{{ if $labels.a }}x{{ end }}\"\n", omit},
		"include in annotation":    {promRuleHead + "      annotations:\n        summary: '{{ include \"x\" . }}'\n", omit},
		"shell var in annotation":  {promRuleHead + "      annotations:\n        summary: \"${X}\"\n", omit},
		"templated expr":           {"apiVersion: monitoring.coreos.com/v1\nkind: PrometheusRule\nmetadata: {name: r}\nspec:\n  groups:\n  - name: g\n    rules:\n    - alert: A\n      expr: \"up == {{ $value }}\"\n", omit},
		"templated name":           {"apiVersion: monitoring.coreos.com/v1\nkind: PrometheusRule\nmetadata: {name: \"{{ $labels.x }}\"}\nspec: {groups: []}\n", omit},
		"templated annotation key": {promRuleHead + "      annotations:\n        \"{{ $labels.k }}\": v\n", omit},
		"templated alert name":     {"apiVersion: monitoring.coreos.com/v1\nkind: PrometheusRule\nmetadata: {name: r}\nspec:\n  groups:\n  - name: g\n    rules:\n    - alert: \"{{ $labels.a }}\"\n      expr: up\n", omit},
		"other kind not excepted":  {"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\ndata: {summary: \"{{ $labels.instance }}\"}\n", omit},
		"wrong group not excepted": {"apiVersion: example.com/v1\nkind: PrometheusRule\nmetadata: {name: a}\nspec:\n  groups:\n  - rules:\n    - annotations: {s: \"{{ $labels.i }}\"}\n", omit},
		"annotations elsewhere":    {"apiVersion: monitoring.coreos.com/v1\nkind: PrometheusRule\nmetadata:\n  name: r\n  annotations: {s: \"{{ $labels.i }}\"}\nspec: {groups: []}\n", omit},
	}
	for name, tc := range cases {
		w, err := Decode("t.yaml", []byte(tc.in))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := summary(w); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %q want %q", name, got, tc.want)
		}
	}
}
