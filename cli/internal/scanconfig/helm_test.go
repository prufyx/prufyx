// SPDX-License-Identifier: AGPL-3.0-only

package scanconfig

import (
	"errors"
	"reflect"
	"testing"
)

func TestParseHelmDeclarations(t *testing.T) {
	text := head + `target: {keda: 2.16.0}
declarations:
  helm:
    keda:
      chart: keda@https://kedacore.github.io/charts
      values: [values/base.yaml, values/prod.yaml]
      set: ["image.tag=2.16.0", 'a\.b=null']
      complete: true
`
	got, err := Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]HelmDeclaration{"keda": {
		Chart: "keda@https://kedacore.github.io/charts", Values: []string{"values/base.yaml", "values/prod.yaml"},
		Set: []string{"image.tag=2.16.0", `a\.b=null`}, Complete: ptr(true),
	}}
	if !reflect.DeepEqual(got.Declarations.Helm, want) {
		t.Fatalf("got %+v", got.Declarations.Helm)
	}
	minimal, err := Parse([]byte(head + "declarations: {helm: {keda: {chart: keda}}}\n"))
	if err != nil || !reflect.DeepEqual(minimal.Declarations.Helm, map[string]HelmDeclaration{"keda": {Chart: "keda"}}) {
		t.Fatalf("minimal %+v %v", minimal.Declarations.Helm, err)
	}
}

func TestParseHelmRefusals(t *testing.T) {
	for name, body := range map[string]string{
		"unknown project":   "{nope: {chart: x}}",
		"kubernetes":        "{kubernetes: {chart: x}}",
		"no chart":          "{keda: {values: [a.yaml]}}",
		"empty chart":       "{keda: {chart: ''}}",
		"chart with space":  "{keda: {chart: 'a b'}}",
		"unknown key":       "{keda: {chart: keda, valuesFiles: [a]}}",
		"values not list":   "{keda: {chart: keda, values: a.yaml}}",
		"values empty":      "{keda: {chart: keda, values: []}}",
		"values dotdot":     "{keda: {chart: keda, values: [../a.yaml]}}",
		"values absolute":   "{keda: {chart: keda, values: [/a.yaml]}}",
		"values directory":  "{keda: {chart: keda, values: [dir/]}}",
		"set not string":    "{keda: {chart: keda, set: [1]}}",
		"complete not bool": "{keda: {chart: keda, complete: 'yes'}}",
		"not a mapping":     "[keda]",
	} {
		if _, err := Parse([]byte(head + "declarations: {helm: " + body + "}\n")); !errors.Is(err, ErrConfig) {
			t.Errorf("%s: err=%v", name, err)
		}
	}
}

// TestMergeHelm: flags override the file key by key, per project.
func TestMergeHelm(t *testing.T) {
	cfg := Config{Declarations: DeclarationSet{Helm: map[string]HelmDeclaration{
		"keda": {Chart: "keda", Values: []string{"a.yaml"}, Set: []string{"x=1"}, Complete: ptr(true)},
	}}}
	got := Merge(cfg, FlagDeclarations{Helm: map[string]HelmFlags{
		"keda":    {Values: []string{"b.yaml"}, Complete: ptr(false)},
		"metallb": {Chart: "metallb"},
	}})
	keda := got.Helm["keda"]
	if keda.Chart != (Value[string]{Value: "keda", Set: true, Source: FromFile}) ||
		!reflect.DeepEqual(keda.Values, Value[[]string]{Value: []string{"b.yaml"}, Set: true, Source: FromFlag}) ||
		!reflect.DeepEqual(keda.Set, Value[[]string]{Value: []string{"x=1"}, Set: true, Source: FromFile}) ||
		keda.Complete != (Value[bool]{Value: false, Set: true, Source: FromFlag}) {
		t.Fatalf("keda %+v", keda)
	}
	if metallb := got.Helm["metallb"]; metallb.Chart.Value != "metallb" || metallb.Values.Set || metallb.Complete.Set {
		t.Fatalf("metallb %+v", metallb)
	}
	if Merge(Config{}, FlagDeclarations{}).Helm != nil {
		t.Fatal("no declaration gave a chart")
	}
}
