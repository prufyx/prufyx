// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"os"
	"strings"
	"testing"
)

const chartYAML = "apiVersion: v2\nname: demo\nversion: 1.0.0\n"

// failPair runs a quiet pair with files at both releases and returns the
// later release's finding for the one template file among them.
func failPair(t *testing.T, files map[string]string, exclude ...Exclusion) *Finding {
	t.Helper()
	alpha := crd("Alpha", "v1beta1", "v1")
	_, proof := classPair(t, alpha, alpha, files, files, exclude...)
	if proof.To == nil || proof.To.Scan == nil {
		t.Fatal("no scan")
	}
	for p := range files {
		if strings.HasSuffix(strings.ToLower(p), ".tpl") || strings.HasSuffix(p, ".tmpl") {
			return findingOf(proof.To.Scan, p)
		}
	}
	t.Fatal("no template file")
	return nil
}

func isFailMessage(f *Finding) bool {
	return f != nil && f.Class == ClassNoDefinition && f.Reason == ReasonFailMessage && !f.blocks() && !f.opaque() && !f.unreadable()
}

func readVolcano(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/volcano-v1.16.0/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The jobflow partial of volcano v1.16.0 (a byte copy of the file at the
// tag) meets the rule at its real path: recorded, not blocking.
func TestFailMessagePartialVolcano(t *testing.T) {
	const root = "installer/helm/chart/volcano/"
	files := map[string]string{
		root + "Chart.yaml":                            chartYAML,
		root + "templates/_helpers.tpl":                readVolcano(t, "chart-helpers.tpl"),
		root + "charts/jobflow/Chart.yaml":             chartYAML,
		root + "charts/jobflow/templates/_helpers.tpl": readVolcano(t, "jobflow-helpers.tpl"),
	}
	alpha := crd("Alpha", "v1beta1", "v1")
	_, proof := classPair(t, alpha, alpha, files, files)
	f := findingOf(proof.To.Scan, root+"charts/jobflow/templates/_helpers.tpl")
	if !isFailMessage(f) || f.SHA256 == "" || f.Location != "" {
		t.Fatalf("jobflow: %+v", f)
	}
	// The main chart partial holds actions outside the closed list
	// (printf, assignment, pipes): unsupported, blocking.
	g := findingOf(proof.To.Scan, root+"templates/_helpers.tpl")
	if g == nil || g.Class != ClassUnsupported || g.Reason != ReasonSourceTemplate || !g.blocks() || !g.opaque() {
		t.Fatalf("chart helpers: %+v", g)
	}
}

// The same bytes under a default-excluded directory and a void entry are
// recorded with their place; under a reviewed exclusion the class is as
// before.
func TestFailMessagePartialPlaces(t *testing.T) {
	body := readVolcano(t, "jobflow-helpers.tpl")
	at := func(dir string) map[string]string {
		return map[string]string{dir + "Chart.yaml": chartYAML, dir + "templates/_h.tpl": body}
	}
	if f := failPair(t, at("test/chart/")); !isFailMessage(f) || f.Location != "default: test" {
		t.Fatalf("default dir: %+v", f)
	}
	// Void entry: an install target refers to the fixture directory.
	files := at(fixtureDir + "chart/")
	files["Makefile"] = "install:\n\tkubectl apply -f test/fixtures/crd.yaml\n"
	if f := failPair(t, files, fixtureExclusion()); !isFailMessage(f) || f.Location != "void: "+fixtureDir {
		t.Fatalf("void: %+v", f)
	}
	// Reviewed exclusion (not void): excluded-unread as before (16).
	if f := failPair(t, at(fixtureDir+"chart/"), fixtureExclusion()); f == nil || f.Class != ClassExcludedUnread || f.Reason == ReasonFailMessage {
		t.Fatalf("reviewed: %+v", f)
	}
	// Reviewed exclusion that declares copies: still unsupported, blocking.
	ex := fixtureExclusion()
	ex.Copies = true
	if f := failPair(t, at(fixtureDir+"chart/"), ex); f == nil || f.Class != ClassUnsupported || !f.blocks() {
		t.Fatalf("reviewed copies: %+v", f)
	}
}

// Every negative keeps the file unsupported (blocking, opaque).
func TestFailMessagePartialNegatives(t *testing.T) {
	const w = "CustomResourceDefinition"
	ok := "{{- define \"v\" -}}\n{{- fail \"" + w + " is not supported\" -}}\n{{- end -}}\n"
	const tpl = "chart/templates/_h.tpl"
	with := func(body string) map[string]string {
		return map[string]string{tpl: body, "chart/Chart.yaml": chartYAML}
	}
	cases := []struct {
		name  string
		files map[string]string
	}{
		// (11) the word in literal text, before or after a fail.
		{"literal text", with("kind: " + w + "\n" + ok)},
		{"literal text after", with(ok + "# " + w + "\n")},
		{"apiextensions in text", with(ok + "apiVersion: apiextensions.k8s.io/v1\n")},
		{"apiextensions in text, other case", with(ok + "APIExtensions.K8s.IO\n")},
		{"lowercase kind in text", with(ok + "customresourcedefinition\n")},
		// (12) the kind inside a define.
		{"kind in a define", with("{{- define \"crd\" -}}\napiVersion: apiextensions.k8s.io/v1\nkind: " + w + "\n{{- end -}}\n" + ok)},
		{"kind in a define name", with("{{- define \"" + w + "\" -}}x{{- end -}}\n" + ok)},
		// (13) the word in another action form.
		{"printf", with("{{ printf \"%s\" \"" + w + "\" }}\n")},
		{"print", with("{{ print \"" + w + "\" }}\n")},
		{"required", with("{{ required \"" + w + "\" .Values.x }}\n")},
		{"pipe", with("{{ \"" + w + "\" | quote }}\n")},
		{"fail piped", with("{{ fail \"" + w + "\" | quote }}\n")},
		{"fail printf", with("{{ fail (printf \"" + w + " %s\" .x) }}\n")},
		{"fail variable", with("{{ $m := \"" + w + "\" }}{{ fail $m }}\n")},
		{"fail two arguments", with("{{ fail \"" + w + "\" \"x\" }}\n")},
		{"fail concatenated", with("{{ fail (cat \"" + w + "\" \"x\") }}\n")},
		{"lowercase kind in another action", with(ok + "{{ print \"customresourcedefinition\" }}\n")},
		{"kind in a comment", with(ok + "{{/* " + w + " */}}\n")},
		{"kind in an if", with("{{ if eq .Kind \"" + w + "\" }}x{{ end }}\n")},
		{"fail in a branch, kind in another", with("{{ if .x }}{{ fail \"" + w + "\" }}{{ else }}kind: " + w + "{{ end }}\n")},
		// Actions outside the closed list can build the name while a fail
		// literal sits in a define that is never called.
		{"name built by print", with(ok + "{{ print \"CustomResource\" \"Definition\" }}\n")},
		{"name built by printf", with(ok + "{{ printf \"%s%s\" \"CustomResource\" \"Definition\" }}\n")},
		{"group built by print", with(ok + "apiVersion: {{ print \"apiextensions\" \".k8s.io/v1\" }}\n")},
		{"name built by print in a define", with("{{- define \"crd\" -}}{{ print \"CustomResource\" \"Definition\" }}{{- end -}}\n" + ok)},
		{"name built by assignment", with(ok + "{{ $a := \"CustomResource\" }}{{ $a }}Definition\n")},
		{"name built by tpl", with(ok + "{{ tpl \"Custom\" . }}\n")},
		{"include", with(ok + "{{ include \"other\" . }}\n")},
		{"template", with(ok + "{{ template \"other\" . }}\n")},
		{"name built from text around a comment", with(ok + "CustomResource{{/* x */}}Definition\n")},
		{"name built from text around if and end", with(ok + "CustomResource{{ if .Capabilities.APIVersions.Has \"a/v1\" }}{{ end }}Definition\n")},
		{"name built from text around a trimmed comment", with(ok + "Custom{{- /* x */ -}}ResourceDefinition\n")},
		{"group built from text around a comment", with(ok + "apiextensions{{/* x */}}.k8s.io\n")},
		{"mixed fail and emitting helper", with(ok + "{{ define \"h\" }}{{ .Values.x | quote }}{{ end }}\n")},
		{"if with another condition", with(ok + "{{ if .Values.x }}y{{ end }}\n")},
		{"if with a call", with(ok + "{{ if eq .Values.x \"y\" }}y{{ end }}\n")},
		{"if with has and a pipe", with(ok + "{{ if .Capabilities.APIVersions.Has \"a\" | not }}y{{ end }}\n")},
		{"range", with(ok + "{{ range .x }}{{ end }}\n")},
		{"bare value", with(ok + "{{ .Values.x }}\n")},
		// A comment that wraps a fail-shaped text refuses, trimmed or not.
		{"fail-shaped comment", with("{{/* fail \"" + w + "\" */}}\n")},
		{"fail-shaped trimmed comment", with("{{- /* fail \"" + w + "\" */ -}}\n")},
		{"fail-shaped comment beside a fail", with(ok + "{{/* fail \"" + w + "\" */}}\n")},
		{"fail-shaped trimmed comment beside a fail", with(ok + "{{- /* fail \"" + w + "\" */ -}}\n")},
		{"multiline comment with the name", with(ok + "{{/*\nx\n" + w + "\n*/}}\n")},
		// Escapes outside the closed set refuse.
		{"escape q", with("{{ fail \"" + w + "\\q\" }}\n")},
		{"escape x", with("{{ fail \"" + w + "\\x41\" }}\n")},
		{"incomplete hex escape", with("{{ fail \"" + w + "\\x4\" }}\n")},
		{"incomplete unicode escape", with("{{ fail \"" + w + "\\u12\" }}\n")},
		{"unicode escape", with("{{ fail \"" + w + "\\u0041\" }}\n")},
		{"long unicode escape", with("{{ fail \"" + w + "\\U00000041\" }}\n")},
		{"octal escape", with("{{ fail \"" + w + "\\101\" }}\n")},
		{"escaped single quote", with("{{ fail \"" + w + "\\'\" }}\n")},
		{"bell escape", with("{{ fail \"" + w + "\\a\" }}\n")},
		{"trailing backslash", with("{{ fail \"" + w + "\\\" }}\n")},
		// (14) path and chart conditions.
		{"not a partial name", map[string]string{"chart/templates/helpers.tpl": ok, "chart/Chart.yaml": chartYAML}},
		{"other extension", map[string]string{"chart/templates/_h.tmpl": ok, "chart/Chart.yaml": chartYAML}},
		{"upper case extension", map[string]string{"chart/templates/_h.TPL": ok, "chart/Chart.yaml": chartYAML}},
		{"not under templates", map[string]string{"chart/lib/_h.tpl": ok, "chart/Chart.yaml": chartYAML}},
		{"nested below templates", map[string]string{"chart/templates/sub/_h.tpl": ok, "chart/Chart.yaml": chartYAML, "chart/templates/Chart.yaml": chartYAML}},
		{"no chart file", map[string]string{tpl: ok}},
		{"chart file elsewhere", map[string]string{tpl: ok, "other/Chart.yaml": chartYAML}},
		{"chart file in the templates directory", map[string]string{tpl: ok, "chart/templates/Chart.yaml": chartYAML}},
		{"chart file wrong case", map[string]string{tpl: ok, "chart/chart.yaml": chartYAML}},
		// (15) malformed actions.
		{"unclosed action", with("{{- fail \"" + w + "\" -\n")},
		{"open inside action", with("{{ fail {{ \"" + w + "\" }}\n")},
		{"close inside literal", with("{{ fail \"" + w + " }} x\" }}\n")},
		{"close inside raw literal", with("{{ fail `" + w + " }} x` }}\n")},
		{"open inside literal", with("{{ fail \"" + w + " {{ x\" }}\n")},
		{"unclosed literal", with("{{ fail \"" + w + " }}\n")},
		{"unclosed comment", with(ok + "{{/* x }}\n")},
		{"comment without close delimiter", with(ok + "{{/* x */ }}\n")},
		{"trim marker without space", with("{{ fail \"" + w + "\"-}}\n")},
		{"newline in literal", with("{{ fail \"" + w + "\n\" }}\n")},
		{"unclosed action after a fail", with(ok + "{{ if .x \n")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := failPair(t, tc.files)
			if f == nil || f.Class != ClassUnsupported || f.Reason != ReasonSourceTemplate || !f.blocks() || !f.opaque() {
				t.Fatalf("%+v", f)
			}
		})
	}
}

// The accepted forms, as bytes.
func TestFailOnlyPartialForms(t *testing.T) {
	const w = "CustomResourceDefinition"
	yes := []string{
		"{{ fail \"" + w + " x\" }}",
		"{{- fail \"" + w + " x\" -}}",
		"{{-\tfail `" + w + " x` }}",
		"{{ fail \"a \\\" " + w + "\" }}",
		"{{ fail \"a \\\\ \\n \\r \\t " + w + "\" }}",
		"{{ define \"d\" }}x{{ end }}{{ fail \"" + w + "\" }}",
		"{{/* text */}}\n{{ fail \"" + w + "\" }}",
		"{{- /* text */ -}}\n{{ if .Capabilities.APIVersions.Has \"apiextensions.k8s.io/v1\" }}x{{ else }}{{ fail \"" + w + "\" }}{{ end }}",
	}
	for _, s := range yes {
		if !failOnlyPartial([]byte(s)) {
			t.Errorf("want accepted: %q", s)
		}
	}
	// Not accepted: no fail action at all (the kind is nowhere), a word
	// outside actions, oversized input.
	no := []string{"", "{{ fail \"\\u0043ustomResourceDefinition\" }}{{ fail \"" + w + "\\q\" }}", "{{ fail \"x\" }}", w, "{{ fail \"" + w + "\" }}" + w}
	for _, s := range no {
		if failOnlyPartial([]byte(s)) {
			t.Errorf("want refused: %q", s)
		}
	}
	if failOnlyPartial([]byte("{{ fail \"" + w + "\" }}" + strings.Repeat(" ", MaxFileBytes))) {
		t.Error("oversized input accepted")
	}
}
