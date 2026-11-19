// SPDX-License-Identifier: AGPL-3.0-only

package chartapisurface

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/servedapis"
)

const chartYAML = "apiVersion: v2\nname: demo\nversion: 1.2.3\n"

// build makes a chart archive from path -> content under one root directory.
func build(t testing.TB, files map[string]string) []byte {
	t.Helper()
	if _, ok := files["Chart.yaml"]; !ok {
		files["Chart.yaml"] = chartYAML
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, n := range names {
		body := files[n]
		if err := tw.WriteHeader(&tar.Header{Name: "demo/" + n, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	zw.Close()
	return buf.Bytes()
}

func read(t testing.TB, files map[string]string) *Ledger {
	t.Helper()
	l, err := Read(build(t, files))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func codes(l *Ledger) []string {
	var out []string
	for _, w := range l.Withheld {
		out = append(out, w.Code)
	}
	return out
}

func hasCode(l *Ledger, c string) bool {
	for _, w := range l.Withheld {
		if w.Code == c {
			return true
		}
	}
	return false
}

func pairs(l *Ledger) string {
	var s []string
	for _, p := range l.Pairs() {
		s = append(s, p.APIVersion+" "+p.Kind)
	}
	return strings.Join(s, ",")
}

func TestLiteralComplete(t *testing.T) {
	l := read(t, map[string]string{"templates/a.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: x\n---\n# second\napiVersion: policy/v1beta1\nkind: PodDisruptionBudget\n"})
	if l.Status != StatusComplete || len(l.Withheld) != 0 {
		t.Fatalf("%+v", l.Withheld)
	}
	if pairs(l) != "apps/v1 Deployment,policy/v1beta1 PodDisruptionBudget" {
		t.Fatal(pairs(l))
	}
	for _, e := range l.APIs {
		if e.Conditional || e.File != "templates/a.yaml" || e.VersionGroup != GroupLiteral {
			t.Fatalf("%+v", e)
		}
	}
	if l.APIs[1].Line != 7 || l.APIs[0].Line != 1 {
		t.Fatalf("lines %+v", l.APIs)
	}
}

func TestNestedKeysAreNotDocuments(t *testing.T) {
	l := read(t, map[string]string{"templates/a.yaml": "apiVersion: v1\nkind: ConfigMap\ndata:\n  apiVersion: apps/v1\n  kind: Nope\nsubjects:\n- kind: ServiceAccount\n"})
	if l.Status != StatusComplete || pairs(l) != "v1 ConfigMap" {
		t.Fatal(pairs(l), codes(l))
	}
}

func TestCapabilitySwitchHelper(t *testing.T) {
	l := read(t, map[string]string{
		"templates/_h.tpl": `{{- define "demo.pdb.apiVersion" -}}
{{- if .Capabilities.APIVersions.Has "policy/v1" -}}
policy/v1
{{- else -}}
policy/v1beta1
{{- end -}}
{{- end -}}
`,
		"templates/pdb.yaml": "apiVersion: {{ include \"demo.pdb.apiVersion\" . }}\nkind: PodDisruptionBudget\n",
	})
	if l.Status != StatusComplete || pairs(l) != "policy/v1 PodDisruptionBudget,policy/v1beta1 PodDisruptionBudget" {
		t.Fatal(pairs(l), l.Withheld)
	}
	for _, e := range l.APIs {
		if !e.Conditional || e.VersionGroup != GroupCapabilitySwitch || e.Line != 1 {
			t.Fatalf("%+v", e)
		}
	}
}

func TestInlineChoiceAndTemplatedKinds(t *testing.T) {
	l := read(t, map[string]string{
		"templates/a.yaml": "{{- if .Values.stateful }}\napiVersion: apps/v1\nkind: StatefulSet\n{{- else }}\napiVersion: apps/v1\nkind: Deployment\n{{- end }}\n",
		"templates/b.yaml": "apiVersion: v1\nkind: {{ if .Values.secret }}Secret{{ else }}ConfigMap{{ end }}\n",
		"templates/c.yaml": "apiVersion: {{ if .Values.a }}batch/v1{{ else }}batch/v1beta1{{ end }}\nkind: CronJob\n",
	})
	if l.Status != StatusComplete {
		t.Fatal(l.Withheld)
	}
	want := "apps/v1 Deployment,apps/v1 StatefulSet,batch/v1 CronJob,batch/v1beta1 CronJob,v1 ConfigMap,v1 Secret"
	if pairs(l) != want {
		t.Fatal(pairs(l))
	}
	var kindSet, inline int
	for _, e := range l.APIs {
		if !e.Conditional {
			t.Fatalf("%+v", e)
		}
		if e.KindGroup == GroupTemplatedKindSet {
			kindSet++
		}
		if e.VersionGroup == GroupInlineChoice {
			inline++
		}
	}
	if kindSet != 2 || inline != 2 {
		t.Fatalf("kindSet=%d inline=%d", kindSet, inline)
	}
}

func TestLibraryHelperInArchiveAndMissing(t *testing.T) {
	sub := map[string]string{
		"charts/lib/Chart.yaml":       "apiVersion: v2\nname: lib\nversion: 0.1.0\ntype: library\n",
		"charts/lib/templates/_h.tpl": `{{- define "lib.api" -}}{{- if .Capabilities.APIVersions.Has "networking.k8s.io/v1" -}}networking.k8s.io/v1{{- else -}}networking.k8s.io/v1beta1{{- end -}}{{- end -}}`,
		"Chart.yaml":                  "apiVersion: v2\nname: demo\nversion: 1.2.3\ndependencies:\n- name: lib\n  version: 0.1.0\n",
		"templates/i.yaml":            "apiVersion: {{ include \"lib.api\" . }}\nkind: Ingress\n",
	}
	l := read(t, sub)
	if l.Status != StatusComplete || pairs(l) != "networking.k8s.io/v1 Ingress,networking.k8s.io/v1beta1 Ingress" {
		t.Fatal(pairs(l), l.Withheld)
	}
	if l.APIs[0].VersionGroup != GroupCapabilitySwitch {
		t.Fatalf("%+v", l.APIs[0])
	}
	// the library is not in the archive: dependency and helper are both named
	delete(sub, "charts/lib/Chart.yaml")
	delete(sub, "charts/lib/templates/_h.tpl")
	l = read(t, sub)
	if l.Status != StatusWithheld || !hasCode(l, CodeDependencyMissing) || !hasCode(l, CodeHelperNotFound) {
		t.Fatal(codes(l))
	}
}

func TestLibraryHelperWithoutSwitchIsGroupedAndUnconditional(t *testing.T) {
	l := read(t, map[string]string{
		"Chart.yaml":                  "apiVersion: v2\nname: demo\nversion: 1.2.3\ndependencies:\n- name: lib\n",
		"charts/lib/Chart.yaml":       "apiVersion: v2\nname: lib\nversion: 0.1.0\n",
		"charts/lib/templates/_h.tpl": `{{- define "lib.api" -}}v1{{- end -}}`,
		"templates/i.yaml":            "apiVersion: {{ include \"lib.api\" . | trim }}\nkind: ConfigMap\n",
	})
	if l.Status != StatusComplete || len(l.APIs) != 1 || l.APIs[0].Conditional || l.APIs[0].VersionGroup != GroupLibraryHelper {
		t.Fatalf("%+v %+v", l.APIs, l.Withheld)
	}
}

func TestConditionalSubchartAndNestedArchive(t *testing.T) {
	inner := build(t, map[string]string{"Chart.yaml": "apiVersion: v2\nname: inner\nversion: 0.0.1\n", "templates/x.yaml": "apiVersion: v1\nkind: Service\n"})
	// build uses the root "demo/"; the nested archive is stored as a file
	l, err := Read(buildBytes(t, map[string][]byte{
		"Chart.yaml":             []byte("apiVersion: v2\nname: demo\nversion: 1.2.3\ndependencies:\n- name: inner\n  condition: inner.enabled\n"),
		"charts/inner-0.0.1.tgz": inner,
		"templates/x.yaml":       []byte("apiVersion: v1\nkind: ConfigMap\n"),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if l.Status != StatusComplete || pairs(l) != "v1 ConfigMap,v1 Service" {
		t.Fatal(pairs(l), l.Withheld)
	}
	for _, e := range l.APIs {
		if e.Kind == "Service" && (!e.Conditional || !strings.HasPrefix(e.File, "charts/inner-0.0.1.tgz!/")) {
			t.Fatalf("%+v", e)
		}
		if e.Kind == "ConfigMap" && e.Conditional {
			t.Fatalf("%+v", e)
		}
	}
}

func buildBytes(t testing.TB, files map[string][]byte) []byte {
	t.Helper()
	m := map[string]string{}
	for k, v := range files {
		m[k] = string(v)
	}
	return build(t, m)
}

// Each case is one typed void: a shape the reader must not list as complete.
func TestWithheldCodes(t *testing.T) {
	lit := "apiVersion: v1\nkind: ConfigMap\n"
	cases := []struct {
		name  string
		files map[string]string
		code  string
	}{
		{"printf version", map[string]string{"templates/a.yaml": "apiVersion: {{ printf \"%s/v1\" .Values.g }}\nkind: Role\n"}, CodeVersionKindBuilt},
		{"printf kind", map[string]string{"templates/a.yaml": "apiVersion: v1\nkind: {{ printf \"%s\" \"Config\" }}Map\n"}, CodeVersionKindBuilt},
		{"concat text and value", map[string]string{"templates/a.yaml": "apiVersion: {{ .Values.group }}/v1\nkind: Role\n"}, CodeUserValue},
		{"user value version", map[string]string{"templates/a.yaml": "apiVersion: {{ .Values.apiVersion | default \"v1\" }}\nkind: ConfigMap\n"}, CodeUserValue},
		{"root user value", map[string]string{"templates/a.yaml": "apiVersion: v1\nkind: {{ $.Values.kind }}\n"}, CodeUserValue},
		{"variable", map[string]string{"templates/a.yaml": "{{- $v := \"v1\" }}\napiVersion: {{ $v }}\nkind: ConfigMap\n"}, CodeVariable},
		{"lookup direct", map[string]string{"templates/a.yaml": "apiVersion: {{ (lookup \"v1\" \"ConfigMap\" \"\" \"x\").apiVersion }}\nkind: ConfigMap\n"}, CodeLookup},
		{"lookup via variable", map[string]string{"templates/a.yaml": "{{- $o := lookup \"v1\" \"ConfigMap\" \"\" \"x\" }}\napiVersion: v1\nkind: {{ $o.kind }}\n"}, CodeLookup},
		{"other expression", map[string]string{"templates/a.yaml": "apiVersion: v1\nkind: {{ .Chart.Name }}\n"}, CodeExpression},
		{"range in value", map[string]string{"templates/a.yaml": "apiVersion: v1\nkind: {{ range .X }}a{{ end }}\n"}, CodeExpression},
		{"filter on helper", map[string]string{"templates/_h.tpl": `{{ define "h" }}v1{{ end }}`, "templates/a.yaml": "apiVersion: {{ include \"h\" . | upper }}\nkind: ConfigMap\n"}, CodeExpression},
		{"files at document level", map[string]string{"templates/a.yaml": lit + "---\n{{ .Files.Get \"objs.yaml\" }}\n"}, CodeFilesOrTpl},
		{"tpl at document level", map[string]string{"templates/a.yaml": lit + "---\n{{ tpl .Values.extra . }}\n"}, CodeFilesOrTpl},
		{"helper missing", map[string]string{"templates/a.yaml": "apiVersion: {{ include \"nope\" . }}\nkind: ConfigMap\n"}, CodeHelperNotFound},
		{"template action missing", map[string]string{"templates/a.yaml": "apiVersion: {{ template \"nope\" . }}\nkind: ConfigMap\n"}, CodeHelperNotFound},
		{"helper prints a value", map[string]string{"templates/_h.tpl": `{{ define "h" }}{{ .Values.v }}{{ end }}`, "templates/a.yaml": "apiVersion: {{ include \"h\" . }}\nkind: ConfigMap\n"}, CodeUserValue},
		{"ambiguous helper", map[string]string{"templates/_h.tpl": `{{ define "h" }}v1{{ end }}`, "templates/_g.tpl": `{{ define "h" }}v2{{ end }}`, "templates/a.yaml": "apiVersion: {{ include \"h\" . }}\nkind: ConfigMap\n"}, CodeHelperAmbiguous},
		{"template parse error", map[string]string{"templates/a.yaml": lit, "templates/b.yaml": "{{ if }}"}, CodeTemplateParse},
		{"missing kind", map[string]string{"templates/a.yaml": "apiVersion: v1\n"}, CodeDocumentPairing},
		{"missing apiVersion", map[string]string{"templates/a.yaml": "kind: ConfigMap\n"}, CodeDocumentPairing},
		{"two api one kind", map[string]string{"templates/a.yaml": "apiVersion: v1\napiVersion: v2\nkind: ConfigMap\n"}, CodeDocumentPairing},
		{"invalid version", map[string]string{"templates/a.yaml": "apiVersion: not a version\nkind: ConfigMap\n"}, CodeInvalidValue},
		{"invalid kind", map[string]string{"templates/a.yaml": "apiVersion: v1\nkind: config map\n"}, CodeInvalidValue},
		{"empty version", map[string]string{"templates/a.yaml": "apiVersion:\nkind: ConfigMap\n"}, CodeInvalidValue},
		{"list kind", map[string]string{"templates/a.yaml": "apiVersion: v1\nkind: List\nitems:\n- apiVersion: apps/v1\n  kind: Deployment\n"}, CodeListKind},
		{"dependency missing", map[string]string{"Chart.yaml": chartYAML + "dependencies:\n- name: gone\n", "templates/a.yaml": lit}, CodeDependencyMissing},
		{"requirements missing", map[string]string{"templates/a.yaml": lit, "requirements.yaml": "dependencies:\n- name: gone\n"}, CodeDependencyMissing},
		{"empty scan", map[string]string{"templates/a.yaml": "{{ .Values.x }}\n"}, CodeEmptyScan},
		{"value set too large", map[string]string{"templates/a.yaml": "apiVersion: v1\nkind: {{ if .a }}A{{ else }}B{{ end }}{{ if .a }}A{{ else }}B{{ end }}{{ if .a }}A{{ else }}B{{ end }}{{ if .a }}A{{ else }}B{{ end }}{{ if .a }}A{{ else }}B{{ end }}{{ if .a }}A{{ else }}B{{ end }}{{ if .a }}A{{ else }}B{{ end }}\n"}, CodeValueSetTooLarge},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := read(t, c.files)
			if l.Status != StatusWithheld || !hasCode(l, c.code) {
				t.Fatalf("status %s codes %v want %s", l.Status, codes(l), c.code)
			}
		})
	}
}

// The measured trap: objects built from files through the template function
// show one literal field and an otherwise empty scan. That is not complete.
func TestFileBackedObjectsAreRefused(t *testing.T) {
	l := read(t, map[string]string{
		"files/objs.yaml":    "apiVersion: apps/v1\nkind: StatefulSet\n",
		"templates/cfg.yaml": "apiVersion: v1\nkind: ConfigMap\ndata:\n  x: {{ .Files.Get \"files/objs.yaml\" | quote }}\n",
		"templates/obj.yaml": "{{- tpl (.Files.Get \"files/objs.yaml\") . }}\n",
	})
	if l.Status != StatusWithheld || !hasCode(l, CodeFilesOrTpl) {
		t.Fatal(codes(l))
	}
	// only files, no literal: empty scan plus the files code
	l = read(t, map[string]string{"templates/obj.yaml": "{{ tpl (.Files.Get \"files/objs.yaml\") . }}\n"})
	if l.Status != StatusWithheld || len(l.APIs) != 0 || !hasCode(l, CodeFilesOrTpl) || !hasCode(l, CodeEmptyScan) {
		t.Fatal(codes(l))
	}
	// files used for data only inside a mapping, with objects listed: complete
	l = read(t, map[string]string{"templates/cfg.yaml": "apiVersion: v1\nkind: ConfigMap\ndata:\n  x: {{ .Files.Get \"f\" | quote }}\n"})
	if l.Status != StatusComplete {
		t.Fatal(codes(l))
	}
}

func TestMixedChartFileRenderedDocumentWithheld(t *testing.T) {
	lit := "apiVersion: v1\nkind: ConfigMap\n"
	for name, tail := range map[string]string{
		"trimmed text":  "---\n{{- tpl .Values.x . }}\n",
		"after action":  "---\n{{ $x := 1 }}{{ .Files.Get \"f\" }}\n",
		"trimmed files": "---\n{{- .Files.Get \"f\" }}\n",
		"list item":     "---\n- {{ tpl .Values.x . }}\n",
	} {
		l := read(t, map[string]string{"templates/a.yaml": lit + tail})
		if l.Status != StatusWithheld || len(l.APIs) == 0 || !hasCode(l, CodeFilesOrTpl) {
			t.Fatalf("%s: %v", name, codes(l))
		}
	}
}

func TestHelperWorkBudget(t *testing.T) {
	var h strings.Builder
	const levels = MaxTemplateDepth - 1
	for i := 0; i < levels; i++ {
		fmt.Fprintf(&h, "{{ define \"h%d\" }}", i)
		for j := 0; j < 10; j++ {
			fmt.Fprintf(&h, "{{ include \"h%d\" . }}", i+1)
		}
		h.WriteString("{{ end }}\n")
	}
	fmt.Fprintf(&h, "{{ define \"h%d\" }}v1{{ end }}\n", levels)
	l := read(t, map[string]string{
		"templates/_h.tpl": h.String(),
		"templates/a.yaml": "apiVersion: {{ include \"h0\" . }}\nkind: ConfigMap\n",
	})
	if l.Status != StatusWithheld || !hasCode(l, CodeWorkExceeded) {
		t.Fatal(codes(l))
	}
}

func TestChartWithoutTemplatesIsCompleteAndEmpty(t *testing.T) {
	l := read(t, map[string]string{"values.yaml": "a: 1\n"})
	if l.Status != StatusComplete || len(l.APIs) != 0 {
		t.Fatal(codes(l))
	}
}

func TestCRDsAreListedUnconditionally(t *testing.T) {
	l := read(t, map[string]string{"crds/x.yaml": "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nspec:\n  names:\n    kind: Thing\n"})
	if l.Status != StatusComplete || pairs(l) != "apiextensions.k8s.io/v1 CustomResourceDefinition" || l.APIs[0].Conditional {
		t.Fatalf("%+v %v", l.APIs, codes(l))
	}
}

func TestDeterminism(t *testing.T) {
	files := func() map[string]string {
		return map[string]string{
			"templates/_h.tpl": `{{- define "h" -}}{{ if .Capabilities.APIVersions.Has "a/v1" }}a/v1{{ else }}a/v1beta1{{ end }}{{- end -}}`,
			"templates/a.yaml": "apiVersion: {{ include \"h\" . }}\nkind: Thing\n---\napiVersion: v1\nkind: Secret\n",
			"templates/b.yaml": "apiVersion: {{ .Values.x }}\nkind: A\n---\napiVersion: v1\nkind: Secret\n",
		}
	}
	a, b := build(t, files()), build(t, files())
	var out [][]byte
	for _, raw := range [][]byte{a, b, a} {
		l, err := Read(raw)
		if err != nil {
			t.Fatal(err)
		}
		m, err := l.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	if !bytes.Equal(out[0], out[1]) || !bytes.Equal(out[0], out[2]) {
		t.Fatal("ledger differs between runs")
	}
}

// ---- bounds and refusals

func rawTar(t testing.TB, hdrs []tar.Header, bodies []string) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for i := range hdrs {
		h := hdrs[i]
		h.Size = int64(len(bodies[i]))
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(bodies[i]))
	}
	tw.Close()
	zw.Close()
	return buf.Bytes()
}

func TestArchiveRefusals(t *testing.T) {
	reg := func(n string) tar.Header { return tar.Header{Name: n, Typeflag: tar.TypeReg, Mode: 0o644} }
	chartY := reg("demo/Chart.yaml")
	cases := map[string][]byte{
		"not gzip":       []byte("plain"),
		"empty":          nil,
		"traversal":      rawTar(t, []tar.Header{chartY, reg("demo/../evil")}, []string{chartYAML, "x"}),
		"absolute":       rawTar(t, []tar.Header{chartY, reg("/etc/x")}, []string{chartYAML, "x"}),
		"two roots":      rawTar(t, []tar.Header{chartY, reg("other/a")}, []string{chartYAML, "x"}),
		"duplicate":      rawTar(t, []tar.Header{chartY, chartY}, []string{chartYAML, chartYAML}),
		"no Chart.yaml":  rawTar(t, []tar.Header{reg("demo/templates/a.yaml")}, []string{"x"}),
		"bad Chart.yaml": rawTar(t, []tar.Header{chartY}, []string{"name: ["}),
		"no name":        rawTar(t, []tar.Header{chartY}, []string{"version: 1.0.0\n"}),
		"symlink":        rawTar(t, []tar.Header{chartY, {Name: "demo/l", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}}, []string{chartYAML, ""}),
		"hardlink":       rawTar(t, []tar.Header{chartY, {Name: "demo/l", Typeflag: tar.TypeLink, Linkname: "demo/Chart.yaml"}}, []string{chartYAML, ""}),
		"device":         rawTar(t, []tar.Header{chartY, {Name: "demo/d", Typeflag: tar.TypeChar}}, []string{chartYAML, ""}),
		"file at top":    rawTar(t, []tar.Header{reg("Chart.yaml")}, []string{chartYAML}),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if l, err := Read(raw); err == nil || !errors.Is(err, ErrRefused) || l != nil {
				t.Fatalf("not refused: %v", err)
			}
		})
	}
}

func TestBounds(t *testing.T) {
	t.Run("archive size", func(t *testing.T) {
		if _, err := Read(make([]byte, MaxArchiveBytes+1)); !errors.Is(err, ErrRefused) {
			t.Fatal(err)
		}
	})
	t.Run("file count", func(t *testing.T) {
		files := map[string]string{}
		for i := 0; i <= MaxFiles; i++ {
			files[fmt.Sprintf("files/f%d", i)] = ""
		}
		if _, err := Read(build(t, files)); !errors.Is(err, ErrRefused) {
			t.Fatal(err)
		}
	})
	t.Run("template file size", func(t *testing.T) {
		big := strings.Repeat("a", MaxFileBytes+1)
		if _, err := Read(build(t, map[string]string{"templates/a.yaml": big})); !errors.Is(err, ErrRefused) {
			t.Fatal(err)
		}
	})
	t.Run("unpacked size", func(t *testing.T) {
		files := map[string]string{}
		chunk := strings.Repeat("a", MaxFileBytes)
		for i := 0; i < MaxUnpackedBytes/MaxFileBytes+1; i++ {
			files[fmt.Sprintf("files/f%d", i)] = chunk
		}
		if _, err := Read(build(t, files)); !errors.Is(err, ErrRefused) {
			t.Fatal(err)
		}
	})
	t.Run("subchart depth", func(t *testing.T) {
		inner := build(t, map[string]string{})
		for i := 0; i < MaxSubchartDepth+1; i++ {
			inner = build(t, map[string]string{"charts/x.tgz": string(inner)})
		}
		if _, err := Read(inner); !errors.Is(err, ErrRefused) {
			t.Fatal(err)
		}
	})
	t.Run("template depth", func(t *testing.T) {
		files := map[string]string{"templates/a.yaml": "apiVersion: {{ include \"h0\" . }}\nkind: ConfigMap\n"}
		var h strings.Builder
		for i := 0; i < MaxTemplateDepth+2; i++ {
			fmt.Fprintf(&h, "{{ define \"h%d\" }}{{ include \"h%d\" . }}{{ end }}\n", i, i+1)
		}
		h.WriteString("{{ define \"h" + fmt.Sprint(MaxTemplateDepth+2) + "\" }}v1{{ end }}\n")
		files["templates/_h.tpl"] = h.String()
		l := read(t, files)
		if l.Status != StatusWithheld || !hasCode(l, CodeTemplateDepth) {
			t.Fatal(codes(l))
		}
	})
	t.Run("helper cycle", func(t *testing.T) {
		l := read(t, map[string]string{
			"templates/_h.tpl": `{{ define "a" }}{{ include "b" . }}{{ end }}{{ define "b" }}{{ include "a" . }}{{ end }}`,
			"templates/a.yaml": "apiVersion: {{ include \"a\" . }}\nkind: ConfigMap\n",
		})
		if l.Status != StatusWithheld || !hasCode(l, CodeTemplateDepth) {
			t.Fatal(codes(l))
		}
	})
	t.Run("nesting depth", func(t *testing.T) {
		var b strings.Builder
		for i := 0; i < MaxNestDepth+2; i++ {
			b.WriteString("{{ if .a }}")
		}
		b.WriteString("apiVersion: v1\nkind: ConfigMap\n")
		for i := 0; i < MaxNestDepth+2; i++ {
			b.WriteString("{{ end }}")
		}
		l := read(t, map[string]string{"templates/a.yaml": b.String()})
		if l.Status != StatusWithheld || !hasCode(l, CodeTemplateDepth) {
			t.Fatal(codes(l))
		}
	})
	t.Run("entries", func(t *testing.T) {
		var b strings.Builder
		for i := 0; i < MaxEntries+1; i++ {
			b.WriteString("---\napiVersion: v1\nkind: ConfigMap\n")
		}
		l := read(t, map[string]string{"templates/a.yaml": b.String()})
		if l.Status != StatusWithheld || !hasCode(l, CodeTooManyEntries) {
			t.Fatal(codes(l))
		}
	})
}

// ---- served-API measurement

func rec(line string, complete bool, apis ...string) servedapis.Record {
	c := servedapis.Completeness
	if !complete {
		c = servedapis.CompletenessPartial
	}
	return servedapis.Record{Component: servedapis.KubernetesComponent, Line: line, Completeness: c, APIs: apis}
}

var served = []servedapis.Record{
	rec("1.24", true, "apps/v1 Deployment", "policy/v1beta1 PodDisruptionBudget", "policy/v1 PodDisruptionBudget", "v1 ConfigMap"),
	rec("1.25", true, "apps/v1 Deployment", "policy/v1 PodDisruptionBudget", "v1 ConfigMap"),
	rec("1.26", false, "apps/v1 Deployment", "v1 ConfigMap"),
}

// Known answer: an unconditional policy/v1beta1 document would block on 1.25.
func TestKnownAnswerWouldBlock125(t *testing.T) {
	l := read(t, map[string]string{"templates/pdb.yaml": "apiVersion: policy/v1beta1\nkind: PodDisruptionBudget\nmetadata:\n  name: x\n"})
	l.CheckServed(served, []string{"1.24", "1.25"})
	l.Finish()
	if got := l.ServedChecks[0].Result; got != ResultWouldPass {
		t.Fatalf("1.24: %s", got)
	}
	c := l.ServedChecks[1]
	if c.Line != "1.25" || c.Result != ResultWouldBlock || len(c.Blockers) != 1 || c.Blockers[0].File != "templates/pdb.yaml" || c.Blockers[0].Line != 1 {
		t.Fatalf("%+v", c)
	}
}

func TestServedCheckNegatives(t *testing.T) {
	// the same pair under a capability switch is a notice, never a block
	l := read(t, map[string]string{
		"templates/_h.tpl": `{{- define "h" -}}{{ if .Capabilities.APIVersions.Has "policy/v1" }}policy/v1{{ else }}policy/v1beta1{{ end }}{{- end -}}`,
		"templates/a.yaml": "apiVersion: {{ include \"h\" . }}\nkind: PodDisruptionBudget\n",
	})
	l.CheckServed(served, []string{"1.25"})
	if c := l.ServedChecks[0]; c.Result != ResultWouldPass || len(c.Blockers) != 0 || len(c.Notices) != 1 {
		t.Fatalf("%+v", c)
	}
	// custom resources are not decided
	l = read(t, map[string]string{"templates/a.yaml": "apiVersion: example.test/v1\nkind: Thing\n---\napiVersion: v1\nkind: ConfigMap\n"})
	l.CheckServed(served, []string{"1.25"})
	if c := l.ServedChecks[0]; c.Result != ResultWouldPass || len(c.NotBuiltin) != 1 {
		t.Fatalf("%+v", c)
	}
	// a withheld chart without a blocker is withheld, never would-pass
	l = read(t, map[string]string{"templates/a.yaml": "apiVersion: v1\nkind: ConfigMap\n---\napiVersion: {{ .Values.v }}\nkind: Secret\n"})
	l.CheckServed(served, []string{"1.25"})
	if c := l.ServedChecks[0]; c.Result != ResultWithheld {
		t.Fatalf("%+v", c)
	}
	// ... but an unconditional unserved entry still blocks
	l = read(t, map[string]string{"templates/a.yaml": "apiVersion: policy/v1beta1\nkind: PodDisruptionBudget\n---\napiVersion: {{ .Values.v }}\nkind: Secret\n"})
	l.CheckServed(served, []string{"1.25"})
	if c := l.ServedChecks[0]; c.Result != ResultWouldBlock {
		t.Fatalf("%+v", c)
	}
	// a line without a record, and a partial list, are withheld
	l = read(t, map[string]string{"templates/a.yaml": "apiVersion: policy/v1\nkind: PodDisruptionBudget\n"})
	l.CheckServed(served, []string{"1.26", "1.99"})
	if l.ServedChecks[0].Result != ResultWithheld || l.ServedChecks[1].Result != ResultWithheld || len(l.ServedChecks[0].Unknown) != 1 {
		t.Fatalf("%+v", l.ServedChecks)
	}
}

func TestRemovedBuiltinGroupAndUnclassified(t *testing.T) {
	// a built-in group no record lists is not foreign: unserved, so it blocks
	l := read(t, map[string]string{"templates/a.yaml": "apiVersion: extensions/v1beta1\nkind: Ingress\n"})
	l.CheckServed(served, []string{"1.25"})
	if c := l.ServedChecks[0]; c.Result != ResultWouldBlock || len(c.NotBuiltin) != 0 {
		t.Fatalf("%+v", c)
	}
	// an unlisted dotless or k8s.io group is withheld, not foreign
	for _, av := range []string{"newgroup/v1", "future.k8s.io/v1"} {
		l = read(t, map[string]string{"templates/a.yaml": "apiVersion: " + av + "\nkind: Thing\n"})
		l.CheckServed(served, []string{"1.25"})
		if c := l.ServedChecks[0]; c.Result != ResultWithheld || len(c.NotBuiltin) != 0 {
			t.Fatalf("%s %+v", av, c)
		}
	}
}

func TestToolBugOverridesWouldBlock(t *testing.T) {
	l := read(t, map[string]string{"templates/pdb.yaml": "apiVersion: policy/v1beta1\nkind: PodDisruptionBudget\n"})
	l.ApplyOracle([]byte("apiVersion: policy/v1beta1\nkind: PodDisruptionBudget\n---\napiVersion: v1\nkind: Secret\n"))
	l.CheckServed(served, []string{"1.25"})
	if c := l.ServedChecks[0]; c.Result != ResultWithheld {
		t.Fatalf("%+v", c)
	}
}

// ---- oracle

func TestOracle(t *testing.T) {
	files := map[string]string{"templates/a.yaml": "apiVersion: apps/v1\nkind: Deployment\n"}
	ok := "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: a\n---\n"
	l := read(t, files)
	l.ApplyOracle([]byte(ok))
	if l.Status != StatusComplete || l.Oracle.Result != OracleOK {
		t.Fatalf("%+v %v", l.Oracle, codes(l))
	}
	// a rendered pair the static set does not hold is a tool bug
	l = read(t, files)
	l.ApplyOracle([]byte(ok + "apiVersion: v1\nkind: Secret\n"))
	if l.Status != StatusWithheld || !hasCode(l, CodeToolBugOracleMatch) || l.Oracle.Result != OracleMismatch || len(l.Oracle.Missing) != 1 {
		t.Fatalf("%+v %v", l.Oracle, codes(l))
	}
	// withheld chart: the difference is explained by the withheld codes
	l = read(t, map[string]string{"templates/a.yaml": "apiVersion: {{ .Values.v }}\nkind: Deployment\n"})
	l.ApplyOracle([]byte(ok))
	if l.Oracle.Result != OracleExtraOnWH || hasCode(l, CodeToolBugOracleMatch) {
		t.Fatalf("%+v %v", l.Oracle, codes(l))
	}
	// unreadable render withholds
	for _, bad := range []string{"a: [", "- x\n", "kind: Secret\n"} {
		l = read(t, files)
		l.ApplyOracle([]byte(bad))
		if l.Status != StatusWithheld || !hasCode(l, CodeOracleUnavailable) {
			t.Fatalf("%q: %v", bad, codes(l))
		}
	}
}
