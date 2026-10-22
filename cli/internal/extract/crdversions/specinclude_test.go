// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/extract"
)

const (
	specChart    = "charts/widgets"
	specTplPath  = specChart + "/templates/widgets.yaml"
	specFragPath = specChart + "/hack/widgets_spec.yaml"
	specCRDName  = "widgets." + synthGroup
	specCommit   = "v1.0.0"
)

// specTarget reads the templates directory of the synthetic chart.
func specTarget(dirs ...string) Target {
	tg := synthTarget()
	tg.Paths = nil
	if len(dirs) == 0 {
		dirs = []string{specChart + "/templates"}
	}
	for _, d := range dirs {
		tg.Paths = append(tg.Paths, PathSpec{Path: d, Dir: true, Match: regexp.MustCompile(`^[^.][^/]*\.ya?ml$`), Guard: regexp.MustCompile(`(?i)crd`)})
	}
	return tg
}

// specTemplate is a header template of the admitted shape.
func specTemplate(name, rel string) string {
	return "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  annotations:\n    example.org/inject: {{ include \"widgets.annotation\" . }}\n  labels:\n    {{- include \"widgets.labels\" . | nindent 4 }}\n  name: " + name + "\nspec:\n  {{ tpl (.Files.Get \"" + rel + "\") . | nindent 2 }}\n"
}

const specConversion = "conversion:\n  strategy: Webhook\n  webhook:\n    clientConfig:\n      service:\n        name: '{{ .Values.svc }}'\n        namespace: \"{{ .Values.ns }}\"\n        path: /convert\n    conversionReviewVersions:\n    - v1\n"

// specBody is the bare spec of the synthetic Widget CRD with a conversion
// webhook after its versions.
func specBody(versions ...string) string {
	_, rest, _ := strings.Cut(crd("Widget", versions...), "\nspec:\n")
	var b strings.Builder
	for _, l := range strings.Split(strings.TrimRight(rest, "\n"), "\n") {
		b.WriteString(strings.TrimPrefix(l, "  "))
		b.WriteByte('\n')
	}
	return b.String() + specConversion
}

// kindDefault adds a schema default that holds a manifest of the kind, so a
// fragment that the scan reads as a file of its own is a finding.
func kindDefault(body string) string {
	return strings.Replace(body, "      type: object\n", "      type: object\n      properties:\n        x:\n          type: object\n          default:\n            kind: CustomResourceDefinition\n", -1)
}

// specFiles is a chart whose template includes hack/widgets_spec.yaml.
func specFiles(dir string, body string) map[string]string {
	return map[string]string{
		dir + "/Chart.yaml":             "apiVersion: v2\nname: widgets\nversion: 0.1.0\n",
		dir + "/templates/widgets.yaml": specTemplate(specCRDName, "hack/widgets_spec.yaml"),
		dir + "/hack/widgets_spec.yaml": body,
	}
}

func specReader(files map[string]string) memReader {
	m := memReader{}
	for p, c := range files {
		m[commitOf(specCommit)+":"+p] = []byte(c)
	}
	return m
}

// linkedReader reports the listed paths as symbolic links.
type linkedReader struct {
	memReader
	links map[string]bool
}

func (l linkedReader) List(r extract.RepoRef, c, d string) ([]extract.TreeEntry, error) {
	es, err := l.memReader.List(r, c, d)
	for i := range es {
		if l.links[es[i].Path] {
			es[i].Type, es[i].Mode = "blob", "120000"
		}
	}
	return es, err
}

func specInventory(t *testing.T, tg Target, rd extract.PinnedReader) (*Inventory, error) {
	t.Helper()
	repo, err := extract.ParseRepo(tg.Repo)
	must(t, err)
	return readInventory(rd, repo, tg, attribution{tg.Project, customresources.DefaultIndex()}, commitOf(specCommit))
}

func shaOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// plainEquivalent is the definition the template and spec stand for, written
// as the plain file a chart without the include would hold.
func plainEquivalent(t *testing.T, body string) CRD {
	t.Helper()
	plain := strings.NewReplacer("{{ .Values.svc }}", "svc", "{{ .Values.ns }}", "ns").Replace(body)
	text := "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: " + specCRDName + "\nspec:\n  " + strings.ReplaceAll(strings.TrimSuffix(plain, "\n"), "\n", "\n  ") + "\n"
	_, crds, err := parseFile(specFragPath, []byte(text))
	if err != nil || len(crds) != 1 {
		t.Fatalf("plain file: %v %+v", err, crds)
	}
	return crds[0]
}

func TestSpecIncludeIsReadLikeAPlainFile(t *testing.T) {
	body := specBody("v1beta1", "v1")
	files := specFiles(specChart, body)
	inv, err := specInventory(t, specTarget(), specReader(files))
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.CRDs) != 1 {
		t.Fatalf("crds %+v", inv.CRDs)
	}
	got, want := inv.CRDs[0], plainEquivalent(t, body)
	// The lines are those of the included file; the plain file has the
	// five lines of the header before it.
	shift := func(l int) int { return l - specIncludeHeaderLines }
	if got.Path != specFragPath || got.Name != want.Name || got.Group != want.Group || got.Kind != want.Kind || got.Plural != want.Plural || got.Scope != want.Scope || got.StorageVersion != want.StorageVersion || got.Document != 1 || got.StartLine != 1 || got.VersionsLine != shift(want.VersionsLine) || len(got.Versions) != len(want.Versions) {
		t.Fatalf("read\n%+v\nplain\n%+v", got, want)
	}
	for i, v := range want.Versions {
		w := CRDVersion{Name: v.Name, Served: v.Served, Storage: v.Storage, StartLine: shift(v.StartLine), EndLine: shift(v.EndLine), ServedLine: shift(v.ServedLine), StorageLine: shift(v.StorageLine)}
		if !reflect.DeepEqual(got.Versions[i], w) {
			t.Fatalf("version %d: %+v, plain %+v", i, got.Versions[i], w)
		}
	}
	// The cited lines are lines of the included file.
	lines := strings.Split(body, "\n")
	for _, v := range got.Versions {
		if !strings.HasPrefix(lines[v.StartLine-1], "- name: "+v.Name) || !strings.Contains(lines[v.ServedLine-1], "served:") || !strings.Contains(lines[v.StorageLine-1], "storage:") {
			t.Fatalf("version %s cites lines that are not its own: %+v", v.Name, v)
		}
	}
	// Both blobs are named, with the digest of their bytes.
	byPath := map[string]FileRecord{}
	for _, f := range inv.Files {
		byPath[f.Path] = f
	}
	tpl, frag := byPath[specTplPath], byPath[specFragPath]
	if len(inv.Files) != 2 || tpl.SHA256 != shaOf(files[specTplPath]) || frag.SHA256 != shaOf(files[specFragPath]) || tpl.CRDs != 1 || frag.CRDs != 0 || tpl.Size != len(files[specTplPath]) || frag.Size != len(files[specFragPath]) {
		t.Fatalf("files %+v", inv.Files)
	}
	if inv.Paths[0].Files != 1 {
		t.Fatalf("paths %+v", inv.Paths)
	}
}

// Without the quotes of the template's spacing and with trimming markers the
// same template is read.
func TestSpecIncludeSpellings(t *testing.T) {
	for name, edit := range map[string][2]string{
		"no spaces":        {"{{ tpl (.Files.Get \"hack/widgets_spec.yaml\") . | nindent 2 }}", "{{tpl (.Files.Get \"hack/widgets_spec.yaml\") .|nindent 2}}"},
		"left trim":        {"{{ tpl", "{{- tpl"},
		"right trim":       {"nindent 2 }}", "nindent 2 -}}"},
		"both trims":       {"  {{ tpl (.Files.Get \"hack/widgets_spec.yaml\") . | nindent 2 }}", "  {{- tpl (.Files.Get \"hack/widgets_spec.yaml\") . | nindent 2 -}}"},
		"wide indent":      {"nindent 2 }}", "nindent 6 }}"},
		"no label lines":   {"  labels:\n    {{- include \"widgets.labels\" . | nindent 4 }}\n", ""},
		"literal labels":   {"    {{- include \"widgets.labels\" . | nindent 4 }}\n", "    app: widgets\n    {{ include \"widgets.labels\" . | nindent 4 }}\n"},
		"no final newline": {"nindent 2 }}\n", "nindent 2 }}"},
	} {
		files := specFiles(specChart, specBody("v1"))
		if !strings.Contains(files[specTplPath], edit[0]) {
			t.Fatalf("%s: %q not in the template", name, edit[0])
		}
		files[specTplPath] = strings.Replace(files[specTplPath], edit[0], edit[1], 1)
		inv, err := specInventory(t, specTarget(), specReader(files))
		if err != nil || len(inv.CRDs) != 1 || inv.CRDs[0].Name != specCRDName {
			t.Fatalf("%s: %v %+v", name, err, inv)
		}
	}
}

// Every shape the reader does not admit keeps today's failure: the template
// contains template syntax.
func TestSpecIncludeRefusals(t *testing.T) {
	const syntax = "contains template syntax"
	tplEdit := func(old, new string) func(map[string]string) {
		return func(f map[string]string) {
			if !strings.Contains(f[specTplPath], old) {
				t.Fatalf("%q not in the template", old)
			}
			f[specTplPath] = strings.Replace(f[specTplPath], old, new, 1)
		}
	}
	fragEdit := func(old, new string) func(map[string]string) {
		return func(f map[string]string) {
			if !strings.Contains(f[specFragPath], old) {
				t.Fatalf("%q not in the included file", old)
			}
			f[specFragPath] = strings.Replace(f[specFragPath], old, new, 1)
		}
	}
	// include points the template at rel, and puts a copy of the spec at
	// that literal path too, so a refusal is the path's and not a missing file.
	include := func(rel string) func(map[string]string) {
		return func(f map[string]string) {
			tplEdit("hack/widgets_spec.yaml", rel)(f)
			if strings.Contains(rel, "/") && !strings.HasPrefix(rel, "/") && !strings.HasPrefix(rel, "..") {
				f[specChart+"/"+rel] = f[specFragPath]
			}
		}
	}
	tpl := "{{ tpl (.Files.Get \"hack/widgets_spec.yaml\") . | nindent 2 }}"
	tests := []struct {
		name string
		edit func(map[string]string)
		want string
		tg   *Target
	}{
		{"include of another chart", func(f map[string]string) {
			include("../other/hack/widgets_spec.yaml")(f)
			f["charts/other/hack/widgets_spec.yaml"] = f[specFragPath]
		}, syntax, nil},
		{"dot dot", include("hack/../hack/widgets_spec.yaml"), syntax, nil},
		{"leading dot dot", func(f map[string]string) {
			include("../widgets/hack/widgets_spec.yaml")(f)
		}, syntax, nil},
		{"absolute", include("/charts/widgets/hack/widgets_spec.yaml"), syntax, nil},
		{"glob star", include("hack/*_spec.yaml"), syntax, nil},
		{"glob question", include("hack/widgets_spec.yam?"), syntax, nil},
		{"glob bracket", include("hack/[w]idgets_spec.yaml"), syntax, nil},
		{"template in path", include("hack/{{ .Values.x }}.yaml"), syntax, nil},
		{"backslash", include(`hack\widgets_spec.yaml`), syntax, nil},
		{"dot prefix", include("./hack/widgets_spec.yaml"), syntax, nil},
		{"double slash", include("hack//widgets_spec.yaml"), syntax, nil},
		{"trailing slash", include("hack/"), syntax, nil},
		{"empty path", include(""), syntax, nil},
		{"space in path", include("hack/widgets spec.yaml"), syntax, nil},
		{"missing file", func(f map[string]string) { delete(f, specFragPath) }, syntax, nil},
		{"directory instead of file", include("hack"), syntax, nil},
		{"no Chart.yaml", func(f map[string]string) { delete(f, specChart+"/Chart.yaml") }, syntax, nil},
		{"Chart.yaml only further up", func(f map[string]string) {
			delete(f, specChart+"/Chart.yaml")
			f["Chart.yaml"] = "apiVersion: v2\nname: root\nversion: 0.1.0\n"
		}, syntax, nil},
		{"template not under templates", func(f map[string]string) {
			f[specChart+"/misc/widgets.yaml"] = f[specTplPath]
			delete(f, specTplPath)
		}, syntax, ptr(specTarget(specChart + "/misc"))},
		{"included file is also listed", func(f map[string]string) {
			f[specFragPath] = strings.NewReplacer("{{ .Values.svc }}", "svc", "{{ .Values.ns }}", "ns").Replace(f[specFragPath])
		}, syntax, ptr(specTarget(specChart+"/templates", specChart+"/hack"))},
		{"duplicate name in a plain file", func(f map[string]string) {
			f[specChart+"/templates/plain.yaml"] = crd("Widget", "v1")
		}, "is defined in both", nil},
		{"two templates, one spec", func(f map[string]string) {
			f[specChart+"/templates/widgets2.yaml"] = f[specTplPath]
		}, syntax, nil},
		{"if around the file", func(f map[string]string) {
			f[specTplPath] = "{{- if .Values.crds.enabled }}\n" + f[specTplPath] + "{{- end }}\n"
		}, syntax, nil},
		{"if in metadata", tplEdit("  labels:\n", "  {{- if .Values.x }}\n  labels:\n  {{- end }}\n"), syntax, nil},
		{"range in metadata", tplEdit("    {{- include \"widgets.labels\" . | nindent 4 }}", "    {{- range .Values.labels }}"), syntax, nil},
		{"with in metadata", tplEdit("    {{- include \"widgets.labels\" . | nindent 4 }}", "    {{- with .Values.labels }}"), syntax, nil},
		{"define", tplEdit("  labels:\n", "  {{- define \"x\" }}\n  labels:\n"), syntax, nil},
		{"template action", tplEdit("{{ include \"widgets.annotation\" . }}", "{{ template \"widgets.annotation\" . }}"), syntax, nil},
		{"second include on a line", tplEdit("{{ include \"widgets.annotation\" . }}", "{{ include \"a\" . }}{{ include \"b\" . }}"), syntax, nil},
		{"value include with a pipe", tplEdit("{{ include \"widgets.annotation\" . }}", "{{ include \"a\" . | upper }}"), syntax, nil},
		{"value include trims", tplEdit("{{ include \"widgets.annotation\" . }}", "{{- include \"a\" . -}}"), syntax, nil},
		{"value include of a value", tplEdit("{{ include \"widgets.annotation\" . }}", "{{ .Values.x }}"), syntax, nil},
		{"include name with a brace", tplEdit("\"widgets.annotation\"", "\"a{b\""), syntax, nil},
		{"include name with a backslash", tplEdit("\"widgets.annotation\"", "\"a\\\\b\""), syntax, nil},
		{"include with another context", tplEdit("\"widgets.annotation\" .", "\"widgets.annotation\" $"), syntax, nil},
		{"line include nindent 2", tplEdit("nindent 4", "nindent 2"), syntax, nil},
		{"line include nindent 0", tplEdit("nindent 4", "nindent 0"), syntax, nil},
		{"line include trims after", tplEdit("nindent 4 }}", "nindent 4 -}}"), syntax, nil},
		{"line include indented wrongly", tplEdit("    {{- include \"widgets.labels\"", "  {{- include \"widgets.labels\""), syntax, nil},
		{"metadata namespace", tplEdit("  name: ", "  namespace: x\n  name: "), syntax, nil},
		{"metadata finalizers", tplEdit("  name: ", "  finalizers: []\n  name: "), syntax, nil},
		{"template as name", tplEdit("  name: "+specCRDName, "  name: {{.Values.n}}"), syntax, nil},
		{"name not plural.group", tplEdit("  name: "+specCRDName, "  name: gadgets."+synthGroup), syntax, nil},
		{"name not DNS", tplEdit("  name: "+specCRDName, "  name: Widgets."+synthGroup), syntax, nil},
		{"two names", tplEdit("  name: "+specCRDName, "  name: "+specCRDName+"\n  name: "+specCRDName), syntax, nil},
		{"literal value with a flow map", tplEdit("  labels:\n", "  labels:\n    a: {b: c}\n"), syntax, nil},
		{"literal value that is not a string", tplEdit("  labels:\n", "  labels:\n    a: 1\n"), syntax, nil},
		{"entry outside annotations and labels", tplEdit("  annotations:\n", "    stray: x\n  annotations:\n"), syntax, nil},
		{"comment line", tplEdit("  labels:\n", "  # note\n  labels:\n"), syntax, nil},
		{"wrong apiVersion", tplEdit("apiextensions.k8s.io/v1\n", "apiextensions.k8s.io/v1beta1\n"), syntax, nil},
		{"document marker", func(f map[string]string) { f[specTplPath] = "---\n" + f[specTplPath] }, syntax, nil},
		{"tpl without nindent", tplEdit(" | nindent 2 }}", " }}"), syntax, nil},
		{"tpl nindent 0", tplEdit("nindent 2", "nindent 0"), syntax, nil},
		{"tpl nindent too wide", tplEdit("nindent 2", "nindent 40"), syntax, nil},
		{"tpl with a variable path", tplEdit("\"hack/widgets_spec.yaml\"", "$p"), syntax, nil},
		{"tpl of another function", tplEdit("tpl (", "include ("), syntax, nil},
		{"tpl with another context", tplEdit(") . |", ") $ |"), syntax, nil},
		{"tpl piped further", tplEdit("nindent 2 }}", "nindent 2 | quote }}"), syntax, nil},
		{"second tpl", tplEdit(tpl+"\n", tpl+"\n  "+tpl+"\n"), syntax, nil},
		{"trailing line", func(f map[string]string) { f[specTplPath] += "# end\n" }, syntax, nil},
		{"trailing blank line", func(f map[string]string) { f[specTplPath] += "\n" }, syntax, nil},
		{"line between spec and tpl", tplEdit("spec:\n", "spec:\n  # note\n"), syntax, nil},
		{"tab", tplEdit("  labels:", "\tlabels:"), syntax, nil},
		{"carriage return", func(f map[string]string) { f[specTplPath] = strings.ReplaceAll(f[specTplPath], "\n", "\r\n") }, syntax, nil},
		{"non-ASCII byte", tplEdit("  labels:\n", "  labels:\n    a: \u00e9\n"), syntax, nil},
		{"oversize", tplEdit("  labels:\n", "  labels:\n    big: "+strings.Repeat("a", specIncludeMaxTemplateBytes)+"\n"), syntax, nil},
		{"too many lines", tplEdit("  labels:\n", "  labels:\n"+strings.Repeat("    a: b\n", specIncludeMaxMetaLines+1)), syntax, nil},
		{"brace in the spec description", fragEdit("      type: object\n", "      type: object\n      description: 'use {{ here }}'\n"), syntax, nil},
		{"brace in a comment of the spec", func(f map[string]string) { f[specFragPath] = "# {{ note }}\n" + f[specFragPath] }, syntax, nil},
		{"brace under conversion path", fragEdit("path: /convert", "path: '{{ .Values.p }}'"), syntax, nil},
		{"brace in conversion caBundle", fragEdit("strategy: Webhook\n", "strategy: Webhook\n  caBundle: '{{ .Values.ca }}'\n"), syntax, nil},
		{"brace in a version name", fragEdit("- name: v1beta1", "- name: '{{ .Values.v }}'"), syntax, nil},
		{"brace in group", fragEdit("group: "+synthGroup, "group: '{{ .Values.g }}'"), syntax, nil},
		{"service name outside the service", fragEdit("    conversionReviewVersions:", "    name: '{{ .Values.x }}'\n    conversionReviewVersions:"), syntax, nil},
		{"service name with a pipe", fragEdit("'{{ .Values.svc }}'", "'{{ .Values.svc | upper }}'"), syntax, nil},
		{"service name unquoted value", fragEdit("'{{ .Values.svc }}'", "{{ .Values.svc }}"), syntax, nil},
		{"service name with mismatched quotes", fragEdit("'{{ .Values.svc }}'", "'{{ .Values.svc }}\""), syntax, nil},
		{"service name with indent", fragEdit("'{{ .Values.svc }}'", "'{{ .Release.Name | nindent 2 }}'"), syntax, nil},
		{"service name with a trim", fragEdit("'{{ .Values.svc }}'", "'{{- .Values.svc }}'"), syntax, nil},
		{"service name with a comment", fragEdit("'{{ .Values.svc }}'", "'{{/* x */}}'"), syntax, nil},
		{"service name with text around", fragEdit("'{{ .Values.svc }}'", "'a-{{ .Values.svc }}'"), syntax, nil},
		{"service name with two actions", fragEdit("'{{ .Values.svc }}'", "'{{ .Values.a }}{{ .Values.b }}'"), syntax, nil},
		{"service name with an include", fragEdit("'{{ .Values.svc }}'", "'{{ include \"x\" . }}'"), syntax, nil},
		{"service name with an assignment", fragEdit("'{{ .Values.svc }}'", "'{{ $x := 1 }}'"), syntax, nil},
		{"service name key in a list", fragEdit("- name: v1beta1", "- name: '{{ .Values.v }}'"), syntax, nil},
		{"placeholder word in the spec", fragEdit("      type: object\n", "      type: object\n      description: TEMPLATED\n"), syntax, nil},
		{"apiVersion in the spec", func(f map[string]string) { f[specFragPath] = "apiVersion: apiextensions.k8s.io/v1\n" + f[specFragPath] }, syntax, nil},
		{"kind in the spec", func(f map[string]string) { f[specFragPath] = "kind: CustomResourceDefinition\n" + f[specFragPath] }, syntax, nil},
		{"metadata in the spec", func(f map[string]string) { f[specFragPath] = "metadata:\n  name: x\n" + f[specFragPath] }, syntax, nil},
		{"two documents in the spec", func(f map[string]string) { f[specFragPath] += "---\ngroup: other\n" }, syntax, nil},
		{"spec is a list", func(f map[string]string) { f[specFragPath] = "- a\n- b\n" }, syntax, nil},
		{"empty spec", func(f map[string]string) { f[specFragPath] = "" }, syntax, nil},
		{"spec with an anchor", fragEdit("scope: Namespaced\n", "scope: &s Namespaced\n"), syntax, nil},
		{"spec with an invalid kind", fragEdit("  kind: Widget\n", "  kind: widget\n"), syntax, nil},
		{"spec with a name that is not its names", fragEdit("plural: widgets", "plural: gadgets"), syntax, nil},
		{"spec without versions", func(f map[string]string) {
			f[specFragPath] = "group: " + synthGroup + "\nnames:\n  kind: Widget\n  plural: widgets\nscope: Namespaced\n"
		}, syntax, nil},
		{"oversize spec", func(f map[string]string) {
			f[specFragPath] = strings.Repeat("#", MaxFileBytes) + "\n" + f[specFragPath]
		}, syntax, nil},
	}
	for _, tc := range tests {
		files := specFiles(specChart, specBody("v1beta1", "v1"))
		tc.edit(files)
		tg := specTarget()
		if tc.tg != nil {
			tg = *tc.tg
		}
		inv, err := specInventory(t, tg, specReader(files))
		pr, ok := asProblem(err)
		if !ok || !strings.Contains(pr.msg, tc.want) {
			t.Errorf("%s: err %v, want a problem containing %q", tc.name, err, tc.want)
			continue
		}
		for _, f := range inv.Files {
			if f.Path != specTplPath || tc.name == "duplicate name in a plain file" || tc.name == "two templates, one spec" {
				continue
			}
			if f.CRDs != 0 {
				t.Errorf("%s: the refused template holds a definition: %+v", tc.name, f)
			}
		}
	}
}

func ptr(t Target) *Target { return &t }

// A symbolic link on the way to the included file, or as the file, or as
// Chart.yaml, refuses the include.
func TestSpecIncludeRefusesSymbolicLinks(t *testing.T) {
	for _, link := range []string{specFragPath, specChart + "/hack", specChart + "/Chart.yaml"} {
		files := specFiles(specChart, specBody("v1"))
		rd := linkedReader{memReader: specReader(files), links: map[string]bool{link: true}}
		_, err := specInventory(t, specTarget(), rd)
		if pr, ok := asProblem(err); !ok || !strings.Contains(pr.msg, "contains template syntax") {
			t.Errorf("link at %s: %v", link, err)
		}
	}
	// The same tree without links is read.
	rd := linkedReader{memReader: specReader(specFiles(specChart, specBody("v1")))}
	if inv, err := specInventory(t, specTarget(), rd); err != nil || len(inv.CRDs) != 1 {
		t.Fatalf("without links: %v", err)
	}
}

// The nearest chart directory is the base of the path, a chart at the root
// of the repository included.
func TestSpecIncludeChartDirectories(t *testing.T) {
	// A chart at the root.
	files := map[string]string{
		"Chart.yaml":             "apiVersion: v2\nname: root\nversion: 0.1.0\n",
		"templates/widgets.yaml": specTemplate(specCRDName, "hack/widgets_spec.yaml"),
		"hack/widgets_spec.yaml": specBody("v1"),
	}
	inv, err := specInventory(t, specTarget("templates"), specReader(files))
	if err != nil || len(inv.CRDs) != 1 || inv.CRDs[0].Path != "hack/widgets_spec.yaml" {
		t.Fatalf("root chart: %v %+v", err, inv)
	}
	// A subchart: the path is relative to the nearest Chart.yaml, so the
	// outer chart's file of the same relative path is not the one read.
	files = specFiles(specChart+"/charts/sub", specBody("v1"))
	files[specChart+"/Chart.yaml"] = "apiVersion: v2\nname: widgets\nversion: 0.1.0\n"
	files[specChart+"/hack/widgets_spec.yaml"] = specBody("v1", "v2")
	inv, err = specInventory(t, specTarget(specChart+"/charts/sub/templates"), specReader(files))
	if err != nil || len(inv.CRDs) != 1 || inv.CRDs[0].Path != specChart+"/charts/sub/hack/widgets_spec.yaml" || len(inv.CRDs[0].Versions) != 1 {
		t.Fatalf("subchart: %v %+v", err, inv)
	}
	// A template below templates/ at any depth.
	files = specFiles(specChart, specBody("v1"))
	files[specChart+"/templates/crds/widgets.yaml"] = files[specTplPath]
	delete(files, specTplPath)
	tg := specTarget(specChart + "/templates")
	tg.Paths[0].Recursive = true
	if inv, err = specInventory(t, tg, specReader(files)); err != nil || len(inv.CRDs) != 1 {
		t.Fatalf("nested template: %v", err)
	}
}

// A file with "{{" that is not of the shape, or a file without it, reads
// as it did: the reader is reached only by files that failed.
func TestSpecIncludeLeavesOtherFilesAlone(t *testing.T) {
	files := specFiles(specChart, specBody("v1"))
	files[specChart+"/templates/plain.yaml"] = crd("Gadget", "v1")
	inv, err := specInventory(t, specTarget(), specReader(files))
	if err != nil || len(inv.CRDs) != 2 || len(inv.Files) != 3 {
		t.Fatalf("%v %+v", err, inv)
	}
	// A repository without the listed chart.
	if _, err := specInventory(t, specTarget(), specReader(map[string]string{"README": "x"})); err == nil {
		t.Fatal("no chart")
	}
}

func TestSpecIncludeTemplateParser(t *testing.T) {
	sh := parseSpecIncludeTemplate([]byte(specTemplate(specCRDName, "hack/widgets_spec.yaml")))
	if sh == nil || sh.CRD != specCRDName || sh.Path != "hack/widgets_spec.yaml" || sh.Indent != 2 {
		t.Fatalf("%+v", sh)
	}
	for _, in := range []string{"", "\n", "apiVersion: apiextensions.k8s.io/v1\n", string(make([]byte, 10))} {
		if parseSpecIncludeTemplate([]byte(in)) != nil {
			t.Errorf("%q read", in)
		}
	}
	for _, p := range []string{"a", "hack/x.yaml", "a/b/c.yaml", "a-b_c.d/e.yaml"} {
		if !specIncludePathOK(p) {
			t.Errorf("%q refused", p)
		}
	}
	for _, p := range []string{"", ".", "..", "/a", "a/", "a//b", "./a", "a/./b", "a/../b", "../a", "a/..", "a*", "a?", "a[", "a]", "a{", "a}", "a\\b", "a\x00b", "a b", "a\tb", "a\nb", "é", strings.Repeat("a", specIncludeMaxPathBytes+1)} {
		if specIncludePathOK(p) {
			t.Errorf("%q admitted", p)
		}
	}
}

// Versions are derived across two releases, with a removal and with an added
// version, and the pair is attestable: the template, the spec and every other
// file of the scan are accounted for.
func TestSpecIncludeDerivesPairs(t *testing.T) {
	tests := []struct {
		name      string
		from, to  []string
		wantRules int
	}{
		{"version removed", []string{"v1beta1", "v1"}, []string{"v1"}, 1},
		{"version added", []string{"v1"}, []string{"v1", "v2"}, 0},
	}
	for _, tc := range tests {
		s := newSynth(release{"v1.0.0", specFiles(specChart, specBody(tc.from...))}, release{"v1.1.0", specFiles(specChart, specBody(tc.to...))})
		p, proof := pairOf(t, runSynth(t, specTarget(), s), "1.0.0", "1.1.0")
		if p.Status != extract.PairDerived || len(p.Rules) != tc.wantRules || !proof.Completeness.Attestable || !proof.Completeness.Declared || !proof.Completeness.Scan {
			t.Fatalf("%s: %s %q %d rules %+v %+v", tc.name, p.Status, p.Reason, len(p.Rules), proof.Completeness, proof.To.Scan.Findings)
		}
		for _, inv := range []*Inventory{proof.From, proof.To} {
			var paths []string
			for _, f := range inv.Files {
				paths = append(paths, f.Path)
			}
			slices.Sort(paths)
			if !slices.Equal(paths, []string{specFragPath, specTplPath}) {
				t.Fatalf("%s: files %v", tc.name, paths)
			}
		}
		for _, rm := range proof.Removals {
			if rm.FromPath != specFragPath || rm.ToPath != "" && rm.ToPath != specFragPath || rm.FromStartLine < 1 || rm.FromEndLine < rm.FromStartLine {
				t.Fatalf("%s: removal %+v", tc.name, rm)
			}
		}
	}
	// A pair is withheld when the later release's template is refused.
	bad := specFiles(specChart, specBody("v1"))
	bad[specTplPath] = strings.Replace(bad[specTplPath], "nindent 2", "nindent 0", 1)
	s := newSynth(release{"v1.0.0", specFiles(specChart, specBody("v1beta1", "v1"))}, release{"v1.1.0", bad})
	p, _ := pairOf(t, runSynth(t, specTarget(), s), "1.0.0", "1.1.0")
	if p.Status != extract.PairWithheld || !strings.Contains(p.Reason, "contains template syntax") {
		t.Fatalf("refused template: %s %q", p.Status, p.Reason)
	}
}

// In the full-tree scan the included file is accounted for with its template.
// An included file the scan would otherwise report is not a finding; the same
// bytes without a template that includes them keep their classification; and
// a template of the shape outside the listed paths is read as a definition.
func TestSpecIncludeInTheScan(t *testing.T) {
	const twin = "charts/twin"
	build := func(versions ...string) map[string]string {
		body := kindDefault(specBody(versions...))
		files := specFiles(specChart, body)
		for p, c := range specFiles(twin, body) {
			files[p] = c
		}
		return files
	}
	from, to := build("v1beta1", "v1"), build("v1")
	run := func(from, to map[string]string) (extract.PairRecord, PairProof) {
		s := newSynth(release{"v1.0.0", from}, release{"v1.1.0", to})
		return pairOf(t, runSynth(t, specTarget(), s), "1.0.0", "1.1.0")
	}

	// The listed chart's fragment is declared by the inventory; the twin
	// chart's template is a copy of the listed definition and claims its
	// fragment.
	p, proof := run(from, to)
	scan := proof.To.Scan
	if p.Status != extract.PairDerived || !proof.Completeness.Attestable {
		t.Fatalf("%s %q %+v %+v", p.Status, p.Reason, proof.Completeness, scan.Findings)
	}
	for _, path := range []string{specFragPath, twin + "/hack/widgets_spec.yaml"} {
		if f := findingOf(scan, path); f != nil {
			t.Errorf("the included file %s is a finding: %+v", path, f)
		}
	}
	f := findingOf(scan, twin+"/templates/widgets.yaml")
	if f == nil || f.Class != ClassTemplatedCopy || !slices.Equal(f.CRDs, []string{specCRDName}) || !strings.Contains(f.Detail, "joined with the spec file") {
		t.Fatalf("twin template: %+v", f)
	}
	if f.blocks() || f.opaque() || f.unreadable() {
		t.Fatalf("effects of %+v", f)
	}

	// The same fragment with no template that includes it keeps its
	// classification.
	lone := map[string]string{}
	for k, v := range to {
		lone[k] = v
	}
	delete(lone, twin+"/templates/widgets.yaml")
	loneFrom := map[string]string{}
	for k, v := range from {
		loneFrom[k] = v
	}
	delete(loneFrom, twin+"/templates/widgets.yaml")
	_, proof = run(loneFrom, lone)
	if f := findingOf(proof.To.Scan, twin+"/hack/widgets_spec.yaml"); f == nil || f.Class != ClassUnread {
		t.Fatalf("an unclaimed fragment: %+v", f)
	}

	// A template whose include is refused is unread as before, and its
	// fragment is not claimed.
	broken := map[string]string{}
	for k, v := range to {
		broken[k] = v
	}
	broken[twin+"/templates/widgets.yaml"] = strings.Replace(broken[twin+"/templates/widgets.yaml"], "hack/widgets_spec.yaml", "hack/other_spec.yaml", 1)
	p, proof = run(from, broken)
	if f := findingOf(proof.To.Scan, twin+"/templates/widgets.yaml"); f == nil || f.Class != ClassUnread || !strings.Contains(f.Detail, "template directives") {
		t.Fatalf("a refused include: %+v", f)
	}
	if f := findingOf(proof.To.Scan, twin+"/hack/widgets_spec.yaml"); f == nil || f.Class != ClassUnread {
		t.Fatalf("the fragment of a refused include: %+v", f)
	}
	if p.Status != extract.PairWithheld {
		t.Fatalf("a refused include: %s", p.Status)
	}

	// A twin that is not a copy of the listed definitions is unread, never
	// a conflict or an extra definition.
	stale := map[string]string{}
	for k, v := range to {
		stale[k] = v
	}
	stale[twin+"/hack/widgets_spec.yaml"] = kindDefault(specBody("v1beta1", "v1"))
	p, proof = run(from, stale)
	if f := findingOf(proof.To.Scan, twin+"/templates/widgets.yaml"); f == nil || f.Class != ClassUnread || !strings.Contains(f.Detail, "not a copy of the listed paths") || p.Status != extract.PairWithheld {
		t.Fatalf("a twin that differs: %s %+v", p.Status, f)
	}

	// A twin of a definition the listed paths do not hold is unread too.
	other := map[string]string{}
	for k, v := range to {
		other[k] = v
	}
	other[twin+"/templates/widgets.yaml"] = specTemplate("gadgets."+synthGroup, "hack/widgets_spec.yaml")
	other[twin+"/hack/widgets_spec.yaml"] = strings.NewReplacer("Widget", "Gadget", "widgets", "gadgets").Replace(kindDefault(specBody("v1")))
	_, proof = run(from, other)
	if f := findingOf(proof.To.Scan, twin+"/templates/widgets.yaml"); f == nil || f.Class != ClassUnread || !strings.Contains(f.Detail, "the listed paths do not hold") {
		t.Fatalf("a twin of another definition: %+v", f)
	}
}
