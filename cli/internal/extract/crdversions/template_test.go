// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// crdText renders a one-version CRD whose name, metadata extras, version
// extras and OpenAPI schema body are given. schema is indented under
// openAPIV3Schema by the caller's own relative indentation.
func crdText(meta, versionExtra, schema string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: alphas.%s\n%sspec:\n  group: %s\n  names:\n    kind: Alpha\n    plural: alphas\n  scope: Namespaced\n  versions:\n  - name: v1\n    served: true\n    storage: true\n%s    schema:\n      openAPIV3Schema:\n", synthGroup, meta, synthGroup, versionExtra)
	for _, line := range strings.Split(strings.TrimRight(schema, "\n"), "\n") {
		fmt.Fprintf(&b, "        %s\n", line)
	}
	return b.String()
}

func parseText(t *testing.T, text string) ([]CRD, error) {
	t.Helper()
	_, crds, err := parseFile("deploy/crds/a.yaml", []byte(text))
	return crds, err
}

func requireRendered(t *testing.T, name, text string) {
	t.Helper()
	crds, err := parseText(t, text)
	if err != nil {
		t.Fatalf("%s: refused: %v", name, err)
	}
	if len(crds) != 1 || crds[0].Name != "alphas."+synthGroup || len(crds[0].Versions) != 1 || !crds[0].Versions[0].Served {
		t.Fatalf("%s: read %+v", name, crds)
	}
	// The same file without its "{{" is read identically: the admitted
	// text never changes what the extractor reads, lines included.
	plain, err := parseText(t, strings.ReplaceAll(text, "{{", "{ "))
	if err != nil {
		t.Fatalf("%s: the file without its braces is refused: %v", name, err)
	}
	if fmt.Sprint(plain) != fmt.Sprint(crds) {
		t.Fatalf("%s: read differently:\n%+v\n%+v", name, crds, plain)
	}
}

func requireTemplate(t *testing.T, name, text string) {
	t.Helper()
	_, err := parseText(t, text)
	pr, isProblem := asProblem(err)
	if err == nil || !isProblem || !strings.Contains(pr.msg, "contains template syntax") {
		t.Fatalf("%s: read as a rendered manifest (err %v)", name, err)
	}
}

// A description of the CRD schema may quote template syntax (Cluster API's
// ClusterClass documents its patch templates that way): the file is a
// rendered manifest, in every YAML spelling of a string.
func TestDescriptionsMayQuoteTemplateSyntax(t *testing.T) {
	const quoted = "Value is substituted from {{ .builtin.cluster.name }} and {{ .vars.x }}."
	for name, schema := range map[string]string{
		"plain":                      "type: object\ndescription: see {{ .builtin.cluster.name }} here",
		"double quoted":              "type: object\ndescription: \"" + quoted + "\"",
		"single quoted":              "type: object\ndescription: '" + quoted + "'",
		"literal block":              "type: object\ndescription: |-\n  First line.\n  " + quoted + "\n  Last {{ line }}.",
		"folded block":               "type: object\ndescription: >-\n  " + quoted + "\n  more text",
		"multi-line plain":           "type: object\ndescription: first line\n  continues with {{ .x }}",
		"three braces":               "type: object\ndescription: a {{{ b }}} c",
		"nested property":            "type: object\nproperties:\n  spec:\n    type: object\n    description: \"" + quoted + "\"\n    properties:\n      name:\n        type: string\n        description: \"{{ .name }}\"",
		"items and additional":       "type: object\nproperties:\n  list:\n    type: array\n    items:\n      type: object\n      description: \"{{ item }}\"\n  map:\n    type: object\n    additionalProperties:\n      type: string\n      description: \"{{ value }}\"",
		"allOf and not":              "type: object\nallOf:\n- description: \"{{ a }}\"\nnot:\n  description: \"{{ b }}\"",
		"a field called description": "type: object\nproperties:\n  description:\n    type: string\n    description: \"{{ the field }}\"",
	} {
		requireRendered(t, name, crdText("", "", schema))
	}
	// Descriptions of a second version and of a second document.
	two := crdText("", "", "type: object\ndescription: \"{{ a }}\"") + "---\n" + strings.Replace(crdText("", "", "type: object\ndescription: \"{{ b }}\""), "alphas.", "betas.", 1)
	two = strings.Replace(two, "kind: Alpha\n    plural: alphas", "kind: Beta\n    plural: betas", 2)
	two = strings.Replace(two, "kind: Beta\n    plural: betas", "kind: Alpha\n    plural: alphas", 1)
	if crds, err := parseText(t, two); err != nil || len(crds) != 2 {
		t.Fatalf("two documents: %v %v", crds, err)
	}
}

// Everything else that holds "{{" is template syntax: a name, a flag, an
// annotation, a default, an enumeration, a validation rule, a key, a
// comment, a directive line, a flow collection, a description outside the
// schema, a document that is not a CRD, a "{{" that an escape builds, and
// a file that mixes an admitted description with any of them.
func TestTemplateSyntaxElsewhereIsATemplate(t *testing.T) {
	desc := "type: object\ndescription: \"quoted {{ x }}\""
	cases := map[string]string{
		"quoted name":                     strings.Replace(crdText("", "", desc), "name: alphas."+synthGroup, "name: \"alphas.{{ .Values.domain }}\"", 1),
		"flow name":                       strings.Replace(crdText("", "", "type: object"), "name: alphas."+synthGroup, "name: {{ .Values.name }}", 1),
		"served flag":                     strings.Replace(crdText("", "", desc), "served: true", "served: {{ .Values.served }}", 1),
		"quoted served":                   strings.Replace(crdText("", "", desc), "served: true", "served: \"{{ .Values.served }}\"", 1),
		"version name":                    strings.Replace(crdText("", "", desc), "- name: v1", "- name: \"{{ .Values.version }}\"", 1),
		"group":                           strings.Replace(crdText("", "", desc), "group: "+synthGroup, "group: \"{{ .Values.group }}\"", 1),
		"annotation":                      crdText("  annotations:\n    note: chart {{ .Chart.Name }}\n", "", desc),
		"label":                           crdText("  labels:\n    chart: chart-{{ .Chart.Name }}\n", "", desc),
		"quoted label and description":    crdText("  labels:\n    chart: \"{{ .Chart.Name }}\"\n", "", desc),
		"directive line":                  "{{- if .Values.crds.enabled }}\n" + crdText("", "", desc) + "{{- end }}\n",
		"directive in the middle":         crdText("", "", desc) + "{{- if .Values.extra }}\n  # extra\n{{- end }}\n",
		"comment":                         crdText("", "", desc) + "# rendered by {{ .Chart.Name }}\n",
		"comment and description":         crdText("", "", desc) + "# {{ x }} {{ y }}\n",
		"default":                         crdText("", "", "type: object\nproperties:\n  a:\n    type: string\n    default: \"{{ x }}\""),
		"enum":                            crdText("", "", "type: object\nproperties:\n  a:\n    type: string\n    enum:\n    - \"{{ x }}\""),
		"example":                         crdText("", "", "type: object\nproperties:\n  a:\n    type: string\n    example: \"{{ x }}\""),
		"validation rule":                 crdText("", "", "type: object\nx-kubernetes-validations:\n- rule: \"self.x != '{{'\"\n  message: \"no {{\""),
		"pattern":                         crdText("", "", "type: object\nproperties:\n  a:\n    type: string\n    pattern: \"^{{\""),
		"schema key":                      crdText("", "", "type: object\nproperties:\n  \"{{ key }}\":\n    type: string"),
		"printer column":                  crdText("", "    additionalPrinterColumns:\n    - name: Age\n      type: string\n      jsonPath: .metadata.creationTimestamp\n      description: \"{{ age }}\"\n", "type: object"),
		"conversion":                      strings.Replace(crdText("", "", desc), "  scope: Namespaced\n", "  scope: Namespaced\n  conversion:\n    strategy: Webhook\n    webhook:\n      clientConfig:\n        service:\n          namespace: \"{{ .Release.Namespace }}\"\n          name: webhook\n      conversionReviewVersions: [v1]\n", 1),
		"description outside":             strings.Replace(crdText("", "", desc), "  scope: Namespaced\n", "  scope: Namespaced\n  description: \"{{ x }}\"\n", 1),
		"version description":             strings.Replace(crdText("", "", desc), "    storage: true\n", "    storage: true\n    description: \"{{ x }}\"\n", 1),
		"flow collection":                 crdText("", "", "type: object\nrequired: [{{ a }}]"),
		"flow in flow":                    crdText("", "", "type: object\nproperties: {a: {{ b }}}"),
		"other document":                  crdText("", "", desc) + "---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\ndata:\n  description: \"{{ x }}\"\n",
		"description of a ConfigMap":      "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\ndata:\n  description: \"{{ x }}\"\n",
		"comment and escaped description": crdText("", "", "type: object\ndescription: \"\\x7b\\x7b x }}\"") + "# {{ y\n",
		"escape and structural":           strings.Replace(crdText("", "", "type: object\ndescription: \"\\x7b\\x7b x }}\""), "served: true", "served: \"{{ x }}\"", 1),
		"unparsable":                      "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata: {{ x\n",
		"directive then schema":           "{{ define \"x\" }}\n" + crdText("", "", desc),
	}
	for name, text := range cases {
		requireTemplate(t, name, text)
	}
}

// Text that only decodes to "{{" (an escape sequence, a line continuation)
// holds no "{{" in its bytes, so no template engine finds an action in it:
// the file is a rendered manifest. The same text beside a "{{" that is in
// the bytes (above) is not.
func TestDecodedBracesWithoutBracesInTheBytesAreNotTemplates(t *testing.T) {
	requireRendered(t, "escape", crdText("", "", "type: object\ndescription: \"\\x7b\\x7b x }}\""))
	requireRendered(t, "line continuation", crdText("", "", "type: object\ndescription: \"{\\\n  {\""))
}

// The refusal does not depend on the order of the file, on how many
// descriptions there are or on how long the quoted text is.
func TestTemplateRuleIsExactAboutCounts(t *testing.T) {
	many := "type: object\nproperties:\n"
	for i := 0; i < 50; i++ {
		many += fmt.Sprintf("  f%d:\n    type: string\n    description: \"{{ v%d }}\"\n", i, i)
	}
	requireRendered(t, "fifty descriptions", crdText("", "", many))
	requireTemplate(t, "fifty descriptions and a comment", crdText("", "", many)+"# {{\n")
	requireTemplate(t, "fifty descriptions and a name", strings.Replace(crdText("", "", many), "served: true", "served: {{ x }}", 1))
	long := "type: object\ndescription: \"" + strings.Repeat("{{ a }} ", 400) + "\""
	requireRendered(t, "long description", crdText("", "", long))
	requireTemplate(t, "long description and a comment", crdText("", "", long)+"# {{\n")
}

// A file whose descriptions quote template syntax is a derived pair, not a
// withheld one; a real template stays withheld. (Cluster API's ClusterClass.)
func TestQuotedTemplateDescriptionsDoNotWithholdAPair(t *testing.T) {
	schema := "type: object\ndescription: \"patch {{ .builtin.cluster.name }}\"\nproperties:\n  spec:\n    type: object"
	one := func(extra string) release {
		return release{tag: "", files: map[string]string{"deploy/crds/a.yaml": crdText("", "", schema) + extra}}
	}
	releases := func(extra string) []release {
		var out []release
		for _, tag := range []string{"v1.0.0", "v1.1.0", "v1.2.0"} {
			r := one(extra)
			r.tag = tag
			out = append(out, r)
		}
		return out
	}
	out := runSynth(t, synthTarget(), newSynth(releases("")...))
	for _, p := range out.Manifest.Pairs {
		_, proof := pairOf(t, out, p.From, p.To)
		if p.Status != extract.PairDerived || !proof.Completeness.Attestable {
			t.Fatalf("pair %s -> %s: %s, attestable %v (%+v)", p.From, p.To, p.Status, proof.Completeness.Attestable, proof.Completeness.Reasons)
		}
	}
	// The same releases with a real template directive in the file are
	// withheld, as before.
	templated := runSynth(t, synthTarget(), newSynth(releases("{{- if .Values.extra }}\n# x\n{{- end }}\n")...))
	for _, p := range templated.Manifest.Pairs {
		if p.Status == extract.PairDerived {
			t.Fatalf("pair %s -> %s derived from a template", p.From, p.To)
		}
	}
}

// FuzzTemplateRule: whatever the bytes, a file that holds "{{" and is read as
// a rendered manifest is read the same without its "{{" (the braces carry no
// meaning for the extractor), and a file that parses without any "{{" is
// unaffected by the rule.
func FuzzTemplateRule(f *testing.F) {
	f.Add([]byte(crdText("", "", "type: object\ndescription: \"a {{ b }}\"")))
	f.Add([]byte(crdText("", "", "type: object\ndescription: |-\n  a {{ b }}\n  c")))
	f.Add([]byte(crdText("", "", "type: object\ndescription: x\n") + "# {{\n"))
	f.Add([]byte(strings.Replace(crdText("", "", "type: object"), "served: true", "served: {{ x }}", 1)))
	f.Add([]byte(crdText("", "", "type: object\ndescription: \"\\x7b\\x7b\"")))
	f.Add([]byte(strings.SplitN(cmFile(cmDoc("Alpha")), "\n", 2)[1]))
	f.Add([]byte(cmFile(cmDoc("Alpha"))))
	f.Add([]byte(cmDoc("Alpha") + "---\n" + cmDoc("Beta")))
	f.Add([]byte(strings.Replace(cmDoc("Alpha"), "  - name: v1\n", "  # {{- if .x }}\n  - name: v1\n", 1) + "  # {{- end }}\n"))
	f.Add([]byte(strings.Replace(cmDoc("Alpha"), "helm.sh/resource-policy: keep", "note: |\n      # {{ .x }}", 1)))
	f.Add([]byte(crdText("  labels:\n    a: '{{ .Release.Name }}'\n", "", "type: object")))
	f.Add([]byte(lineBreakShift("\u2028")))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, crds, err := parseFile("deploy/crds/a.yaml", data)
		if err != nil || !strings.Contains(string(data), "{{") {
			return
		}
		plain := strings.ReplaceAll(string(data), "{{", "{ ")
		_, other, err := parseFile("deploy/crds/a.yaml", []byte(plain))
		if err != nil || fmt.Sprint(crds) != fmt.Sprint(other) {
			t.Fatalf("a file with braces was read, but not the same without them: %v\n%q", err, data)
		}
	})
}

// cmHeader is cert-manager's declared template header.
const cmHeader = `include "cert-manager.crd-check" .`

// cmDoc renders one CRD document written as cert-manager writes
// deploy/crds/crd-*.yaml from 1.16 to 1.18: a condition and its end around
// the annotations, quoted labels that are template actions, and generated
// labels included under them, all in metadata.
func cmDoc(kind string) string {
	plural := strings.ToLower(kind) + "s"
	return fmt.Sprintf(`apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: %s.%s
  # START annotations {{- if .Values.crds.keep }}
  annotations:
    helm.sh/resource-policy: keep
  # END annotations {{- end }}
  labels:
    app: '{{ template "cert-manager.name" . }}'
    app.kubernetes.io/name: '{{ template "cert-manager.name" . }}'
    app.kubernetes.io/instance: "{{ .Release.Name }}"
    # Generated labels {{- include "labels" . | nindent 4 }}
spec:
  group: %s
  names:
    kind: %s
    plural: %s
  scope: Namespaced
  versions:
  - name: v1
    served: true
    storage: true
    schema:
      openAPIV3Schema:
        type: object
`, plural, synthGroup, synthGroup, kind, plural)
}

// cmFile wraps documents in cert-manager's header and file condition.
func cmFile(docs ...string) string {
	return "# {{- include \"cert-manager.crd-check\" . }}\n# START crd {{- if or .Values.crds.enabled .Values.installCRDs }}\n" + strings.Join(docs, "---\n") + "# END crd {{- end -}}\n"
}

func parseHeaderText(text, header string) ([]CRD, error) {
	_, crds, err := parseFileHeader("deploy/crds/a.yaml", []byte(text), header)
	return crds, err
}

// A file whose "{{" are all comment directives (the declared header, the
// condition around the file, conditions and includes in metadata) or
// actions in quoted metadata labels and annotations is read as written, the
// same as without its braces.
func TestCommentDirectivesAndMetadataStringsAreRead(t *testing.T) {
	two := cmFile(cmDoc("Alpha"), cmDoc("Beta"))
	for name, tc := range map[string]struct {
		text  string
		kinds int
	}{
		"cert-manager":                     {cmFile(cmDoc("Alpha")), 1},
		"two documents, one condition":     {two, 2},
		"no header":                        {strings.SplitN(cmFile(cmDoc("Alpha")), "\n", 2)[1], 1},
		"no condition around the file":     {cmDoc("Alpha"), 1},
		"template comment anywhere":        {strings.Replace(cmFile(cmDoc("Alpha")), "  scope: Namespaced\n", "  # {{/* a note */}}\n  scope: Namespaced\n", 1), 1},
		"with and toYaml in metadata":      {strings.Replace(cmFile(cmDoc("Alpha")), "  labels:\n", "  # {{- with .Values.extra }}\n  # {{- toYaml . | nindent 2 }}\n  # {{- end }}\n  labels:\n", 1), 1},
		"quoted annotation":                {strings.Replace(cmFile(cmDoc("Alpha")), "helm.sh/resource-policy: keep", "note: 'by {{ .Release.Name }}'", 1), 1},
		"quoted label without a condition": {crdText("  labels:\n    chart: \"{{ .Chart.Name }}\"\n", "", "type: object"), 1},
	} {
		crds, err := parseHeaderText(tc.text, cmHeader)
		if err != nil || len(crds) != tc.kinds {
			t.Fatalf("%s: %v %+v", name, err, crds)
		}
		for _, c := range crds {
			if len(c.Versions) != 1 || !c.Versions[0].Served || !c.Versions[0].Storage {
				t.Fatalf("%s: read %+v", name, c)
			}
		}
		plain, err := parseHeaderText(strings.ReplaceAll(tc.text, "{{", "{ "), cmHeader)
		if err != nil || fmt.Sprint(plain) != fmt.Sprint(crds) {
			t.Fatalf("%s: read differently without braces: %v\n%+v\n%+v", name, err, crds, plain)
		}
	}
}

// Every other place or shape of "{{" in such a file is template syntax.
func TestCommentDirectivesElsewhereAreTemplates(t *testing.T) {
	cm := cmFile(cmDoc("Alpha"))
	replace := func(old, new string) string {
		if !strings.Contains(cm, old) {
			t.Fatalf("fixture lacks %q", old)
		}
		return strings.Replace(cm, old, new, 1)
	}
	const endLine = "# END crd {{- end -}}\n"
	configMap := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n  # {{- if .Values.x }}\n  labels:\n    a: b\n  # {{- end }}\ndata:\n  a: b\n"
	cases := map[string]string{
		"key":                                      replace("    app: '{{", "    '{{ .x }}': a\n    app: '{{"),
		"string outside metadata":                  replace("    storage: true\n", "    storage: true\n    deprecationWarning: '{{ .x }}'\n"),
		"metadata name":                            replace("  name: alphas."+synthGroup, "  name: 'alphas.{{ .x }}'"),
		"comment in a block scalar":                replace("helm.sh/resource-policy: keep", "note: |\n      # {{ .x }}"),
		"condition around a version":               strings.Replace(replace("  - name: v1\n", "  # {{- if .Values.v1 }}\n  - name: v1\n"), endLine, "  # {{- end }}\n"+endLine, 1),
		"if without end":                           strings.TrimSuffix(cm, endLine),
		"end not last":                             strings.Replace(cm, endLine, "# END crd {{- end }}\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n", 1),
		"template comment that trims in a label":   replace("'{{ template \"cert-manager.name\" . }}'\n    app.kubernetes.io/name", "'{{- /* x */ -}}'\n    app.kubernetes.io/name"),
		"line separators shift the metadata block": lineBreakShift(" "),
		"NEL shifts the metadata block":            lineBreakShift("\u0085"),
		"PS shifts the metadata block":             lineBreakShift(" "),
		"line separator before a quoted label":     replace("  labels:\n", "  # pad"+strings.Repeat(" ", 3)+"\n  labels:\n"),
		"trim after, not last":                     replace("# END annotations {{- end }}", "# END annotations {{- end -}}"),
		"directive not a comment":                  replace("# START crd {{- if", "{{- if"),
		"two actions on a line":                    replace("| nindent 4 }}", "| nindent 4 }} {{ .x }}"),
		"plain label":                              replace("\"{{ .Release.Name }}\"", "x-{{ .Release.Name }}"),
		"plain label, quoted twice":                replace("app: '{{ template", "app: a{{ template"),
		"multi-line label":                         replace("\"{{ .Release.Name }}\"", "\"a\n      {{ .Release.Name }}\""),
		"label with a comment":                     replace("\"{{ .Release.Name }}\"", "\"{{ .Release.Name }}\" # {{ .x }}"),
		"label with an escape":                     replace("\"{{ .Release.Name }}\"", "\"\\x41{{ .Release.Name }}\""),
		"label with an if":                         replace("\"{{ .Release.Name }}\"", "\"{{ if .x }}a{{ end }}\""),
		"label that trims":                         replace("\"{{ .Release.Name }}\"", "\"{{- .Release.Name }}\""),
		"label with an assignment":                 replace("\"{{ .Release.Name }}\"", "\"{{ $x := 1 }}\""),
		"label with braces inside":                 replace("\"{{ .Release.Name }}\"", "\"{{ .x {{ .y }}\""),
		"annotation outside metadata":              replace("  scope: Namespaced\n", "  scope: Namespaced\n  metadata:\n    annotations:\n      a: '{{ .x }}'\n"),
		"header twice":                             "# {{- include \"cert-manager.crd-check\" . }}\n" + cm,
		"header after the condition":               strings.Replace(cm, "# {{- include \"cert-manager.crd-check\" . }}\n# START crd {{- if or .Values.crds.enabled .Values.installCRDs }}\n", "# START crd {{- if or .Values.crds.enabled .Values.installCRDs }}\n# {{- include \"cert-manager.crd-check\" . }}\n", 1),
		"condition after content":                  strings.Replace(cm, "# START crd {{- if or .Values.crds.enabled .Values.installCRDs }}\napiVersion: apiextensions.k8s.io/v1\n", "apiVersion: apiextensions.k8s.io/v1\n# START crd {{- if or .Values.crds.enabled .Values.installCRDs }}\n", 1),
		"range in a comment":                       replace("  labels:\n", "  # {{- range .Values.x }}\n  # {{- end }}\n  labels:\n"),
		"else in metadata":                         replace("  # END annotations {{- end }}", "  # {{- else }}\n  # END annotations {{- end }}"),
		"expression in a comment":                  replace("  labels:\n", "  # {{ .Release.Name }}\n  labels:\n"),
		"include without nindent":                  replace("| nindent 4 }}", "}}"),
		"define in a comment":                      replace("  labels:\n", "  # {{ define \"x\" }}\n  labels:\n"),
		"metadata condition left open":             replace("  # END annotations {{- end }}\n", ""),
		"end in metadata of the file condition":    replace("  # END annotations {{- end }}\n", "  # END annotations {{- end }}\n  # {{- end }}\n"),
		"directive between documents":              cmFile(cmDoc("Alpha"), "# {{ include \"x\" . | nindent 2 }}\n"+cmDoc("Beta")),
		"comment in another kind":                  cmFile(cmDoc("Alpha"), configMap),
		"description and comments":                 replace("        type: object\n", "        type: object\n        description: \"{{ .x }}\"\n"),
		"CRLF":                                     strings.ReplaceAll(cm, "\n", "\r\n"),
	}
	for name, text := range cases {
		_, err := parseHeaderText(text, cmHeader)
		pr, isProblem := asProblem(err)
		if err == nil || !isProblem || !strings.Contains(pr.msg, "contains template syntax") {
			t.Errorf("%s: read as a rendered manifest (err %v)", name, err)
		}
	}
	// The header is admitted only as declared.
	for name, header := range map[string]string{"undeclared": "", "another": `include "other.check" .`} {
		if _, err := parseHeaderText(cm, header); err == nil {
			t.Errorf("header %s: read", name)
		}
	}
	requireTemplate(t, "header without a declaration", cm)
	// The end-not-last case is refused for that reason, not for a trim.
	text := []byte(cases["end not last"])
	nodes, values, err := decodeStrict(text)
	if err != nil {
		t.Fatal(err)
	}
	if why := templateInCommentsAndMetadata(text, nodes, values, cmHeader); !strings.Contains(why, "ends before its last line") {
		t.Fatalf("end not last: %q", why)
	}
}

// A target's declared header is the only include it admits: it is checked
// when the target loads.
func TestTemplateHeaderDeclaration(t *testing.T) {
	var cm Target
	for _, tg := range Targets {
		if tg.Project == "cert-manager" {
			cm = tg
		}
	}
	if cm.TemplateHeader == nil || cm.TemplateHeader.Action != cmHeader {
		t.Fatalf("cert-manager header: %+v", cm.TemplateHeader)
	}
	raw, err := source.ReadFile(TargetFileName("cert-manager"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ old, new, want string }{
		{`"action": "include \"cert-manager.crd-check\" ."`, `"action": "include \"cert-manager.crd-check\" .Values"`, "templateHeader action"},
		{`"action": "include \"cert-manager.crd-check\" ."`, `"action": "if .Values.x"`, "templateHeader action"},
		{`"action": "include \"cert-manager.crd-check\" ."`, `"action": ""`, "templateHeader action"},
		{`"evidence": "Read at every final tag`, `"evidence": "short", "x": "Read at every final tag`, "unknown field"},
	} {
		mutated := strings.Replace(string(raw), tc.old, tc.new, 1)
		if mutated == string(raw) {
			t.Fatalf("mutation %q did not apply", tc.old)
		}
		if _, err := LoadTarget(TargetFileName("cert-manager"), []byte(mutated)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: %v", tc.new, err)
		}
	}
	short := regexp.MustCompile(`"evidence": "Read at every final tag.*can only fail the rendering\."`).ReplaceAllString(string(raw), `"evidence": "too short"`)
	if _, err := LoadTarget(TargetFileName("cert-manager"), []byte(short)); err == nil || !strings.Contains(err.Error(), "templateHeader: evidence") {
		t.Fatalf("short evidence: %v", err)
	}
}

// cert-manager-shaped releases are derived and attestable pairs when the
// target declares the header, and withheld when it does not.
func TestCommentDirectivesDoNotWithholdAPair(t *testing.T) {
	releases := func() []release {
		var out []release
		for _, tag := range []string{"v1.0.0", "v1.1.0", "v1.2.0"} {
			out = append(out, release{tag: tag, files: map[string]string{"deploy/crds/a.yaml": cmFile(cmDoc("Alpha"))}})
		}
		return out
	}
	declared := synthTarget()
	declared.TemplateHeader = &TemplateHeader{Action: cmHeader, Evidence: "test"}
	out := runSynth(t, declared, newSynth(releases()...))
	if len(out.Manifest.Pairs) == 0 {
		t.Fatal("no pairs")
	}
	for _, p := range out.Manifest.Pairs {
		_, proof := pairOf(t, out, p.From, p.To)
		if p.Status != extract.PairDerived || !proof.Completeness.Attestable {
			t.Fatalf("pair %s -> %s: %s, attestable %v (%+v)", p.From, p.To, p.Status, proof.Completeness.Attestable, proof.Completeness.Reasons)
		}
	}
	undeclared := runSynth(t, synthTarget(), newSynth(releases()...))
	for _, p := range undeclared.Manifest.Pairs {
		if p.Status == extract.PairDerived {
			t.Fatalf("pair %s -> %s derived without a declared header", p.From, p.To)
		}
	}
}

// lineBreakShift builds two CRD documents in which sep, a byte sequence the
// YAML decoder counts as a line break but "\n" splitting does not, follows
// a comment before the first document's metadata, as many times as the
// first document's metadata key needs to land on the second document's
// metadata line. The first document's metadata block is longer than the
// second document's span from its metadata to a condition around its
// version entry, so a metadata block located by decoded lines and applied
// to split lines would cover that condition.
func lineBreakShift(sep string) string {
	var labels strings.Builder
	for i := 0; i < 13; i++ {
		fmt.Fprintf(&labels, "    l%d: v\n", i)
	}
	doc1 := func(pad string) string {
		return "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\n# pad" + pad + "\nmetadata:\n  name: alphas." + synthGroup + "\n  labels:\n" + labels.String() +
			"spec:\n  group: " + synthGroup + "\n  names:\n    kind: Alpha\n    plural: alphas\n  scope: Namespaced\n  versions:\n  - name: v1\n    served: true\n    storage: true\n"
	}
	doc2 := "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: betas." + synthGroup + "\nspec:\n  group: " + synthGroup + "\n  names:\n    kind: Beta\n    plural: betas\n  scope: Namespaced\n  versions:\n  # {{- if .Values.v1 }}\n  - name: v1\n    served: true\n    storage: true\n  # {{- end }}\n"
	plain := doc1("") + "---\n" + doc2
	lines := strings.Split(plain, "\n")
	m1, m2 := -1, -1
	for i, l := range lines {
		if l == "metadata:" {
			if m1 < 0 {
				m1 = i
			} else {
				m2 = i
			}
		}
	}
	return doc1(strings.Repeat(sep, m2-m1)) + "---\n" + doc2
}
