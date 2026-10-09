// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"fmt"
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
		"annotation":                      crdText("  annotations:\n    note: \"{{ .Chart.Name }}\"\n", "", desc),
		"label":                           crdText("  labels:\n    chart: \"{{ .Chart.Name }}\"\n", "", desc),
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
