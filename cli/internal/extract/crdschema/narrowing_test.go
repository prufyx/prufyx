// SPDX-License-Identifier: AGPL-3.0-only

package crdschema

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const widgetX = "example.io/Widget/spec/x"

// withMeta replaces the metadata block of a simple CRD.
func withMeta(meta string, props ...string) []byte {
	return bytes.Replace(simpleCRD(props...), []byte("metadata:\n  name: widgets.example.io\n"), []byte(meta+"\n"), 1)
}

// kustCase puts a file next to a CRD that loses the field x, at both commits.
func kustCase(name, file, content string, exp expected) testCase {
	return testCase{
		name: name,
		from: map[string][]byte{"crd/widget.yaml": simpleCRD("k", "x"), "crd/" + file: []byte(content)},
		to:   map[string][]byte{"crd/widget.yaml": simpleCRD("k"), "crd/" + file: []byte(content)},
		exp:  exp,
	}
}

func flowCase(name, meta string, exp expected) testCase {
	return testCase{name: name,
		from: map[string][]byte{"crd/crd.yaml": simpleCRD("k", "x")},
		to:   map[string][]byte{"crd/crd.yaml": withMeta(meta, "k")},
		exp:  exp}
}

func narrowingCases() []testCase {
	const kust = "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n- widget.yaml\n"
	const kustA = "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n- widget.yaml\n"
	gadgetCRD := strings.NewReplacer("kind: Widget", "kind: Gadget", "plural: widgets", "plural: gadgets", "widgets.example.io", "gadgets.example.io").Replace(string(simpleCRD("k")))
	const kustAB = kustA + "- ./gadget.yaml\n"
	skipped := func(f string) expected {
		return expected{Fields: []string{widgetX}, Complete: true, Exclusions: []string{"KUSTOMIZE_FILE_SKIPPED|crd/" + f + "|2"}}
	}
	withheld := func(reason, f string) expected {
		return expected{Fields: []string{widgetX}, Omissions: []string{reason + "|crd/" + f + "|2"}}
	}
	flowOK := expected{Fields: []string{widgetX}, Complete: true}
	flowBad := expected{Omissions: []string{"CRD_PARSE_UNPROVEN|crd/crd.yaml|1", "CRD_PRESENCE_UNSTABLE|example.io/Widget|1"}}
	m := func(list string) string { return "metadata: {name: widgets.example.io, finalizers: " + list + "}" }
	return []testCase{
		// Change 1: kustomize files.
		kustCase("kustomize_skipped", "kustomization.yaml", kust, skipped("kustomization.yaml")),
		kustCase("kustomize_yml_component_skipped", "kustomization.yml",
			"kind: Component\napiVersion: kustomize.config.k8s.io/v1alpha1\nnamespace: n\nresources: [widget.yaml]\n", skipped("kustomization.yml")),
		kustCase("kustomize_crd_marker", "kustomization.yaml",
			kust+"metadata:\n  name: k\n  annotations:\n    note: CustomResourceDefinition\n", withheld("NON_CRD_DOCUMENT", "kustomization.yaml")),
		kustCase("kustomize_crd_marker_upper", "kustomization.yaml",
			kust+"metadata:\n  name: k\n  annotations:\n    note: CUSTOMRESOURCEDEFINITION\n", withheld("NON_CRD_DOCUMENT", "kustomization.yaml")),
		kustCase("kustomize_duplicate_key", "kustomization.yaml", kust+"kind: Kustomization\n", withheld("NON_CRD_DOCUMENT", "kustomization.yaml")),
		kustCase("kustomize_anchor", "kustomization.yaml", kust+"metadata: &m {name: k}\n", withheld("NON_CRD_DOCUMENT", "kustomization.yaml")),
		kustCase("kustomize_resource_entry_map", "kustomization.yaml",
			"apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources: [widget.yaml, {a: b}]\n", withheld("NON_CRD_DOCUMENT", "kustomization.yaml")),
		kustCase("kustomize_oversize", "kustomization.yaml", kust+"#"+strings.Repeat("x", maxFileBytes), withheld("CRD_TOO_LARGE", "kustomization.yaml")),
		kustCase("kustomize_patches", "kustomization.yaml", kust+"patches:\n- path: p.yaml\n", withheld("NON_CRD_DOCUMENT", "kustomization.yaml")),
		kustCase("kustomize_foreign_apiversion", "kustomization.yaml", "apiVersion: apps/v1\nkind: Kustomization\n", withheld("NON_CRD_DOCUMENT", "kustomization.yaml")),
		kustCase("kustomize_wrong_kind", "kustomization.yaml", "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Other\n", withheld("NON_CRD_DOCUMENT", "kustomization.yaml")),
		kustCase("kustomize_malformed", "kustomization.yaml", "kind: Kustomization\nresources: [a, \n", withheld("CRD_PARSE_UNPROVEN", "kustomization.yaml")),
		kustCase("kustomize_two_documents", "kustomization.yaml", kust+"---\n"+kust, expected{Fields: []string{widgetX}, Omissions: []string{"NON_CRD_DOCUMENT|crd/kustomization.yaml|4"}}),
		kustCase("kustomize_other_name", "crd.yaml", kust, withheld("NON_CRD_DOCUMENT", "crd.yaml")),
		{name: "kustomize_hidden_removal",
			from: map[string][]byte{"crd/widget.yaml": simpleCRD("k"), "crd/gadget.yaml": []byte(gadgetCRD), "crd/kustomization.yaml": []byte(kustAB)},
			to:   map[string][]byte{"crd/widget.yaml": simpleCRD("k"), "crd/gadget.yaml": []byte(gadgetCRD), "crd/kustomization.yaml": []byte(kustA)},
			exp:  expected{Omissions: []string{"NON_CRD_DOCUMENT|crd/kustomization.yaml|1"}, Exclusions: []string{"KUSTOMIZE_FILE_SKIPPED|crd/kustomization.yaml|1"}}},
		kustCase("kustomize_foreign_resource", "kustomization.yaml", kust+"- ../extra\n", withheld("NON_CRD_DOCUMENT", "kustomization.yaml")),
		kustCase("kustomize_name_case", "Kustomization.yaml", kust, withheld("NON_CRD_DOCUMENT", "Kustomization.yaml")),
		kustCase("kustomize_secret_generator", "kustomization.yaml", kust+"secretGenerator:\n- name: s\n", withheld("NON_CRD_DOCUMENT", "kustomization.yaml")),

		// Change 2: quoted scalars in flow collections.
		flowCase("flow_quoted_double", m(`["a", "b"]`), flowOK),
		flowCase("flow_quoted_single", m(`['a', 'b']`), flowOK),
		flowCase("flow_quoted_mixed", m(`[a, "b", 'c u']`), flowOK),
		flowCase("flow_quoted_coercible_strings", m(`["true", "null", "1e3", "~", '123', "", "é"]`), flowOK),
		flowCase("flow_quoted_escape", m(`["a\tb"]`), flowBad),
		flowCase("flow_quoted_hex_escape", m(`["\x41"]`), flowBad),
		flowCase("flow_quoted_single_escape", m(`['it''s']`), flowBad),
		flowCase("flow_quoted_multiline", "metadata: {name: widgets.example.io, finalizers: [\"a\n  b\"]}", flowBad),
		// U+2028 earlier in the file is a line end for the decoder but not for a
		// split on \n; the next physical line looks like a valid quoted list.
		flowCase("flow_quoted_after_unicode_break",
			"metadata:\n  name: widgets.example.io\n  annotations:\n    n: \"p\u2028q\"\n  finalizers: [\"a\"]\n  finalizerz:  \"a\"", flowBad),
		flowCase("flow_quoted_crlf", "metadata: {name: widgets.example.io, finalizers: [\"a\"]}\r", flowOK),
		flowCase("flow_quoted_tagged", m(`[!!str "a"]`), flowBad),
		flowCase("flow_quoted_anchor", m(`[&a "a"]`), flowBad),
		flowCase("flow_quoted_alias", m(`[&a b, *a]`), flowBad),
		{name: "flow_quoted_enum_strings",
			from: map[string][]byte{"crd/crd.yaml": enumCRD(`enum: [a, "true", "null", "1e3"]`)},
			to:   map[string][]byte{"crd/crd.yaml": enumCRD(`enum: ["a"]`)},
			exp: expected{Complete: true, Enums: []string{
				"example.io/Widget/spec/mode/1e3", "example.io/Widget/spec/mode/null", "example.io/Widget/spec/mode/true"}}},

		// Change 3 is not made: a same-named new path stays a rename candidate,
		// whatever the name. These pin that, including the generic name `name`.
		{name: "rename_generic_name_kept",
			from: map[string][]byte{"crd/crd.yaml": nestedCRD("ref:\n                type: object\n                properties:\n                  name:\n                    type: string\n                  group:\n                    type: string\n")},
			to:   map[string][]byte{"crd/crd.yaml": nestedCRD("other:\n                type: object\n                properties:\n                  name:\n                    type: string\n                  size:\n                    type: integer\n")},
			exp:  expected{Omissions: []string{"RENAME_CANDIDATE|example.io/Widget|1"}}},
		{name: "rename_equal_fingerprint_kept",
			from: map[string][]byte{"crd/crd.yaml": nestedCRD("timeout:\n                type: string\n")},
			to:   map[string][]byte{"crd/crd.yaml": nestedCRD("adv:\n                type: object\n                properties:\n                  timeout:\n                    type: string\n")},
			exp:  expected{Omissions: []string{"RENAME_CANDIDATE|example.io/Widget|1"}}},
		{name: "rename_different_type_kept",
			from: map[string][]byte{"crd/crd.yaml": nestedCRD("timeout:\n                type: string\n")},
			to:   map[string][]byte{"crd/crd.yaml": nestedCRD("adv:\n                type: object\n                properties:\n                  timeout:\n                    type: integer\n")},
			exp:  expected{Omissions: []string{"RENAME_CANDIDATE|example.io/Widget|1"}}},
	}
}

// nestedCRD is a CRD with the property k plus extra, which starts at the
// indentation of the spec properties.
func nestedCRD(extra string) []byte {
	return append(simpleCRD("k"), []byte("              "+extra)...)
}

func enumCRD(enum string) []byte {
	return append(simpleCRD("k"), []byte("              mode:\n                type: string\n                "+enum+"\n")...)
}

// A quoted scalar in a flow list is a string, whatever it looks like.
func TestQuotedFlowScalarsStayStrings(t *testing.T) {
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(`["true", "null", "1e3", "~", 'x']`), &n); err != nil {
		t.Fatal(err)
	}
	for _, c := range n.Content[0].Content {
		if c.Tag != "!!str" {
			t.Errorf("%q has tag %s", c.Value, c.Tag)
		}
	}
}

// isKustomizeFile, one property at a time.
func TestIsKustomizeFileOneFieldAtATime(t *testing.T) {
	const ok = "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n- a.yaml\n"
	for _, tc := range []struct {
		name, file, body string
		want             bool
	}{
		{"base", "kustomization.yaml", ok, true},
		{"yml", "d/kustomization.yml", ok, true},
		{"component without apiVersion", "kustomization.yaml", "kind: Component\nresources: [a.yaml]\n", true},
		{"other name", "kustomization.yaml.txt", ok, false},
		{"upper-case name", "KUSTOMIZATION.yaml", ok, false},
		{"marker upper", "kustomization.yaml", ok + "x: CUSTOMRESOURCEDEFINITION\n", false},
		{"marker lower", "kustomization.yaml", ok + "metadata: {name: customresourcedefinition}\n", false},
		{"duplicate kind", "kustomization.yaml", ok + "kind: Kustomization\n", false},
		{"anchor", "kustomization.yaml", ok + "metadata: &m {name: k}\n", false},
		{"tag", "kustomization.yaml", ok + "namespace: !!str n\n", false},
		{"resource entry map", "kustomization.yaml", "kind: Kustomization\nresources: [{a: b}]\n", false},
		{"resource entry number", "kustomization.yaml", "kind: Kustomization\nresources: [1]\n", false},
		{"resources not a list", "kustomization.yaml", "kind: Kustomization\nresources: a\n", false},
		{"unknown key", "kustomization.yaml", ok + "patches: []\n", false},
		{"no kind", "kustomization.yaml", "resources: [a]\n", false},
		{"other kind", "kustomization.yaml", "kind: Deployment\n", false},
		{"foreign apiVersion", "kustomization.yaml", "apiVersion: apps/v1\nkind: Kustomization\n", false},
		{"two documents", "kustomization.yaml", ok + "---\n" + ok, false},
		{"list root", "kustomization.yaml", "- a\n", false},
		{"oversize", "kustomization.yaml", ok + "#" + strings.Repeat("x", maxFileBytes), false},
	} {
		if got := isKustomizeFile(tc.file, []byte(tc.body), []string{"a.yaml"}, defaultGuards().parse); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A kustomize file is skipped only when its resources name every sibling YAML
// file of the directory.
func TestIsKustomizeFileSiblingsMustBeNamed(t *testing.T) {
	const body = "kind: Kustomization\nresources:\n- a.yaml\n- ./b.yaml\n"
	for _, tc := range []struct {
		name     string
		siblings []string
		want     bool
	}{
		{"no sibling, entries are not siblings", nil, false},
		{"all named", []string{"a.yaml", "b.yaml"}, true},
		{"one unnamed", []string{"a.yaml", "c.yaml"}, false},
		{"path entry does not name a sibling", []string{"sub/a.yaml"}, false},
	} {
		if got := isKustomizeFile("kustomization.yaml", []byte(body), tc.siblings, defaultGuards().parse); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A file the target names explicitly is read, never skipped as kustomize.
func TestExplicitKustomizationFileIsRead(t *testing.T) {
	const kust = "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n- widget.yaml\n"
	tg := Target{Repo: repo, Files: []string{"crd/widget.yaml", "crd/kustomization.yaml"}}
	m := newMem()
	for _, c := range []string{commitA, commitB} {
		m.put(c, "crd/kustomization.yaml", []byte(kust))
	}
	m.put(commitA, "crd/widget.yaml", simpleCRD("k", "x"))
	m.put(commitB, "crd/widget.yaml", simpleCRD("k"))
	res, err := Derive(context.Background(), m, tg, commitA, commitB)
	if err != nil {
		t.Fatal(err)
	}
	if res.Attestable() || len(res.Exclusions) != 0 {
		t.Fatalf("explicit kustomization.yaml was skipped: %+v", res)
	}
	found := false
	for _, o := range res.Omissions {
		found = found || (o.Reason == "NON_CRD_DOCUMENT" && o.Subject == "crd/kustomization.yaml")
	}
	if !found {
		t.Fatalf("no NON_CRD_DOCUMENT omission: %+v", res.Omissions)
	}
}
