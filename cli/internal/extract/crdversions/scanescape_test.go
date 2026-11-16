// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"reflect"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

const escPath = "charts/x/templates/t.yaml"

func utf16le(s string) string {
	u := utf16.Encode([]rune(s))
	b := []byte{0xFF, 0xFE}
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	return string(b)
}

func nest(levels int) string {
	return `\` + strings.Repeat("u005c", levels-1) + "u0043"
}

const cr = "CustomResourceDefinition"

// escapeFlagged: files that hide the kind and must be a blocking finding in
// the open tree.
var escapeFlagged = []struct {
	name, path, content, class, reason string
}{
	{"1 concat yaml", escPath, "apiVersion: apiextensions.k8s.io/v1\nkind: {{ \"CustomResource\" }}Definition\nmetadata:\n  name: x\n", ClassUnread, ReasonKindTemplated},
	{"1 concat tpl", "charts/x/templates/t.tpl", "apiVersion: apiextensions.k8s.io/v1\nkind: {{ \"CustomResource\" }}Definition\n", ClassUnread, ReasonKindTemplated},
	{"2 printf", escPath, "apiVersion: apiextensions.k8s.io/v1\nkind: {{ printf \"%s%s\" \"CustomResource\" \"Definition\" }}\n", ClassUnread, ReasonKindTemplated},
	{"2 cat", escPath, "apiVersion: apiextensions.k8s.io/v1\nkind: {{ cat \"CustomResource\" \"Definition\" | nospace }}\n", ClassUnread, ReasonKindTemplated},
	{"3 hex in action", escPath, "apiVersion: apiextensions.k8s.io/v1\nkind: {{ \"\\x43ustomResourceDefinition\" }}\n", ClassUnread, ReasonKindEscaped},
	{"3 unicode in action", escPath, "apiVersion: {{ .Values.api }}\nkind: {{ \"\\u0043ustomResourceDefinition\" }}\n", ClassUnread, ReasonKindEscaped},
	{"3 literal action", escPath, "apiVersion: apiextensions.k8s.io/v1\nkind: {{ \"CustomResourceDefinition\" }}\n", ClassUnread, ReasonTemplateUnread},
	{"4 yaml escape", escPath, "apiVersion: apiextensions.k8s.io/v1\nkind: \"\\u0043ustomResourceDefinition\"\nmetadata:\n  name: x\n", ClassUnread, ReasonKindEscaped},
	{"4 yaml hex", escPath, "kind: \"\\x43ustomResourceDefinition\"\n", ClassUnread, ReasonKindEscaped},
	{"4 json", "charts/x/crds/t.json", `{"kind":"\u0043ustomResourceDefinition","apiVersion":"apiextensions.k8s.io/v1"}`, ClassUnread, ReasonKindEscaped},
	{"4 continuation", escPath, "kind: \"CustomResource\\\n    Definition\"\n", ClassUnread, ReasonKindEscaped},
	{"4 utf16", escPath, utf16le("apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: x\n"), ClassUnread, ReasonKindEscaped},
	{"5 resources", escPath, "resources:\n- a.yaml\nkind: \"\\u0043ustomResourceDefinition\"\n", ClassUnread, ""},
	{"5 escaped key", escPath, "\"\\u006bind\": \"\\u0043ustomResourceDefinition\"\n", ClassUnread, ReasonKindEscaped},
	{"6 undecodable", escPath, "kind: \"\\u0043ustomResourceDefinition\"\nkind: x\n", ClassUnread, ReasonKindEscaped},
	{"6 word in comment", escPath, "# CustomResourceDefinition\nkind: \"\\u0043ustomResourceDefinition\"\nkind: x\n", ClassUnread, ReasonUndecodable},
	{"6 tag value", escPath, "kind: !!str \\u0043\nkind: x\n\\u0043ustomResourceDefinition: 1\n", ClassUnread, ReasonKindEscaped},
	{"7 b64dec literal api", escPath, "apiVersion: apiextensions.k8s.io/v1\nkind: {{ \"Q3VzdG9tUmVzb3VyY2VEZWZpbml0aW9u\" | b64dec }}\n", ClassUnread, ReasonKindTemplated},
	{"7 b64dec templated api", escPath, "apiVersion: {{ .Values.apiVersion }}\nkind: {{ \"Q3VzdG9t\" | b64dec }}\n", ClassUnread, ReasonKindTemplated},
	{"8 values kind", escPath, "apiVersion: {{ .Values.apiVersion }}\nkind: {{ .Values.kind }}\n", ClassUnread, ReasonKindTemplated},
	{"8 tld", escPath, "apiVersion: apiextensions.{{ .Values.tld }}/v1\nkind: {{ .Values.kind }}\n", ClassUnread, ReasonKindTemplated},
	{"9 next line", escPath, "apiVersion: apiextensions.k8s.io/v1\nkind:\n  {{ .Values.kind }}\n", ClassUnread, ReasonKindTemplated},
	{"9 block scalar", escPath, "apiVersion: apiextensions.k8s.io/v1\nkind: |\n  {{ .Values.kind }}\n", ClassUnread, ReasonKindTemplated},
	{"9 block scalar plain", escPath, "apiVersion: apiextensions.k8s.io/v1\nkind: >-\n  Deployment\n{{ if .x }}\n{{ end }}\n", ClassUnread, ReasonKindTemplated},
	{"10 embedded", escPath, "data: \"apiVersion: apiextensions.k8s.io/v1\\nkind: \\\\u0043ustomResourceDefinition\\n\"\n", ClassUnread, ReasonKindEscaped},
	{"11 fixpoint", escPath, "kind: \"" + nest(9) + "\"\n", ClassUnread, ReasonKindEscaped},
	{"source escape", "charts/x/templates/t.jsonnet", "{ kind: \"\\u0043ustomResourceDefinition\" }\n", ClassUnsupported, ReasonSourceTemplate},
	{"source literal", "charts/x/templates/t.jsonnet", "{ kind: \"CustomResourceDefinition\" }\n", ClassUnsupported, ReasonSourceTemplate},
}

func TestEscapedKindFlagged(t *testing.T) {
	for _, c := range escapeFlagged {
		t.Run(c.name, func(t *testing.T) {
			p, proof, f := quietPair(t, c.path, c.content)
			if f == nil || f.Class != c.class || (c.reason != "" && f.Reason != c.reason) || !f.blocks() {
				t.Fatalf("finding %+v", f)
			}
			if proof.Completeness.Attestable || p.Status == extract.PairDerived && proof.Completeness.Attestable {
				t.Fatalf("attestable: %+v", proof.Completeness)
			}
		})
	}
}

// escapeClean: files that name no kind, or only name the API group, and
// must stay not found.
var escapeClean = []struct{ name, path, content string }{
	{"14 rbac", escPath, "apiVersion: rbac.authorization.k8s.io/v1\nkind: {{ include \"x.rbacKind\" . }}\nrules:\n- apiGroups: [\"apiextensions.k8s.io\"]\n  resources: [\"customresourcedefinitions\"]\n  verbs: [\"get\"]\n"},
	{"15 apps", escPath, "apiVersion: apps/v1\nkind: {{ .Values.controller.kind }}\n"},
	{"15 apps templated version", escPath, "apiVersion: apps/{{ .Values.v }}\nkind: {{ .Values.controller.kind }}\n"},
	{"16 webhook", escPath, "apiVersion: admissionregistration.k8s.io/v1\nkind: ValidatingWebhookConfiguration\nwebhooks:\n- rules:\n  - apiGroups: [\"apiextensions.k8s.io\"]\n    apiVersions: [\"v1\"]\n    resources: [\"customresourcedefinitions\"]\n  name: {{ .Values.n }}\n"},
	{"17 templated apiVersion", escPath, "apiVersion: {{ include \"capabilities.deployment.apiVersion\" . }}\nkind: Deployment\n"},
	{"18 regex strings decodable", escPath, "pattern: \"^\\\\d+\\\\.\\\\w$\"\npath: 'C:\\Windows\\x'\ntext: \"a\\nb\"\n"},
	{"18 regex strings undecodable", escPath, "pattern: \"^\\\\d+\"\npattern: \"\\n\"\npath: C:\\Windows\n"},
	{"19 description only", escPath, "description: \"the \\u0043ustomResourceDefinition kind is not defined here\"\n"},
	{"20 schema", escPath, "properties:\n  kind:\n    type: string\n  name: {{ .Values.n }}\n"},
	{"plain no escapes", escPath, "kind: Deployment\napiVersion: apps/v1\n"},
}

func TestEscapedKindNotFlagged(t *testing.T) {
	for _, c := range escapeClean {
		t.Run(c.name, func(t *testing.T) {
			p, proof, f := quietPair(t, c.path, c.content)
			if f != nil || !proof.Completeness.Attestable || p.Status != extract.PairDerived {
				t.Fatalf("finding %+v, pair %s %q %+v", f, p.Status, p.Reason, proof.Completeness)
			}
		})
	}
}

// Under every location the new findings keep the effects of a finding of
// their class.
func TestEscapedKindLocations(t *testing.T) {
	for _, c := range escapeFlagged {
		if !strings.HasPrefix(c.name, "1 concat yaml") && !strings.HasPrefix(c.name, "4 yaml escape") && !strings.HasPrefix(c.name, "8 values") {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			// Default-excluded directory: blocks attestation, never withholds.
			p, proof, f := quietPair(t, "test/"+c.path, c.content)
			if f == nil || f.Location != "default: test" || !f.blocks() || f.unreadable() || proof.Completeness.Attestable || p.Status != extract.PairDerived {
				t.Fatalf("default: %+v %s %+v", f, p.Status, proof.Completeness)
			}
			// Reviewed exclusion: recorded as excluded-unread.
			ex := Exclusion{Path: "charts/x/templates/", Reason: "chart templates", Evidence: "reviewed: they render workloads"}
			p, proof, f = quietPair(t, c.path, c.content, ex)
			if f == nil || f.Class != ClassExcludedUnread || f.blocks() || p.Status != extract.PairDerived {
				t.Fatalf("reviewed: %+v %s", f, p.Status)
			}
			// Declared copies: blocks and withholds.
			cp := Exclusion{Path: "charts/x/templates/", Reason: "chart templates", Evidence: "reviewed", Copies: true}
			p, proof, f = quietPair(t, c.path, c.content, cp)
			if f == nil || !f.unreadable() || p.Status != extract.PairDerived {
				t.Fatalf("copies: %+v %s %q", f, p.Status, p.Reason)
			}
			// Defines-none entry: the blocking class is kept.
			dn := definesNone("charts/x/templates/")
			dn.Repo = "github.com/argoproj/argo-cd"
			_, proof, f = quietPair(t, c.path, c.content, dn)
			if f == nil || !f.blocks() || f.Class == ClassNoDefinition || proof.Completeness.Attestable {
				t.Fatalf("defines none: %+v %+v", f, proof.Completeness)
			}
		})
	}
}

// End to end: a file added at the later tag blocks the pair; a definition
// that moved into such a file is not reported removed.
func TestEscapedKindPair(t *testing.T) {
	alpha := crd("Alpha", "v1")
	hidden := "apiVersion: apiextensions.k8s.io/v1\nkind: {{ \"CustomResource\" }}Definition\nmetadata:\n  name: alphas." + synthGroup + "\n"
	s := newSynth(release{"v1.0.0", map[string]string{"deploy/crds/a.yaml": alpha}}, release{"v1.1.0", map[string]string{"deploy/crds/a.yaml": alpha, escPath: hidden}})
	p, proof := pairOf(t, runSynth(t, synthTarget(), s), "1.0.0", "1.1.0")
	if proof.Completeness.Attestable || p.Status != extract.PairWithheld && p.Status != extract.PairDerived {
		t.Fatalf("%s %+v", p.Status, proof.Completeness)
	}
	if f := findingOf(proof.To.Scan, escPath); f == nil || f.Reason != ReasonKindTemplated {
		t.Fatalf("finding %+v", f)
	}
	if proof.To.Scan.Clean() {
		t.Fatal("scan is clean")
	}
	// A pair with a rule is withheld while the file is unread.
	p, proof = classPair(t, crd("Alpha", "v1beta1", "v1"), crd("Alpha", "v1"), nil, map[string]string{escPath: hidden})
	if p.Status != extract.PairWithheld || !strings.Contains(p.Reason, escPath+" is unread") {
		t.Fatalf("with a rule: %s %q", p.Status, p.Reason)
	}
	// Moved: the definition leaves the listed path for the hidden file.
	s = newSynth(release{"v1.0.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1beta1", "v1")}}, release{"v1.1.0", map[string]string{"deploy/crds/b.yaml": "kind: \"\\u0043ustomResourceDefinition\"\n"}})
	out := runSynth(t, synthTarget(), s)
	for _, e := range out.Entries {
		if strings.Contains(e.Rule.ID, "removed") {
			t.Fatalf("removal emitted: %+v", e.Rule.ID)
		}
	}
}

// What N is.
func TestNormalizeEscapes(t *testing.T) {
	for in, want := range map[string]string{
		`plain`:                `plain`,
		`\u0043\x44\U00000045`: `CDE`,
		"a\\\n   b":            `ab`,
		`\u005cu0043`:          `C`,
		`\\u0043`:              `\C`,
		`\d\n\w`:               `\d\n\w`,
	} {
		got, ok := normalizeEscapes([]byte(in))
		if !ok || string(got) != want {
			t.Errorf("%q: %q %v", in, got, ok)
		}
	}
	if _, ok := normalizeEscapes([]byte(nest(9))); ok {
		t.Error("9 rounds are determined")
	}
	if _, ok := normalizeEscapes([]byte(nest(8))); !ok {
		t.Error("8 rounds are undetermined")
	}
	if g, ok := normalizeEscapes([]byte(utf16le("kind: " + cr))); !ok || string(g) != "kind: "+cr {
		t.Errorf("utf16 %q %v", g, ok)
	}
}

// Differential: over every file the corpus holds, the new classification
// only adds findings, and the added ones carry the new reasons.
func TestEscapeDifferential(t *testing.T) {
	x := New(synthTarget())
	var files []string
	for _, c := range escapeFlagged {
		files = append(files, c.content)
	}
	for _, c := range escapeClean {
		files = append(files, c.content)
	}
	files = append(files, crd("Alpha", "v1"), "resources:\n- a.yaml\n", "dependencies:\n- name: a\n  repository: https://x.example\n", "# CustomResourceDefinition\n")
	for i, c := range files {
		for _, kind := range []int{kindData, kindSource, kindNoDef} {
			info := summarize(kind, []byte(c))
			f := scanFile{path: escPath, kind: kind}
			if kind == kindSource {
				f.path = "charts/x/templates/t.tpl"
			}
			old, oldFound, err := x.classifyFound(nil, extract.RepoRef{}, "", f, info, nil, nil)
			if err != nil {
				continue
			}
			nw, nwFound, err := x.classifyFile(nil, extract.RepoRef{}, "", f, info, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if oldFound {
				if !nwFound || !reflect.DeepEqual(nw, old) {
					t.Errorf("file %d kind %d: found changed: %+v -> %+v", i, kind, old, nw)
				}
				continue
			}
			if nwFound && nw.Reason != ReasonKindEscaped && nw.Reason != ReasonKindTemplated && nw.Reason != ReasonSourceTemplate && nw.Reason != ReasonUndecodable {
				t.Errorf("file %d kind %d: added %+v", i, kind, nw)
			}
		}
	}
}

func FuzzEscapeRead(f *testing.F) {
	for _, c := range escapeFlagged {
		f.Add([]byte(c.content))
	}
	for _, c := range escapeClean {
		f.Add([]byte(c.content))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, kind := range []int{kindData, kindSource, kindNoDef} {
			info := summarize(kind, data)
			_ = info.esc.hits(true)
		}
	})
}

// definesNothing refuses what the decoded or the resolved text names.
func TestDefinesNothingEscaped(t *testing.T) {
	for name, c := range map[string]string{
		"escaped kind value":      "kind: \"\\u0043ustomResourceDefinition\"\nspec: {}\n",
		"embedded, escaped once":  "data: \"kind: \\\\u0043ustomResourceDefinition\"\n",
		"embedded, value in text": "data: \"{\\\"kind\\\": \\\"\\\\u0043ustomResourceDefinition\\\"}\"\n",
		"utf16":                   utf16le("kind: CustomResourceDefinition\nspec: {}\n"),
	} {
		if definesNothing([]byte(c)) == "" {
			t.Errorf("%s: accepted", name)
		}
	}
	if definesNothing([]byte("pattern: \"^\\\\d+\"\n")) != "" {
		t.Error("a regex string is refused")
	}
}
