// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/intake"
)

var crTestIndex = customresources.NewIndex([]customresources.Project{
	{Slug: "proj", Groups: []customresources.Group{{Name: "widgets.example.io"}}},
	{Slug: "other", Groups: []customresources.Group{{Name: "gadgets.example.io"}}},
})

var allCRCodes = []CRInstanceOmissionCode{
	CRScopeNotComplete, CRListPaginated, CRWrapperKind, CRDocumentUnparsed, CRDocumentNotPlaced, CRNotRendered,
	CRKindNotAttributed, CRDuplicateIdentity, CRKeyNotEncodable, CRShapeMismatch, CRInstanceCapExceeded,
	CRMemberOverflow, CRAllowlistRejected,
}

const wk = "widgets.example.io/Widget/"

func widget(name, spec string) string {
	return "apiVersion: widgets.example.io/v1\nkind: Widget\nmetadata:\n  name: " + name + "\n  namespace: ns\nspec:\n" + spec
}

func crDecode(t *testing.T, display string, raw string) intake.Workspace {
	t.Helper()
	ws, err := intake.Decode(display, []byte(raw))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return ws
}

func crCollect(t *testing.T, ws intake.Workspace, allow CRInstanceAllowlist, scope bool) map[string]CRInstanceFacts {
	t.Helper()
	out, err := collectCRInstanceFields(crTestIndex, ws, allow, scope)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func fieldsAllow(members ...string) CRInstanceAllowlist {
	return CRInstanceAllowlist{"proj": {Fields: members}}
}

func enumsAllow(members ...string) CRInstanceAllowlist {
	return CRInstanceAllowlist{"proj": {EnumValues: members}}
}

func codesOf(f CRInstanceFacts) []string {
	var out []string
	for _, o := range f.Omissions {
		out = append(out, string(o.Code))
	}
	return out
}

// assertProperty is the invariant every result must hold: any omission makes
// both sets incomplete and a result without omissions is complete.
func assertProperty(t *testing.T, f CRInstanceFacts) {
	t.Helper()
	want := len(f.Omissions) == 0
	if f.Fields.Complete != want || f.EnumValues.Complete != want {
		t.Fatalf("complete fields=%v enums=%v with omissions %v", f.Fields.Complete, f.EnumValues.Complete, codesOf(f))
	}
	for _, o := range f.Omissions {
		if o.Count <= 0 || CRInstanceOmissionText(o.Code) == "" {
			t.Fatalf("bad omission %+v", o)
		}
	}
	if !slices.IsSorted(f.Fields.Members) || !slices.IsSorted(f.EnumValues.Members) {
		t.Fatal("members not ascending")
	}
}

type crCase struct {
	name       string
	input      string
	display    string // default manifests.yaml
	allow      CRInstanceAllowlist
	incomplete bool // scope not declared complete
	fields     []string
	enums      []string
	codes      []string // exact omission codes, sorted; nil = complete
}

func crCorpus() []crCase {
	rep := wk + "spec/replicas"
	return []crCase{
		{name: "present", input: widget("a", "  replicas: 3\n"), allow: fieldsAllow(rep), fields: []string{rep}},
		{name: "absent", input: widget("a", "  other: 3\n"), allow: fieldsAllow(rep)},
		{name: "null value counts present", input: widget("a", "  replicas:\n"), allow: fieldsAllow(rep), fields: []string{rep}},
		{name: "empty list key counts present", input: widget("a", "  replicas: []\n"), allow: fieldsAllow(rep), fields: []string{rep}},
		{name: "terminal item on empty list", input: widget("a", "  list: []\n"), allow: fieldsAllow(wk + "spec/list/_item_"), fields: []string{wk + "spec/list/_item_"}},
		{name: "terminal any on empty map", input: widget("a", "  m: {}\n"), allow: fieldsAllow(wk + "spec/m/_any_"), fields: []string{wk + "spec/m/_any_"}},
		{name: "item path", input: widget("a", "  list:\n  - x: 1\n  - name: n\n"), allow: fieldsAllow(wk+"spec/list/_item_/name", wk+"spec/list/_item_/zzz"), fields: []string{wk + "spec/list/_item_/name"}},
		{name: "any path", input: widget("a", "  m:\n    k1: {x: 1}\n    k2: {y: 2}\n"), allow: fieldsAllow(wk+"spec/m/_any_/y", wk+"spec/m/_any_/q"), fields: []string{wk + "spec/m/_any_/y"}},
		{name: "any value key with dots and dashes is fine", input: widget("a", "  m:\n    a.b-c: {y: 2}\n"), allow: fieldsAllow(wk + "spec/m/_any_/y"), fields: []string{wk + "spec/m/_any_/y"}},
		{name: "second instance sets it", input: widget("a", "  x: 1\n") + "---\n" + widget("b", "  replicas: 1\n"), allow: fieldsAllow(rep), fields: []string{rep}},
		{name: "flow style", input: "{apiVersion: widgets.example.io/v1, kind: Widget, metadata: {name: a}, spec: {replicas: 2}}\n", allow: fieldsAllow(rep), fields: []string{rep}},
		{name: "json object", display: "m.json", input: `{"apiVersion":"widgets.example.io/v1","kind":"Widget","metadata":{"name":"a"},"spec":{"replicas":2}}`, allow: fieldsAllow(rep), fields: []string{rep}},
		{name: "json v1 list", display: "m.json", input: `{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"widgets.example.io/v1","kind":"Widget","metadata":{"name":"a"},"spec":{"replicas":2}}]}`, allow: fieldsAllow(rep), fields: []string{rep}},
		{name: "typed list items without apiVersion", input: "apiVersion: widgets.example.io/v1\nkind: WidgetList\nitems:\n- metadata:\n    name: a\n  spec:\n    replicas: 1\n", allow: fieldsAllow(rep), fields: []string{rep}},
		{name: "multi doc with empty and comment only", input: "---\n# nothing\n---\n" + widget("a", "  replicas: 1\n") + "---\n\n---\n", allow: fieldsAllow(rep), fields: []string{rep}},
		{name: "crlf", input: strings.ReplaceAll(widget("a", "  replicas: 1\n"), "\n", "\r\n"), allow: fieldsAllow(rep), fields: []string{rep}},
		{name: "no trailing newline", input: strings.TrimSuffix(widget("a", "  replicas: 1\n"), "\n"), allow: fieldsAllow(rep), fields: []string{rep}},
		{name: "apiVersion not consulted", input: strings.Replace(widget("a", "  replicas: 1\n"), "/v1\n", "/v1alpha1\n", 1), allow: fieldsAllow(rep), fields: []string{rep}},
		{name: "secret kind never read", input: "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\nspec:\n  replicas: 1\ndata:\n  k: dg==\n", allow: fieldsAllow(rep)},
		{name: "secret kind in a project group never read", input: "apiVersion: widgets.example.io/v1\nkind: Secret\nmetadata:\n  name: s\nspec:\n  replicas: 1\n", allow: fieldsAllow(rep)},
		{name: "secret member rejected", input: "apiVersion: widgets.example.io/v1\nkind: Secret\nmetadata:\n  name: s\nspec:\n  replicas: 1\n", allow: fieldsAllow(wk+"spec/replicas", "widgets.example.io/Secret/spec/replicas"), codes: []string{"CR_INSTANCE_ALLOWLIST_MEMBER_REJECTED"}},
		{name: "paginated list", input: "apiVersion: v1\nkind: List\nmetadata:\n  continue: abc\nitems:\n- apiVersion: widgets.example.io/v1\n  kind: Widget\n  metadata:\n    name: a\n  spec:\n    replicas: 1\n", allow: fieldsAllow(rep), fields: []string{rep}, codes: []string{"CR_INSTANCE_LIST_PAGINATED"}},
		{name: "status never retained", input: widget("a", "  other: 1\n") + "status:\n  replicas: 1\n", allow: fieldsAllow(rep)},
		{name: "status member rejected", input: widget("a", "  other: 1\n") + "status:\n  replicas: 1\n", allow: fieldsAllow(wk+"status/replicas", rep), codes: []string{"CR_INSTANCE_ALLOWLIST_MEMBER_REJECTED"}},
		{name: "metadata member rejected", input: widget("a", "  other: 1\n"), allow: fieldsAllow(wk + "metadata/labels"), codes: []string{"CR_INSTANCE_ALLOWLIST_MEMBER_REJECTED"}},
		{name: "kind of another project rejected", input: widget("a", "  other: 1\n"), allow: fieldsAllow("gadgets.example.io/Gadget/spec/x"), codes: []string{"CR_INSTANCE_ALLOWLIST_MEMBER_REJECTED"}},
		{name: "undecodable member rejected", input: widget("a", "  other: 1\n"), allow: fieldsAllow("not-a-member"), codes: []string{"CR_INSTANCE_ALLOWLIST_MEMBER_REJECTED"}},

		{name: "enum equal", input: widget("a", "  mode: Fast\n"), allow: enumsAllow(wk + "spec/mode/Fast"), enums: []string{wk + "spec/mode/Fast"}},
		{name: "enum differs is dropped", input: widget("a", "  mode: Slow\n"), allow: enumsAllow(wk + "spec/mode/Fast")},
		{name: "enum case sensitive", input: widget("a", "  mode: fast\n"), allow: enumsAllow(wk + "spec/mode/Fast")},
		{name: "enum quoted number", input: widget("a", "  level: \"1\"\n"), allow: enumsAllow(wk + "spec/level/1"), enums: []string{wk + "spec/level/1"}},
		{name: "enum unquoted number", input: widget("a", "  level: 1\n"), allow: enumsAllow(wk + "spec/level/1"), enums: []string{wk + "spec/level/1"}},
		{name: "enum bool", input: widget("a", "  on: true\n"), allow: enumsAllow(wk + "spec/on/true"), enums: []string{wk + "spec/on/true"}},
		{name: "enum null is nothing", input: widget("a", "  mode:\n"), allow: enumsAllow(wk + "spec/mode/Fast")},
		{name: "enum in list items", input: widget("a", "  modes:\n  - Slow\n  - Fast\n"), allow: enumsAllow(wk + "spec/modes/_item_/Fast"), enums: []string{wk + "spec/modes/_item_/Fast"}},
		{name: "enum on a map is a shape mismatch", input: widget("a", "  mode: {x: 1}\n"), allow: enumsAllow(wk + "spec/mode/Fast"), codes: []string{"CR_INSTANCE_SHAPE_MISMATCH"}},

		{name: "item on a map", input: widget("a", "  list: {x: 1}\n"), allow: fieldsAllow(wk + "spec/list/_item_/x"), codes: []string{"CR_INSTANCE_SHAPE_MISMATCH"}},
		{name: "any on an array", input: widget("a", "  m: [1]\n"), allow: fieldsAllow(wk + "spec/m/_any_/x"), codes: []string{"CR_INSTANCE_SHAPE_MISMATCH"}},
		{name: "prop on a scalar", input: widget("a", "  s: text\n"), allow: fieldsAllow(wk + "spec/s/x"), codes: []string{"CR_INSTANCE_SHAPE_MISMATCH"}},
		{name: "prop on an array", input: widget("a", "  s: [1]\n"), allow: fieldsAllow(wk + "spec/s/x"), codes: []string{"CR_INSTANCE_SHAPE_MISMATCH"}},
		{name: "item on a scalar", input: widget("a", "  s: 5\n"), allow: fieldsAllow(wk + "spec/s/_item_"), codes: []string{"CR_INSTANCE_SHAPE_MISMATCH"}},
		{name: "null intermediate is absent not a mismatch", input: widget("a", "  s:\n"), allow: fieldsAllow(wk + "spec/s/x")},

		{name: "key with slash beside path", input: widget("a", "  \"a/b\": 1\n  replicas: 1\n"), allow: fieldsAllow(rep), fields: []string{rep}, codes: []string{"CR_INSTANCE_KEY_NOT_ENCODABLE"}},
		{name: "reserved key beside path", input: widget("a", "  _item_: 1\n"), allow: fieldsAllow(rep), codes: []string{"CR_INSTANCE_KEY_NOT_ENCODABLE"}},
		{name: "charset key beside path", input: widget("a", "  \"a b\": 1\n"), allow: fieldsAllow(rep), codes: []string{"CR_INSTANCE_KEY_NOT_ENCODABLE"}},
		{name: "too long key beside path", input: widget("a", "  "+strings.Repeat("k", 130)+": 1\n"), allow: fieldsAllow(rep), codes: []string{"CR_INSTANCE_KEY_NOT_ENCODABLE"}},
		{name: "free form keys under any are not checked", input: widget("a", "  m:\n    \"a/b c\": {y: 1}\n"), allow: fieldsAllow(wk + "spec/m/_any_/y"), fields: []string{wk + "spec/m/_any_/y"}},
		{name: "unrelated top level keys are not checked", input: "apiVersion: widgets.example.io/v1\nkind: Widget\nmetadata:\n  name: a\n  labels:\n    \"a/b\": c\nspec:\n  replicas: 1\n", allow: fieldsAllow(rep), fields: []string{rep}},

		{name: "scope not declared", incomplete: true, input: widget("a", "  replicas: 1\n"), allow: fieldsAllow(rep), fields: []string{rep}, codes: []string{"CR_INSTANCE_SCOPE_NOT_DECLARED_COMPLETE"}},
		{name: "templated document", input: widget("a", "  replicas: 1\n") + "---\n" + widget("b", "  replicas: \"{{ .Values.n }}\"\n"), allow: fieldsAllow(rep), fields: []string{rep}, codes: []string{"CR_INSTANCE_DOCUMENT_UNPARSED"}},
		{name: "templated file that does not parse is unread", input: widget("a", "  replicas: 1\n") + "---\n" + widget("b", "  replicas: {{ .Values.n }}\n"), allow: fieldsAllow(rep), codes: []string{"CR_INSTANCE_DOCUMENT_UNPARSED"}},
		{name: "unparseable template file", input: "{{- if .Values.x }}\nspec: [\n{{- end }}\n", allow: fieldsAllow(rep), codes: []string{"CR_INSTANCE_DOCUMENT_UNPARSED"}},
		{name: "non kubernetes document", input: widget("a", "  replicas: 1\n") + "---\nfoo: bar\n", allow: fieldsAllow(rep), fields: []string{rep}, codes: []string{"CR_INSTANCE_DOCUMENT_NOT_PLACED"}},
		{name: "no document", input: "# only a comment\n", allow: fieldsAllow(rep), codes: []string{"CR_INSTANCE_DOCUMENT_NOT_PLACED"}},
		{name: "unattributed group", input: widget("a", "  other: 1\n") + "---\napiVersion: unknown.example.org/v1\nkind: Thing\nmetadata:\n  name: t\n", allow: fieldsAllow(rep), codes: []string{"CR_INSTANCE_KIND_NOT_ATTRIBUTED"}},
		{name: "kubernetes group skipped", input: widget("a", "  replicas: 1\n") + "---\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: d\nspec:\n  replicas: 1\n", allow: fieldsAllow(rep), fields: []string{rep}},
		{name: "duplicate identity", input: widget("a", "  replicas: 1\n") + "---\n" + widget("a", "  other: 1\n"), allow: fieldsAllow(rep), fields: []string{rep}, codes: []string{"CR_INSTANCE_DUPLICATE_IDENTITY"}},
		{name: "same name other namespace", input: widget("a", "  replicas: 1\n") + "---\n" + strings.Replace(widget("a", "  other: 1\n"), "namespace: ns", "namespace: ns2", 1), allow: fieldsAllow(rep), fields: []string{rep}},
		{name: "duplicate through a list", input: widget("a", "  other: 1\n") + "---\napiVersion: v1\nkind: List\nitems:\n- apiVersion: widgets.example.io/v1\n  kind: Widget\n  metadata:\n    name: a\n    namespace: ns\n  spec:\n    replicas: 1\n", allow: fieldsAllow(rep), fields: []string{rep}, codes: []string{"CR_INSTANCE_DUPLICATE_IDENTITY"}},
		{name: "kustomization file", display: "kustomization.yaml", input: "resources:\n- a.yaml\n", allow: fieldsAllow(rep), codes: []string{"CR_INSTANCE_DOCUMENT_NOT_PLACED", "CR_INSTANCE_KUSTOMIZE_OR_CHART_NOT_RENDERED"}},
		{name: "helm chart file", display: "Chart.yaml", input: "name: c\nversion: 1.0.0\n", allow: fieldsAllow(rep), codes: []string{"CR_INSTANCE_DOCUMENT_NOT_PLACED", "CR_INSTANCE_KUSTOMIZE_OR_CHART_NOT_RENDERED"}},
		{name: "nested list", input: widget("a", "  replicas: 1\n") + "---\napiVersion: v1\nkind: List\nitems:\n- apiVersion: v1\n  kind: List\n  items: []\n", allow: fieldsAllow(rep), fields: []string{rep}, codes: []string{"CR_INSTANCE_DOCUMENT_NOT_PLACED"}},
	}
}

func TestCRInstanceCorpus(t *testing.T) {
	for _, tc := range crCorpus() {
		t.Run(tc.name, func(t *testing.T) {
			display := tc.display
			if display == "" {
				display = "manifests.yaml"
			}
			got := crCollect(t, crDecode(t, display, tc.input), tc.allow, !tc.incomplete)["proj"]
			assertProperty(t, got)
			if !reflect.DeepEqual(append([]string{}, got.Fields.Members...), append([]string{}, tc.fields...)) {
				t.Fatalf("fields %v want %v", got.Fields.Members, tc.fields)
			}
			if !reflect.DeepEqual(append([]string{}, got.EnumValues.Members...), append([]string{}, tc.enums...)) {
				t.Fatalf("enums %v want %v", got.EnumValues.Members, tc.enums)
			}
			if !reflect.DeepEqual(codesOf(got), tc.codes) {
				t.Fatalf("codes %v want %v", codesOf(got), tc.codes)
			}
		})
	}
}

func TestCRInstanceNonMemberEnumValuesCounted(t *testing.T) {
	got := crCollect(t, crDecode(t, "m.yaml", widget("a", "  mode: Slow\n")+"---\n"+widget("b", "  mode: Other\n")), enumsAllow(wk+"spec/mode/Fast"), true)["proj"]
	if got.NonMemberEnumValues != 2 || len(got.EnumValues.Members) != 0 || !got.EnumValues.Complete {
		t.Fatalf("%+v", got)
	}
}

// Every wrapper kind makes every project's sets incomplete, a document of the
// project itself or not.
func TestCRInstanceWrapperKindsIncompleteForEveryProject(t *testing.T) {
	allow := CRInstanceAllowlist{"proj": {Fields: []string{wk + "spec/replicas"}}, "other": {Fields: []string{"gadgets.example.io/Gadget/spec/x"}}}
	for _, w := range CRInstanceWrapperKinds() {
		t.Run(w.Group+"/"+w.Kind, func(t *testing.T) {
			raw := widget("a", "  replicas: 1\n") + "---\n" + fmt.Sprintf("apiVersion: %s/v1\nkind: %s\nmetadata:\n  name: w\nspec:\n  anything: 1\n", w.Group, w.Kind)
			out := crCollect(t, crDecode(t, "m.yaml", raw), allow, true)
			for project, facts := range out {
				assertProperty(t, facts)
				if facts.Fields.Complete || !slices.Contains(codesOf(facts), string(CRWrapperKind)) {
					t.Fatalf("%s: %+v", project, facts)
				}
			}
			if !slices.Equal(out["proj"].Fields.Members, []string{wk + "spec/replicas"}) {
				t.Fatalf("members of the project are still found: %+v", out["proj"])
			}
		})
	}
}

func TestCRInstanceWrapperListPinned(t *testing.T) {
	var got []string
	for _, w := range CRInstanceWrapperKinds() {
		got = append(got, w.Group+"/"+w.Kind)
	}
	want := []string{
		"helm.toolkit.fluxcd.io/HelmRelease", "kustomize.toolkit.fluxcd.io/Kustomization", "kustomize.config.k8s.io/Kustomization",
		"argoproj.io/Application", "argoproj.io/ApplicationSet", "apiextensions.crossplane.io/Composition", "kubernetes.crossplane.io/Object",
		"work.open-cluster-management.io/ManifestWork", "fleet.cattle.io/Bundle", "helm.cattle.io/HelmChart", "helm.cattle.io/HelmChartConfig",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("wrapper list changed (review it): %v", got)
	}
}

func TestCRInstanceInstanceCap(t *testing.T) {
	build := func(n int) string {
		var b strings.Builder
		b.WriteString("apiVersion: v1\nkind: List\nitems:\n")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "- apiVersion: widgets.example.io/v1\n  kind: Widget\n  metadata:\n    name: w%04d\n  spec:\n    replicas: 1\n", i)
		}
		return b.String()
	}
	rep := wk + "spec/replicas"
	at := crCollect(t, crDecode(t, "m.yaml", build(CRInstanceCap)), fieldsAllow(rep), true)["proj"]
	assertProperty(t, at)
	if !at.Fields.Complete {
		t.Fatalf("at the cap: %v", codesOf(at))
	}
	over := crCollect(t, crDecode(t, "m.yaml", build(CRInstanceCap+1)), fieldsAllow(rep), true)["proj"]
	assertProperty(t, over)
	if over.Fields.Complete || !slices.Equal(codesOf(over), []string{string(CRInstanceCapExceeded)}) || !slices.Equal(over.Fields.Members, []string{rep}) {
		t.Fatalf("over the cap: %+v", over)
	}
}

func TestCRInstanceMemberOverflowIsNotTruncated(t *testing.T) {
	var members []string
	var spec strings.Builder
	for i := 0; i < 257; i++ {
		members = append(members, fmt.Sprintf("%sspec/f%03d", wk, i))
		fmt.Fprintf(&spec, "  f%03d: 1\n", i)
	}
	got := crCollect(t, crDecode(t, "m.yaml", widget("a", spec.String())), fieldsAllow(members...), true)["proj"]
	assertProperty(t, got)
	if len(got.Fields.Members) != 257 || got.Fields.Complete || !slices.Equal(codesOf(got), []string{string(CRMemberOverflow)}) {
		t.Fatalf("members=%d complete=%v codes=%v", len(got.Fields.Members), got.Fields.Complete, codesOf(got))
	}
	// 256 is the most a set may hold and is not an overflow.
	got = crCollect(t, crDecode(t, "m.yaml", widget("a", spec.String())), fieldsAllow(members[:256]...), true)["proj"]
	if len(got.Fields.Members) != 256 || !got.Fields.Complete {
		t.Fatalf("256 members: %v", codesOf(got))
	}
}

func TestCRInstanceAllowlistLimit(t *testing.T) {
	var members []string
	for i := 0; i <= crAllowlistLimit; i++ {
		members = append(members, fmt.Sprintf("%sspec/f%d", wk, i))
	}
	if _, err := collectCRInstanceFields(crTestIndex, intake.Workspace{}, fieldsAllow(members...), true); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err %v", err)
	}
}

func TestCRInstanceDeterministicUnderShuffle(t *testing.T) {
	docs := []string{
		widget("a", "  replicas: 1\n  list:\n  - name: x\n"),
		widget("b", "  mode: Fast\n"),
		widget("c", "  m:\n    k: {y: 1}\n"),
		widget("a", "  other: 1\n"),
		"apiVersion: unknown.example.org/v1\nkind: Thing\nmetadata:\n  name: t\n",
		"apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: d\nspec:\n  replicas: 1\n",
	}
	allow := CRInstanceAllowlist{"proj": {
		Fields:     []string{wk + "spec/replicas", wk + "spec/list/_item_/name", wk + "spec/m/_any_/y", wk + "spec/nope"},
		EnumValues: []string{wk + "spec/mode/Fast"},
	}}
	base := crCollect(t, crDecode(t, "m.yaml", strings.Join(docs, "---\n")), allow, true)
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 30; i++ {
		shuffled := slices.Clone(docs)
		rng.Shuffle(len(shuffled), func(a, b int) { shuffled[a], shuffled[b] = shuffled[b], shuffled[a] })
		got := crCollect(t, crDecode(t, "m.yaml", strings.Join(shuffled, "---\n")), allow, true)
		if !reflect.DeepEqual(base, got) {
			t.Fatalf("order changed the result:\n%+v\n%+v", base, got)
		}
	}
	if len(base["proj"].Fields.Members) != 3 || len(base["proj"].EnumValues.Members) != 1 {
		t.Fatalf("%+v", base["proj"])
	}
}

// No raw path, key, value, name, namespace or status content may reach any
// output, whatever the result.
func TestCRInstanceNeverRetainsRawContent(t *testing.T) {
	canaries := []string{"CANARYNAME", "CANARYNS", "CANARYLABEL", "CANARYANNOT", "CANARYVALUE", "CANARYKEY", "CANARYSTATUS", "CANARYSECRET", "CANARYENUM", "CANARYSLASH"}
	raw := `apiVersion: widgets.example.io/v1
kind: Widget
metadata:
  name: CANARYNAME
  namespace: CANARYNS
  labels:
    CANARYLABEL: CANARYLABEL
  annotations:
    CANARYANNOT: CANARYANNOT
spec:
  replicas: CANARYVALUE
  mode: CANARYENUM
  CANARYKEY: 1
  "CANARYSLASH/x": 1
  list: {CANARYKEY: 1}
  m:
    CANARYKEY: {y: 1}
status:
  CANARYSTATUS: CANARYSTATUS
---
apiVersion: widgets.example.io/v1
kind: Widget
metadata:
  name: CANARYNAME
  namespace: CANARYNS
spec: {}
---
apiVersion: v1
kind: Secret
metadata:
  name: CANARYSECRET
data:
  CANARYSECRET: Q0FOQVJZ
stringData:
  CANARYSECRET: CANARYSECRET
`
	allow := CRInstanceAllowlist{"proj": {
		Fields:     []string{wk + "spec/replicas", wk + "spec/list/_item_/x", wk + "spec/m/_any_/y", wk + "spec/gone"},
		EnumValues: []string{wk + "spec/mode/Fast", wk + "spec/replicas/1"},
	}}
	out := crCollect(t, crDecode(t, "m.yaml", raw), allow, false)
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, code := range allCRCodes {
		text += CRInstanceOmissionText(code) + string(code)
	}
	for _, canary := range canaries {
		if strings.Contains(text, canary) {
			t.Fatalf("output holds %q: %s", canary, data)
		}
	}
	facts := out["proj"]
	assertProperty(t, facts)
	if want := []string{"CR_INSTANCE_DUPLICATE_IDENTITY", "CR_INSTANCE_KEY_NOT_ENCODABLE", "CR_INSTANCE_SCOPE_NOT_DECLARED_COMPLETE", "CR_INSTANCE_SHAPE_MISMATCH"}; !slices.Equal(codesOf(facts), want) {
		t.Fatalf("codes %v want %v", codesOf(facts), want)
	}
	// Every member is an allowlist member.
	for _, m := range append(slices.Clone(facts.Fields.Members), facts.EnumValues.Members...) {
		if !slices.Contains(append(slices.Clone(allow["proj"].Fields), allow["proj"].EnumValues...), m) {
			t.Fatalf("member %q is not on the allowlist", m)
		}
	}
}

func TestCRInstanceEveryCodeHasFixedText(t *testing.T) {
	seen := map[string]bool{}
	for _, code := range allCRCodes {
		text := CRInstanceOmissionText(code)
		if text == "" || seen[text] {
			t.Fatalf("code %s: text %q", code, text)
		}
		seen[text] = true
		if strings.ContainsAny(text, "\"'`<>{}") {
			t.Fatalf("code %s: text quotes or interpolates: %q", code, text)
		}
	}
	if CRInstanceOmissionText("nope") != "" {
		t.Fatal("unknown code has text")
	}
	if !strings.Contains(CRInstanceOmissionText(CRDuplicateIdentity), "over-block") || !strings.Contains(CRInstanceOmissionText(CRDuplicateIdentity), "apiVersion is not consulted") {
		t.Fatal("the over-block cases are not named")
	}
}

func TestCRInstanceBytesFailClosed(t *testing.T) {
	good := widget("a", "  replicas: 1\n")
	json1 := `{"apiVersion":"widgets.example.io/v1","kind":"Widget","metadata":{"name":"a"},"spec":{"replicas":1}}`
	cases := []struct {
		name string
		raw  string
		ok   bool
	}{
		{"plain", good, true},
		{"json", json1, true},
		{"empty", "", false},
		{"anchor and alias", "apiVersion: widgets.example.io/v1\nkind: Widget\nmetadata: {name: a}\nspec: &x\n  replicas: 1\nstatus: *x\n", false},
		{"merge key", "apiVersion: widgets.example.io/v1\nkind: Widget\nmetadata: {name: a}\nspec:\n  <<: {replicas: 1}\n", false},
		{"duplicate key", "apiVersion: widgets.example.io/v1\nkind: Widget\nmetadata: {name: a}\nspec:\n  replicas: 1\n  replicas: 2\n", false},
		{"custom tag", "apiVersion: widgets.example.io/v1\nkind: Widget\nmetadata: {name: a}\nspec:\n  replicas: !custom 1\n", false},
		{"invalid utf8", "apiVersion: widgets.example.io/v1\nkind: Widget\nspec: {a: \xff}\n", false},
		{"json with byte order mark", "\ufeff" + json1, false},
		{"json with duplicate case folded keys", `{"apiVersion":"widgets.example.io/v1","kind":"Widget","spec":{"a":1,"A":2}}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := CollectCRInstanceFieldsBytes([]byte(tc.raw), CRInstanceAllowlist{}, true)
			if tc.ok {
				if err != nil || out == nil {
					t.Fatalf("err %v", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalid) || out != nil {
				t.Fatalf("err %v out %v", err, out)
			}
		})
	}
}

func TestCRInstanceBytesFindsMember(t *testing.T) {
	const member = "kafka.strimzi.io/Kafka/spec/kafka/replicas"
	raw := "apiVersion: kafka.strimzi.io/v1beta2\nkind: Kafka\nmetadata:\n  name: a\nspec:\n  kafka:\n    replicas: 3\n"
	out, err := CollectCRInstanceFieldsBytes([]byte(raw), CRInstanceAllowlist{"strimzi": {Fields: []string{member}}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := out["strimzi"]; !slices.Equal(got.Fields.Members, []string{member}) || !got.Fields.Complete {
		t.Fatalf("%+v", got)
	}
}
