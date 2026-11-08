// SPDX-License-Identifier: AGPL-3.0-only

package k8slifecycle

import (
	"context"
	"encoding/json"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"path"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

var (
	sha  = strings.Repeat("a", 40)
	repo = extract.RepoRef{Key: "github.com/kubernetes/kubernetes"}
)

type mem map[string]string

func (m mem) Read(_ extract.RepoRef, _, p string) ([]byte, error) {
	if d, ok := m[p]; ok {
		return []byte(d), nil
	}
	return nil, fmt.Errorf("%w: %s", extract.ErrNotFound, p)
}

func (m mem) List(_ extract.RepoRef, _, dir string) ([]extract.TreeEntry, error) {
	seen := map[string]bool{}
	var out []extract.TreeEntry
	for p := range m {
		rest, ok := strings.CutPrefix(p, dir+"/")
		if !ok {
			continue
		}
		first, _, nested := strings.Cut(rest, "/")
		if !nested {
			out = append(out, extract.TreeEntry{Mode: "100644", Type: "blob", Path: p})
		} else if !seen[first] {
			seen[first] = true
			out = append(out, extract.TreeEntry{Mode: "040000", Type: "tree", Path: dir + "/" + first})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: %s", extract.ErrNotFound, dir)
	}
	return out, nil
}

const apiDir = DefaultDir

func tgt() Target { return Target{Repo: repo, Dir: apiDir} }

func register(group string) string {
	return "package v1\n\nconst GroupName = " + strconv.Quote(group) + "\n"
}

// one version directory with the given types.go body (the package clause is
// added unless the body starts with one).
func tree(group, ver, body string) mem {
	if !strings.HasPrefix(body, "package ") && !strings.Contains(body, "\npackage ") {
		body = "package " + ver + "\n" + body
	}
	d := apiDir + "/" + group + "/" + ver
	return mem{d + "/types.go": body, d + "/register.go": strings.Replace(register(group), "package v1", "package "+ver, 1)}
}

func merge(ms ...mem) mem {
	out := mem{}
	for _, m := range ms {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

func runG(t *testing.T, m mem, g guards) *Result {
	t.Helper()
	r, err := scan(context.Background(), m, tgt(), sha, g)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func run(t *testing.T, m mem) *Result { return runG(t, m, defaultGuards()) }

func codes(r *Result) []string {
	out := []string{}
	for _, e := range r.Ledger {
		out = append(out, e.Code)
	}
	return out
}

func mark(lines ...string) string {
	return "// " + strings.Join(lines, "\n// ") + "\n\n"
}

const triple = "+k8s:prerelease-lifecycle-gen:introduced=1.8\n// +k8s:prerelease-lifecycle-gen:deprecated=1.19\n// +k8s:prerelease-lifecycle-gen:removed=1.22\n// +k8s:prerelease-lifecycle-gen:replacement=apps,v1,Deployment"

func TestMechanicalTriple(t *testing.T) {
	src := "// +genclient\n// " + triple + "\n\n// Deployment is old.\ntype Deployment struct{}\n"
	r := run(t, tree("apps", "v1beta1", src))
	want := []Lifecycle{{"apps", "v1beta1", "Deployment", "1.8", "1.19", "1.22", "apps,v1,Deployment", BasisMechanical}}
	if !r.Complete || len(r.Ledger) != 0 || !reflect.DeepEqual(r.Lifecycles, want) || !reflect.DeepEqual(r.MechanicalLifecycles(agreeWith(r)), want) {
		t.Fatalf("%+v", r)
	}
	if r.Attestable() {
		t.Fatal("source markers must never attest")
	}
}

func TestMarkersInDocBlockAndGroupedDecl(t *testing.T) {
	src := "type (\n\t// +k8s:prerelease-lifecycle-gen:introduced=1.2\n\t// +k8s:prerelease-lifecycle-gen:deprecated=1.5\n\t// +k8s:prerelease-lifecycle-gen:removed=1.8\n\tA struct{}\n)\n"
	r := run(t, tree("g.example", "v1alpha1", src))
	if len(r.MechanicalLifecycles(agreeWith(r))) != 1 {
		t.Fatalf("%+v", r)
	}
}

func TestPartialIsDraftNotMechanical(t *testing.T) {
	src := mark("+k8s:prerelease-lifecycle-gen:introduced=1.8") + "type A struct{}\n" +
		mark("+k8s:prerelease-lifecycle-gen:introduced=1.8", "+k8s:prerelease-lifecycle-gen:deprecated=1.9") + "type B struct{}\n"
	r := run(t, tree("apps", "v1beta1", src))
	if !r.Complete || len(r.Lifecycles) != 2 || len(r.MechanicalLifecycles(agreeWith(r))) != 0 {
		t.Fatalf("%+v", r)
	}
	for _, l := range r.Lifecycles {
		if l.Basis != BasisDraft {
			t.Fatalf("%+v", l)
		}
	}
}

func TestStableIntroducedOnlyIsFine(t *testing.T) {
	r := run(t, tree("apps", "v1", mark("+k8s:prerelease-lifecycle-gen:introduced=1.9")+"type A struct{}\n"))
	if !r.Complete || len(r.Lifecycles) != 1 || r.Lifecycles[0].Basis != BasisDraft {
		t.Fatalf("%+v", r)
	}
}

const fieldSrc = `type PodSpec struct {
	// Deprecated: use serviceAccountName instead.
	DeprecatedServiceAccount string ` + "`json:\"serviceAccount,omitempty\"`" + `
	// +k8s:deprecated=1.30
	Old string ` + "`json:\"old\"`" + `
	// +k8s:removed
	Gone string ` + "`json:\"gone\"`" + `
	// This is not Deprecated: only a mention inside a paragraph.
	Fine string ` + "`json:\"fine\"`" + `
	// Deprecated: unexported is not API.
	hidden string
}
`

func TestFieldDeprecationsAreDraft(t *testing.T) {
	r := run(t, coreTree(fieldSrc))
	if !r.Complete || len(r.Deprecations) != 3 {
		t.Fatalf("%+v", r)
	}
	got := []string{}
	for _, d := range r.Deprecations {
		got = append(got, d.Field+":"+d.Source+":"+d.Member)
		if d.Basis != BasisDraft || !d.NeedsReview {
			t.Fatalf("%+v", d)
		}
	}
	want := []string{"gone:k8s:removed:core/PodSpec/gone", "old:k8s:deprecated:core/PodSpec/old", "serviceAccount:doc:core/PodSpec/serviceAccount"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
}

// TestNeverMechanical: no deprecation can be mechanical, whatever the markers
// say, and a deprecation never shows up among the mechanical lifecycles.
func TestNeverMechanical(t *testing.T) {
	src := "package v1beta1\n\n// " + triple + "\n\n// +k8s:deprecated=1.2\n// +k8s:removed\ntype X struct {\n\t// Deprecated: x\n\t// +k8s:removed=1.30\n\tF string `json:\"f\"`\n}\n"
	r := run(t, tree("apps", "v1beta1", src))
	if len(r.Deprecations) != 4 || len(r.MechanicalLifecycles(agreeWith(r))) != 1 {
		t.Fatalf("%+v", r)
	}
	for _, d := range r.Deprecations {
		if d.Basis != BasisDraft || !d.NeedsReview {
			t.Fatalf("%+v", d)
		}
	}
	b, _ := json.Marshal(r.MechanicalLifecycles(agreeWith(r)))
	if strings.Contains(string(b), "Deprecated") && strings.Contains(string(b), "doc") {
		t.Fatal("deprecation leaked into lifecycles")
	}
}

type negCase struct {
	code string
	m    mem
	off  func(*guards)
}

func neg() map[string]negCase {
	ver := func(v, body string) mem { return tree("apps", v, body) }
	gen := "// Code generated by x. DO NOT EDIT.\n\npackage v1beta1\n\n" + mark(triple) + "type A struct{}\n"
	return map[string]negCase{
		"conflicting_markers":           {ReasonMarkerConflict, ver("v1beta1", mark("+k8s:prerelease-lifecycle-gen:introduced=1.8", "+k8s:prerelease-lifecycle-gen:introduced=1.9")+"type A struct{}\n"), func(g *guards) { g.conflict = false }},
		"duplicate_same_value":          {ReasonMarkerConflict, ver("v1beta1", mark("+k8s:prerelease-lifecycle-gen:introduced=1.8", "+k8s:prerelease-lifecycle-gen:deprecated=1.9", "+k8s:prerelease-lifecycle-gen:deprecated=1.9")+"type A struct{}\n"), func(g *guards) { g.conflict = false }},
		"removed_without_deprecated":    {ReasonMarkerConflict, ver("v1beta1", mark("+k8s:prerelease-lifecycle-gen:introduced=1.8", "+k8s:prerelease-lifecycle-gen:removed=1.12")+"type A struct{}\n"), func(g *guards) { g.conflict = false }},
		"deprecated_without_introduced": {ReasonMarkerConflict, ver("v1beta1", mark("+k8s:prerelease-lifecycle-gen:deprecated=1.9")+"type A struct{}\n"), func(g *guards) { g.conflict = false }},
		"removed_before_deprecated":     {ReasonOrder, ver("v1beta1", mark("+k8s:prerelease-lifecycle-gen:introduced=1.8", "+k8s:prerelease-lifecycle-gen:deprecated=1.22", "+k8s:prerelease-lifecycle-gen:removed=1.19")+"type A struct{}\n"), func(g *guards) { g.order = false }},
		"removed_equals_deprecated":     {ReasonOrder, ver("v1beta1", mark("+k8s:prerelease-lifecycle-gen:introduced=1.8", "+k8s:prerelease-lifecycle-gen:deprecated=1.19", "+k8s:prerelease-lifecycle-gen:removed=1.19")+"type A struct{}\n"), func(g *guards) { g.order = false }},
		"deprecated_before_introduced":  {ReasonOrder, ver("v1beta1", mark("+k8s:prerelease-lifecycle-gen:introduced=1.20", "+k8s:prerelease-lifecycle-gen:deprecated=1.19")+"type A struct{}\n"), func(g *guards) { g.order = false }},
		"stable_version_removal":        {ReasonVersionSkew, ver("v1", mark(triple)+"type A struct{}\n"), func(g *guards) { g.skew = false }},
		"package_is_not_version":        {ReasonVersionSkew, tree("apps", "v1beta1", "package v1beta2\n\n"+mark(triple)+"type A struct{}\n"), func(g *guards) { g.skew = false }},
		"malformed_minor_text":          {ReasonMarkerBad, ver("v1beta1", mark("+k8s:prerelease-lifecycle-gen:introduced=1.x")+"type A struct{}\n"), func(g *guards) { g.malformed = false }},
		"malformed_v_prefix":            {ReasonMarkerBad, ver("v1beta1", mark("+k8s:prerelease-lifecycle-gen:introduced=v1.8")+"type A struct{}\n"), func(g *guards) { g.malformed = false }},
		"malformed_patch":               {ReasonMarkerBad, ver("v1beta1", mark("+k8s:prerelease-lifecycle-gen:introduced=1.8.0")+"type A struct{}\n"), func(g *guards) { g.malformed = false }},
		"malformed_leading_zero":        {ReasonMarkerBad, ver("v1beta1", mark("+k8s:prerelease-lifecycle-gen:introduced=1.08")+"type A struct{}\n"), func(g *guards) { g.malformed = false }},
		"malformed_other_major":         {ReasonMarkerBad, ver("v1beta1", mark("+k8s:prerelease-lifecycle-gen:introduced=2.1")+"type A struct{}\n"), func(g *guards) { g.malformed = false }},
		"malformed_overflow":            {ReasonMarkerBad, ver("v1beta1", mark("+k8s:prerelease-lifecycle-gen:introduced=1.99999999999999999999")+"type A struct{}\n"), func(g *guards) { g.malformed = false }},
		"malformed_empty_value":         {ReasonMarkerBad, ver("v1beta1", mark("+k8s:prerelease-lifecycle-gen:introduced=")+"type A struct{}\n"), func(g *guards) { g.malformed = false }},
		"malformed_no_equals":           {ReasonMarkerBad, ver("v1beta1", mark("+k8s:prerelease-lifecycle-gen:introduced")+"type A struct{}\n"), func(g *guards) { g.malformed = false }},
		"malformed_replacement":         {ReasonMarkerBad, ver("v1beta1", mark("+k8s:prerelease-lifecycle-gen:introduced=1.8", "+k8s:prerelease-lifecycle-gen:replacement=not a gvk")+"type A struct{}\n"), func(g *guards) { g.malformed = false }},
		"malformed_gen_bool":            {ReasonMarkerBad, ver("v1beta1", mark("+k8s:prerelease-lifecycle-gen=maybe")+"type A struct{}\n"), func(g *guards) { g.malformed = false }},
		"unknown_lifecycle_marker":      {ReasonMarkerUnknown, ver("v1beta1", mark("+k8s:prerelease-lifecycle-gen:retired=1.8")+"type A struct{}\n"), func(g *guards) { g.unknown = false }},
		"unknown_deprecated_variant":    {ReasonMarkerUnknown, ver("v1beta1", mark("+k8s:deprecatedBy=1.8")+"type A struct{}\n"), func(g *guards) { g.unknown = false }},
		"block_comment_marker":          {ReasonMarkerUnknown, ver("v1beta1", "/* +k8s:prerelease-lifecycle-gen:removed=1.9 */\ntype A struct{}\n"), func(g *guards) { g.unknown = false }},
		"generated_file":                {ReasonGenerated, ver("v1beta1", gen), func(g *guards) { g.generated = false }},
		"build_constraint":              {ReasonBuildConstr, ver("v1beta1", "//go:build linux\n\npackage v1beta1\n\n"+mark(triple)+"type A struct{}\n"), func(g *guards) { g.constraint = false }},
		"duplicate_type":                {ReasonDuplicateType, ver("v1beta1", mark(triple)+"type A struct{}\ntype A struct{}\n"), func(g *guards) { g.dup = false }},
		"group_missing":                 {ReasonGroupUnknown, mem{apiDir + "/apps/v1beta1/types.go": "package v1beta1\n\n" + mark(triple) + "type A struct{}\n"}, func(g *guards) { g.group = false }},
		"group_not_literal":             {ReasonGroupUnknown, mem{apiDir + "/apps/v1beta1/types.go": "package v1beta1\n\n" + mark(triple) + "type A struct{}\n", apiDir + "/apps/v1beta1/register.go": "package v1beta1\nconst GroupName = prefix + \"x\"\n"}, func(g *guards) { g.group = false }},
		"group_literal_bad_charset":     {ReasonGroupUnknown, mem{apiDir + "/apps/v1beta1/types.go": "package v1beta1\n\n" + mark(triple) + "type A struct{}\n", apiDir + "/apps/v1beta1/register.go": "package v1beta1\nconst GroupName = \"Bad Group!\"\n"}, func(g *guards) { g.group = false }},
		"group_literal_slash":           {ReasonGroupUnknown, mem{apiDir + "/apps/v1beta1/types.go": "package v1beta1\n\n" + mark(triple) + "type A struct{}\n", apiDir + "/apps/v1beta1/register.go": "package v1beta1\nconst GroupName = \"a/b\"\n"}, func(g *guards) { g.group = false }},
		"gen_false_with_conflict":       {ReasonMarkerConflict, ver("v1beta1", mark("+k8s:prerelease-lifecycle-gen=false", "+k8s:prerelease-lifecycle-gen:introduced=1.8", "+k8s:prerelease-lifecycle-gen:removed=1.12")+"type A struct{}\n"), func(g *guards) { g.conflict = false; g.genOff = false }},
		"gen_false_with_order":          {ReasonOrder, ver("v1beta1", mark("+k8s:prerelease-lifecycle-gen=false", "+k8s:prerelease-lifecycle-gen:introduced=1.8", "+k8s:prerelease-lifecycle-gen:deprecated=1.22", "+k8s:prerelease-lifecycle-gen:removed=1.19")+"type A struct{}\n"), func(g *guards) { g.order = false; g.genOff = false }},
		"gen_false_with_garbage_number": {ReasonMarkerBad, ver("v1beta1", mark("+k8s:prerelease-lifecycle-gen=false", "+k8s:prerelease-lifecycle-gen:introduced=soon")+"type A struct{}\n"), func(g *guards) { g.malformed = false; g.genOff = false }},
		"stable_removed_only":           {ReasonVersionSkew, ver("v1", mark("+k8s:prerelease-lifecycle-gen:introduced=1.8", "+k8s:prerelease-lifecycle-gen:deprecated=1.19", "+k8s:prerelease-lifecycle-gen:removed=1.22")+"type A struct{}\n"), func(g *guards) { g.skew = false }},
		"types_missing":                 {ReasonTypesMissing, mem{apiDir + "/apps/v1beta1/register.go": register("apps")}, nil},
		"field_without_json_name":       {ReasonFieldName, ver("v1beta1", "type A struct {\n\t// Deprecated: x\n\tF string\n}\n"), func(g *guards) { g.field = false }},
		"field_marker_conflict":         {ReasonMarkerConflict, ver("v1beta1", "type A struct {\n\t// +k8s:deprecated=1.2\n\t// +k8s:deprecated=1.3\n\tF string `json:\"f\"`\n}\n"), func(g *guards) { g.conflict = false }},
		"parse_error":                   {ReasonParse, ver("v1beta1", "type A struct {\n"), nil},
		"member_refused":                {ReasonMember, ver("v1beta1", "type A struct {\n\t// Deprecated: x\n\tF string `json:\"a b\"`\n}\n"), nil},
	}
}

func TestNegativeFixtures(t *testing.T) {
	good := tree("batch", "v1beta1", mark(triple)+"type Good struct{}\n")
	for name, tc := range neg() {
		r := run(t, merge(good, tc.m))
		if len(r.Ledger) == 0 || r.Ledger[0].Code != tc.code && !contains(codes(r), tc.code) {
			t.Errorf("%s: want %s, got %v", name, tc.code, codes(r))
			continue
		}
		// Fail closed: one withheld item makes the whole result unusable
		// as mechanical evidence, even next to a clean sibling.
		if r.Complete || r.MechanicalLifecycles(agreeWith(r)) != nil || r.Attestable() {
			t.Errorf("%s: result usable despite ledger %v", name, codes(r))
		}
		for _, l := range r.Lifecycles {
			if l.Kind == "A" && l.Basis == BasisMechanical {
				t.Errorf("%s: withheld type emitted as mechanical", name)
			}
		}
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// Each guard is load-bearing: with it off, the negative stops being withheld.
func TestGuardsAreLoadBearing(t *testing.T) {
	n := 0
	for name, tc := range neg() {
		if tc.off == nil {
			continue
		}
		n++
		g := defaultGuards()
		tc.off(&g)
		r := runG(t, tc.m, g)
		if contains(codes(r), tc.code) {
			t.Errorf("%s: guard is not what withholds", name)
		}
	}
	if n < 25 {
		t.Fatalf("guard scenarios shrank: %d", n)
	}
}

func TestVetoGuard(t *testing.T) {
	m := neg()["conflicting_markers"].m
	if run(t, m).Complete {
		t.Fatal("ledger left result complete")
	}
	g := defaultGuards()
	g.ledger.veto = false
	if !runG(t, m, g).Complete {
		t.Fatal("veto guard inert")
	}
}

func TestEmptyTreeIsNotComplete(t *testing.T) {
	m := mem{apiDir + "/apps/README.md": "x"}
	r := run(t, m)
	if r.Complete || len(r.Lifecycles) != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestBadTargetAndSHA(t *testing.T) {
	for _, d := range []string{"", "/abs", "a/../b", "a\\b"} {
		if _, err := Scan(context.Background(), mem{}, Target{Repo: repo, Dir: d}, sha); err == nil {
			t.Errorf("dir %q accepted", d)
		}
	}
	if _, err := Scan(context.Background(), mem{}, Target{Dir: apiDir}, sha); err == nil {
		t.Error("empty repo accepted")
	}
	if _, err := Scan(context.Background(), mem{}, tgt(), "main"); err == nil {
		t.Error("non-SHA accepted")
	}
	if _, err := Scan(context.Background(), mem{}, tgt(), sha); err == nil {
		t.Error("missing tree must be an error")
	}
}

func TestDeterministicAndSorted(t *testing.T) {
	m := merge(
		tree("batch", "v1beta1", mark(triple)+"type Z struct{}\n"+mark(triple)+"type B struct{}\n"),
		tree("apps", "v1beta2", mark(triple)+"type A struct{}\n"),
		tree("apps", "v1beta1", mark(triple)+"type A struct{}\n"),
	)
	a, _ := json.Marshal(run(t, m))
	for i := 0; i < 5; i++ {
		b, _ := json.Marshal(run(t, m))
		if string(a) != string(b) {
			t.Fatal("output is not deterministic")
		}
	}
	r := run(t, m)
	var ids []string
	for _, l := range r.Lifecycles {
		ids = append(ids, l.Group+"/"+l.Version+"/"+l.Kind)
	}
	if !sort.StringsAreSorted(ids) || len(ids) != 4 {
		t.Fatalf("%v", ids)
	}
}

func TestLimitsAtAndOver(t *testing.T) {
	src := "package v1beta1\n\n" + mark(triple) + "type A struct{}\n"
	m := tree("apps", "v1beta1", src)
	at := defaultGuards()
	at.lim.fileBytes = len(src)
	if r := runG(t, m, at); !r.Complete {
		t.Fatalf("file at the limit withheld: %v", codes(r))
	}
	over := defaultGuards()
	over.lim.fileBytes = len(src) - 1
	if r := runG(t, m, over); r.Complete || !contains(codes(r), ReasonTooLarge) {
		t.Fatalf("file over the limit accepted: %v", codes(r))
	}
	over.limits = false
	if r := runG(t, m, over); !r.Complete {
		t.Fatal("limits guard inert")
	}

	multi := merge(
		tree("a", "v1beta1", mark(triple)+"type A struct{}\n"),
		tree("a", "v1beta2", mark(triple)+"type A struct{}\n"),
		tree("b", "v1beta1", mark(triple)+"type A struct{}\n"),
	)
	for _, tc := range []struct {
		name  string
		set   func(*limits, int)
		count int // the limit that is exactly reached
	}{
		{"versions", func(l *limits, n int) { l.versions = n }, 3},
		{"versionsPerGroup", func(l *limits, n int) { l.versionsPerGroup = n }, 2},
		{"groups", func(l *limits, n int) { l.groups = n }, 2},
		{"entries", func(l *limits, n int) { l.entries = n }, 3},
		{"markerLines", func(l *limits, n int) { l.markerLines = n }, 4},
	} {
		g := defaultGuards()
		tc.set(&g.lim, tc.count)
		if r := runG(t, multi, g); !r.Complete {
			t.Errorf("%s at limit withheld: %v", tc.name, codes(r))
		}
		tc.set(&g.lim, tc.count-1)
		if r := runG(t, multi, g); r.Complete || !contains(codes(r), ReasonTooMany) {
			t.Errorf("%s over limit accepted: %v", tc.name, codes(r))
		}
	}
}

func TestLedgerRules(t *testing.T) {
	g := defaultLedgerGuards()
	if got := ledgerOf([]LedgerEntry{{"B_CODE", "z"}, {"A_CODE", "y"}, {"A_CODE", "y"}}, g); len(got) != 2 || got[0].Code != "A_CODE" {
		t.Fatalf("%v", got)
	}
	for name, e := range map[string]LedgerEntry{
		"lowercase": {"lower_code", "x"}, "reserved": {"LEDGER_X", "x"}, "bad item": {"A_CODE", "has space"}, "empty item": {"A_CODE", ""},
		"long item": {"A_CODE", strings.Repeat("a", MaxLedgerItemLen+1)},
	} {
		if got := ledgerOf([]LedgerEntry{e}, g); len(got) != 1 || got[0].Code != LedgerInvalid {
			t.Errorf("%s: %v", name, got)
		}
	}
	atLimit := make([]LedgerEntry, MaxLedgerEntries)
	for i := range atLimit {
		atLimit[i] = LedgerEntry{"A_CODE", "i" + strconv.Itoa(i)}
	}
	if got := ledgerOf(atLimit, g); len(got) != MaxLedgerEntries {
		t.Fatalf("at limit: %d", len(got))
	}
	if got := ledgerOf(append(atLimit, LedgerEntry{"A_CODE", "extra"}), g); len(got) != 1 || got[0].Code != LedgerOverflow {
		t.Fatalf("over limit: %v", got)
	}
}

func TestLedgerCarriesNoSourceText(t *testing.T) {
	canary := "CANARYTEXT"
	m := tree("apps", "v1beta1", mark("+k8s:prerelease-lifecycle-gen:introduced=1.8", "+k8s:prerelease-lifecycle-gen:introduced="+canary)+"// "+canary+"\ntype A struct{}\n")
	b, _ := json.Marshal(run(t, m))
	if strings.Contains(string(b), canary) {
		t.Fatal("marker text reached the result")
	}
}

// Default-deny import guard: this package's own code may import only from a
// short reviewed list; no process, network, file system, reflection beyond
// struct tags, unsafe or type-checking packages.
func TestImportsDefaultDeny(t *testing.T) {
	allowed := map[string]bool{
		"context": true, "errors": true, "go/ast": true, "go/parser": true, "go/token": true, "path": true, "reflect": true,
		"regexp": true, "sort": true, "strconv": true, "strings": true, "embed": true, "io": true, "io/fs": true, "time": true,
		"github.com/prufyx/prufyx/cli/internal/extract":            true,
		"github.com/prufyx/prufyx/cli/internal/extract/membercode": true,
	}
	files, err := fs.Glob(own, "*.go")
	if err != nil || len(files) == 0 {
		t.Fatal("no embedded source")
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		data, _ := fs.ReadFile(own, f)
		af, err := parser.ParseFile(token.NewFileSet(), f, data, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range af.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			if !allowed[p] {
				t.Errorf("%s imports %s: not on the reviewed list", f, p)
			}
		}
	}
}

func TestSourceSetCoversEncoder(t *testing.T) {
	ents, err := fs.ReadDir(SourceSet().Files, ".")
	if err != nil {
		t.Fatal(err)
	}
	var own, enc bool
	for _, e := range ents {
		own = own || e.Name() == "k8slifecycle.go"
		enc = enc || e.Name() == "membercode_membercode.go"
	}
	if !own || !enc {
		t.Fatalf("source set incomplete: own=%v encoder=%v", own, enc)
	}
	if _, err := extract.CodeFiles(SourceSet()); err != nil {
		t.Fatal(err)
	}
	_ = path.Base
}

// Marker block placement: only the doc comment and the one column-one block
// ending exactly one blank line above attach to a type. Everything else
// attaches to nothing, and never to a neighbour.
func TestMarkerPlacement(t *testing.T) {
	m1 := mark("+k8s:prerelease-lifecycle-gen:introduced=1.8", "+k8s:prerelease-lifecycle-gen:deprecated=1.19", "+k8s:prerelease-lifecycle-gen:removed=1.22")
	block := strings.TrimSuffix(m1, "\n\n") // block without the blank line
	for name, tc := range map[string]struct {
		body string
		kind string // the only kind allowed to carry the lifecycle, "" for none
	}{
		"one blank line above":          {m1 + "type A struct{}\n", "A"},
		"doc comment directly above":    {block + "\ntype A struct{}\n", "A"},
		"block, blank, doc, type":       {m1 + "// A is a thing.\ntype A struct{}\n", "A"},
		"two blank lines above":         {m1 + "\ntype A struct{}\n", ""},
		"three blank lines above":       {m1 + "\n\ntype A struct{}\n", ""},
		"indented floating block":       {"func f() {\n\t" + strings.ReplaceAll(block, "\n", "\n\t") + "\n\n}\n\ntype A struct{}\n", ""},
		"unrelated floating comment":    {m1 + "// unrelated note\n\n\ntype A struct{}\n", ""},
		"block above a function":        {m1 + "func F() {}\n\ntype A struct{}\n", ""},
		"block above a variable":        {m1 + "var V = 1\n\ntype A struct{}\n", ""},
		"block above a constant group":  {m1 + "const (\n\tC = 1\n)\n\ntype A struct{}\n", ""},
		"block belongs to first type":   {m1 + "type A struct{}\n\ntype B struct{}\n", "A"},
		"block after type, before func": {"type A struct{}\n\n" + m1 + "func F() {}\n", ""},
	} {
		r := run(t, tree("apps", "v1beta1", tc.body))
		if len(r.Ledger) != 0 || !r.Complete {
			t.Errorf("%s: ledger %v", name, codes(r))
			continue
		}
		got := ""
		for _, l := range r.Lifecycles {
			if got != "" {
				t.Errorf("%s: more than one lifecycle", name)
			}
			got = l.Kind
		}
		if got != tc.kind {
			t.Errorf("%s: lifecycle on %q, want %q", name, got, tc.kind)
		}
	}
}

// A marker line trailing a declaration is not a block of its own: the lines
// below it become the next type's doc comment and, being a partial set, are
// withheld rather than attached to either type.
func TestTrailingMarkerSplitsAndWithholds(t *testing.T) {
	block := strings.TrimSuffix(mark("+k8s:prerelease-lifecycle-gen:introduced=1.8", "+k8s:prerelease-lifecycle-gen:deprecated=1.19", "+k8s:prerelease-lifecycle-gen:removed=1.22"), "\n\n")
	r := run(t, tree("apps", "v1beta1", "type A struct{} "+block+"\n\ntype B struct{}\n"))
	if r.Complete || r.MechanicalLifecycles(agreeWith(r)) != nil || len(r.Lifecycles) != 0 {
		t.Fatalf("%+v", r)
	}
}

const coreRegister = "package v1\n\nconst GroupName = \"\"\n"

func coreTree(body string) mem {
	d := apiDir + "/core/v1"
	return mem{d + "/types.go": "package v1\n\n" + body, d + "/register.go": coreRegister}
}

func TestCoreGroup(t *testing.T) {
	body := mark("+k8s:prerelease-lifecycle-gen:introduced=1.0") + "type Pod struct{}\n" + fieldSrc
	r := run(t, coreTree(body))
	if !r.Complete || len(r.Lifecycles) != 1 || r.Lifecycles[0].Group != "" || len(r.Deprecations) != 3 {
		t.Fatalf("%+v", r)
	}
	for _, d := range r.Deprecations {
		if d.Group != "" || !strings.HasPrefix(d.Member, "core/PodSpec/") {
			t.Fatalf("%+v", d)
		}
	}
}

func TestCoreReplacementForms(t *testing.T) {
	for _, repl := range []string{",v1,Pod", "core,v1,Pod"} { // kept verbatim after validation
		src := mark("+k8s:prerelease-lifecycle-gen:introduced=1.0", "+k8s:prerelease-lifecycle-gen:replacement="+repl) + "type Old struct{}\n"
		r := run(t, tree("apps", "v1beta1", src))
		if !r.Complete || len(r.Lifecycles) != 1 || r.Lifecycles[0].Replacement != repl {
			t.Errorf("%q: %+v", repl, r)
		}
	}
	for _, repl := range []string{",", ",v1", "core,,Pod", "Core,v1,Pod", ",v1,"} {
		src := mark("+k8s:prerelease-lifecycle-gen:introduced=1.0", "+k8s:prerelease-lifecycle-gen:replacement="+repl) + "type Old struct{}\n"
		if r := run(t, tree("apps", "v1beta1", src)); r.Complete || !contains(codes(r), ReasonMarkerBad) {
			t.Errorf("%q accepted: %+v", repl, r)
		}
	}
}

func TestGenFalseExcludesType(t *testing.T) {
	src := mark("+k8s:prerelease-lifecycle-gen=false", "+k8s:prerelease-lifecycle-gen:introduced=1.8", "+k8s:prerelease-lifecycle-gen:deprecated=1.19", "+k8s:prerelease-lifecycle-gen:removed=1.22") + "type A struct{}\n" +
		mark("+k8s:prerelease-lifecycle-gen=true", "+k8s:prerelease-lifecycle-gen:introduced=1.8") + "type B struct{}\n"
	r := run(t, tree("apps", "v1beta1", src))
	if !r.Complete || len(r.Lifecycles) != 1 || r.Lifecycles[0].Kind != "B" {
		t.Fatalf("%+v", r)
	}
	g := defaultGuards()
	g.genOff = false
	if r := runG(t, tree("apps", "v1beta1", src), g); len(r.Lifecycles) != 2 {
		t.Fatal("gen=false guard is not what excludes the type")
	}
	both := mark("+k8s:prerelease-lifecycle-gen=true", "+k8s:prerelease-lifecycle-gen=false", "+k8s:prerelease-lifecycle-gen:introduced=1.8") + "type A struct{}\n"
	if r := run(t, tree("apps", "v1beta1", both)); r.Complete || !contains(codes(r), ReasonMarkerConflict) {
		t.Fatalf("true and false together accepted: %+v", r)
	}
}

func TestTypesOutsideTypesGo(t *testing.T) {
	d := apiDir + "/apps/v1beta1/"
	base := tree("apps", "v1beta1", mark(triple)+"type A struct{}\n")
	for name, tc := range map[string]struct {
		file, body string
		withheld   bool
	}{
		"marked type in another file":   {"extra.go", "package v1beta1\n\n" + mark(triple) + "type B struct{}\n", true},
		"deprecated field elsewhere":    {"extra.go", "package v1beta1\n\ntype B struct {\n\t// Deprecated: x\n\tF string `json:\"f\"`\n}\n", true},
		"unparsable other file":         {"extra.go", "package v1beta1\n\ntype B struct {\n", true},
		"other file of another package": {"extra.go", "package other\n\ntype B struct{}\n", true},
		"unmarked type is harmless":     {"extra.go", "package v1beta1\n\ntype B struct{}\n", false},
		"generated name is skipped":     {"zz_generated.deepcopy.go", "package v1beta1\n\n" + mark(triple) + "type B struct{}\n", false},
		"test file is skipped":          {"extra_test.go", "package v1beta1\n\n" + mark(triple) + "type B struct{}\n", false},
	} {
		m := merge(base, mem{d + tc.file: tc.body})
		r := run(t, m)
		if tc.withheld != (!r.Complete && contains(codes(r), ReasonTypesOutside)) || tc.withheld == r.Complete {
			t.Errorf("%s: complete=%v ledger=%v", name, r.Complete, codes(r))
		}
		if tc.withheld && r.MechanicalLifecycles(agreeWith(r)) != nil {
			t.Errorf("%s: mechanical lifecycles despite withheld version", name)
		}
	}
	m := merge(base, mem{d + "extra.go": "package v1beta1\n\n" + mark(triple) + "type B struct{}\n"})
	g := defaultGuards()
	g.outside = false
	if !runG(t, m, g).Complete {
		t.Fatal("outside guard is not what withholds")
	}
}

func TestTotalBytesAndVersionFilesAtOver(t *testing.T) {
	m := merge(tree("a", "v1beta1", mark(triple)+"type A struct{}\n"), tree("b", "v1beta1", mark(triple)+"type A struct{}\n"))
	sum := 0
	for _, v := range m {
		sum += len(v)
	}
	g := defaultGuards()
	g.lim.totalBytes = sum
	if r := runG(t, m, g); !r.Complete {
		t.Fatalf("total at the cap withheld: %v", codes(r))
	}
	g.lim.totalBytes = sum - 1
	r := runG(t, m, g)
	if r.Complete || !contains(codes(r), ReasonTooLarge) || r.MechanicalLifecycles(agreeWith(r)) != nil {
		t.Fatalf("total over the cap accepted: %v", codes(r))
	}
	g.limits = false
	if !runG(t, m, g).Complete {
		t.Fatal("limits guard inert for the total cap")
	}

	d := apiDir + "/a/v1beta1/"
	files := merge(tree("a", "v1beta1", mark(triple)+"type A struct{}\n"), mem{d + "x1.go": "package v1beta1\n", d + "x2.go": "package v1beta1\n"})
	g = defaultGuards()
	g.lim.versionFiles = 2
	if r := runG(t, files, g); !r.Complete {
		t.Fatalf("files at the cap withheld: %v", codes(r))
	}
	g.lim.versionFiles = 1
	if r := runG(t, files, g); r.Complete || !contains(codes(r), ReasonTooMany) {
		t.Fatalf("files over the cap accepted: %v", codes(r))
	}
}

// agreeWith is the most permissive cross-check source: it agrees with every
// lifecycle of the result. Tests of the gating itself use it so that only the
// result's own state decides.
func agreeWith(r *Result) func(group, version, kind string) (string, bool) {
	return func(g, v, k string) (string, bool) {
		for _, l := range r.Lifecycles {
			if l.Group == g && l.Version == v && l.Kind == k {
				return l.Removed, true
			}
		}
		return "", false
	}
}

// The real core/v1 layout: ComponentStatus is introduced 1.0 and deprecated
// 1.19 on a stable version, which upstream allows. It must not withhold the
// run.
func TestStableDeprecatedIsLegal(t *testing.T) {
	body := mark("+k8s:prerelease-lifecycle-gen:introduced=1.0", "+k8s:prerelease-lifecycle-gen:deprecated=1.19") + "// ComponentStatus is deprecated.\ntype ComponentStatus struct{}\n\n" +
		mark("+k8s:prerelease-lifecycle-gen:introduced=1.0", "+k8s:prerelease-lifecycle-gen:deprecated=1.19") + "type ComponentStatusList struct{}\n\n" +
		mark("+k8s:prerelease-lifecycle-gen:introduced=1.0") + "type Pod struct{}\n"
	r := run(t, coreTree(body))
	if !r.Complete || len(r.Ledger) != 0 || len(r.Lifecycles) != 3 {
		t.Fatalf("%+v", r)
	}
	for _, l := range r.Lifecycles {
		if l.Group != "" || l.Version != "v1" || l.Basis != BasisDraft {
			t.Fatalf("%+v", l)
		}
	}
	if r.Lifecycles[0].Kind != "ComponentStatus" || r.Lifecycles[0].Deprecated != "1.19" || r.Lifecycles[0].Removed != "" {
		t.Fatalf("%+v", r.Lifecycles[0])
	}
}

func TestMechanicalNeedsCrossCheck(t *testing.T) {
	two := merge(tree("apps", "v1beta1", mark(triple)+"type A struct{}\n"), tree("batch", "v1beta1", mark(triple)+"type B struct{}\n"),
		tree("apps", "v1beta2", mark("+k8s:prerelease-lifecycle-gen:introduced=1.2")+"type D struct{}\n"))
	r := run(t, two)
	if !r.Complete || len(r.Lifecycles) != 3 {
		t.Fatalf("%+v", r)
	}
	served := map[string]string{"apps/v1beta1/A": "1.22", "batch/v1beta1/B": "1.22"}
	cb := func(g, v, k string) (string, bool) { rel, ok := served[g+"/"+v+"/"+k]; return rel, ok }

	if got := r.MechanicalLifecycles(cb); len(got) != 2 {
		t.Fatalf("match: %+v", got)
	}
	served["batch/v1beta1/B"] = "1.23" // mismatch
	if got := r.MechanicalLifecycles(cb); got != nil {
		t.Fatalf("mismatch handed out: %+v", got)
	}
	delete(served, "batch/v1beta1/B") // missing
	if got := r.MechanicalLifecycles(cb); got != nil {
		t.Fatalf("missing entry handed out: %+v", got)
	}
	if got := r.MechanicalLifecycles(nil); got != nil {
		t.Fatalf("nil callback handed out: %+v", got)
	}
	// Drafts legitimately differ: the callback is not asked about them.
	only := run(t, tree("apps", "v1beta2", mark("+k8s:prerelease-lifecycle-gen:introduced=1.2")+"type D struct{}\n"))
	asked := false
	if got := only.MechanicalLifecycles(func(string, string, string) (string, bool) { asked = true; return "", false }); got != nil || asked {
		t.Fatalf("draft-only result: %+v asked=%v", got, asked)
	}
	// A ledger entry still wins over a matching callback.
	bad := run(t, merge(two, tree("x", "v1beta1", mark("+k8s:prerelease-lifecycle-gen:introduced=zz")+"type Z struct{}\n")))
	served["apps/v1beta1/A"], served["batch/v1beta1/B"] = "1.22", "1.22"
	if got := bad.MechanicalLifecycles(cb); got != nil {
		t.Fatalf("incomplete result handed out: %+v", got)
	}
}

type countRd struct {
	mem
	reads int
	after func()
}

func (c *countRd) Read(r extract.RepoRef, s, p string) ([]byte, error) {
	c.reads++
	if c.after != nil {
		c.after()
	}
	return c.mem.Read(r, s, p)
}

func TestNoReadsAfterTotalCap(t *testing.T) {
	d := apiDir + "/a/v1beta1/"
	m := merge(tree("a", "v1beta1", mark(triple)+"type A struct{}\n"),
		mem{d + "x.go": "package v1beta1\n", d + "y.go": "package v1beta1\n"})
	g := defaultGuards()
	g.lim.totalBytes = 1 // the first read passes the cap
	c := &countRd{mem: m}
	r, err := scan(context.Background(), c, tgt(), sha, g)
	if err != nil {
		t.Fatal(err)
	}
	if r.Complete || !contains(codes(r), ReasonTooLarge) {
		t.Fatalf("cap not reported: %v", codes(r))
	}
	if c.reads != 1 {
		t.Fatalf("reads after the cap: %d", c.reads)
	}
}

func TestContextCancelledPerVersion(t *testing.T) {
	m := merge(tree("a", "v1beta1", mark(triple)+"type A struct{}\n"))
	m2 := tree("a", "v1beta2", mark(triple)+"type A struct{}\n")
	m = merge(m, m2)
	ctx, cancel := context.WithCancel(context.Background())
	c := &countRd{mem: m, after: cancel}
	if _, err := scan(ctx, c, tgt(), sha, defaultGuards()); err == nil {
		t.Fatal("cancel inside a group not honoured")
	}
}
