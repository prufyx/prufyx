// SPDX-License-Identifier: AGPL-3.0-only

package crdschema

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/membercode"
)

func unmarshalStrict(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func sorted(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	return out
}

func lines(os []Omission) []string {
	out := []string{}
	for _, o := range os {
		out = append(out, fmt.Sprintf("%s|%s|%d", o.Reason, o.Subject, o.Count))
	}
	return sorted(out)
}

func lowerEnc(group, kind string, p []membercode.Seg) (string, error) {
	q := append([]membercode.Seg(nil), p...)
	for i := range q {
		q[i].Name = strings.ToLower(q[i].Name)
	}
	return membercode.Field(group, kind, q)
}

func guardsFor(c testCase, g guards) guards {
	if c.exp.Lossy {
		g.fieldEnc = lowerEnc
	}
	return g
}

// check runs one case and returns a description of the first mismatch.
func check(c testCase, g guards) error {
	res, err := derive(context.Background(), c.reader(), testTarget, commitA, commitB, guardsFor(c, g))
	if err != nil {
		return err
	}
	if got := sorted(res.Fields.Members); !reflect.DeepEqual(got, sorted(c.exp.Fields)) {
		return fmt.Errorf("fields = %v, want %v", got, sorted(c.exp.Fields))
	}
	if got := sorted(res.Enums.Members); !reflect.DeepEqual(got, sorted(c.exp.Enums)) {
		return fmt.Errorf("enums = %v, want %v", got, sorted(c.exp.Enums))
	}
	if res.Fields.Complete != c.exp.Complete || res.Enums.Complete != c.exp.Complete {
		return fmt.Errorf("complete = %v/%v, want %v", res.Fields.Complete, res.Enums.Complete, c.exp.Complete)
	}
	if got := lines(res.Omissions); !reflect.DeepEqual(got, sorted(c.exp.Omissions)) {
		return fmt.Errorf("omissions = %v, want %v", got, sorted(c.exp.Omissions))
	}
	if got := lines(res.Exclusions); !reflect.DeepEqual(got, sorted(c.exp.Exclusions)) {
		return fmt.Errorf("exclusions = %v, want %v", got, sorted(c.exp.Exclusions))
	}
	return nil
}

func allCases(t testing.TB) []testCase {
	t.Helper()
	td, err := loadTestdata()
	if err != nil {
		t.Fatal(err)
	}
	return append(append(td, syntheticCases()...), narrowingCases()...)
}

// A derived pair is complete exactly when its withhold set is empty.
func TestOracle(t *testing.T) {
	cases := allCases(t)
	if len(cases) < 40 {
		t.Fatalf("only %d cases; fixtures missing", len(cases))
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := check(c, defaultGuards()); err != nil {
				t.Fatal(err)
			}
			if c.exp.Complete != (len(c.exp.Omissions) == 0) {
				t.Fatalf("fixture inconsistent: complete=%v with %d omissions", c.exp.Complete, len(c.exp.Omissions))
			}
		})
	}
}

func laxField(group, kind string, p []membercode.Seg) (string, error) {
	parts := []string{group, kind}
	for _, s := range p {
		switch s.Kind {
		case membercode.Item:
			parts = append(parts, "[]")
		case membercode.Any:
			parts = append(parts, "*")
		default:
			parts = append(parts, s.Name)
		}
	}
	return strings.Join(parts, "/"), nil
}

func laxEnum(group, kind string, p []membercode.Seg, v string) (string, error) {
	m, _ := laxField(group, kind, p)
	return m + "/" + v, nil
}

// Every guard, switched off, must make at least one named case fail.
func TestMutationEveryGuardIsLoadBearing(t *testing.T) {
	cases := allCases(t)
	byName := map[string]testCase{}
	for _, c := range cases {
		byName[c.name] = c
	}
	mutations := []struct {
		guard string
		off   func(*guards)
		fails []string // at least one of these must fail
	}{
		{"conversion webhook", func(g *guards) { g.webhook = false }, []string{"conversion_webhook", "conversion_webhook_from"}},
		{"version specific field", func(g *guards) { g.versionSpecific = false }, []string{"multiversion_removed_in_one"}},
		{"version specific enum", func(g *guards) { g.versionSpecific = false }, []string{"multiversion_enum_one_version"}},
		{"preserve unknown", func(g *guards) { g.preserve = false }, []string{"preserve_unknown_to", "preserve_unknown_from", "additional_properties_true_to"}},
		{"status exclusion", func(g *guards) { g.status = false }, []string{"status_removed_excluded", "status_enum_excluded", "mariadb_status_moved"}},
		{"rename candidate field", func(g *guards) { g.rename = false }, []string{"rename_new_location"}},
		{"rename candidate enum", func(g *guards) { g.rename = false }, []string{"enum_rename_new_location"}},
		{"unmodelled keyword", func(g *guards) { g.parse.unmodel = false }, []string{"anyof_above_removed_path"}},
		{"strict yaml", func(g *guards) { g.parse.strict = false }, []string{"parse_duplicate_keys", "parse_anchor_alias", "parse_anchor_only", "parse_merge_key", "parse_custom_tag", "parse_flow_quoted"}},
		{"secret kind", func(g *guards) { g.parse.secret = false }, []string{"secret_document", "secret_document_after_crd"}},
		{"non crd document", func(g *guards) { g.parse.nonCRD = false }, []string{"non_crd_document"}},
		{"size and depth limits", func(g *guards) { g.parse.limits = false }, []string{"too_large_file", "too_deep_schema"}},
		{"served versions only", func(g *guards) { g.servedOnly = false }, []string{"unserved_version_ignored"}},
		{"presence", func(g *guards) { g.presence = false }, []string{"crd_absent_in_to"}},
		{"typed additionalProperties in B", func(g *guards) { g.preserve = false }, []string{"additional_properties_schema_to"}},
		{"enum: B version lacks the field", func(g *guards) { g.preserve = false }, []string{"enum_version_lacks_field_preserve"}},
		{"non-string enum swapped between versions", func(g *guards) { g.enumSig = false }, []string{"enum_non_string_versions_swapped"}},
		{"nested typed additionalProperties", func(g *guards) { g.preserve = false }, []string{"additional_properties_schema_nested", "item_ancestor_preserve_to", "preserve_two_levels_above_to"}},
		{"unlisted subtree", func(g *guards) { g.subtrees = false }, []string{"unlisted_subtree"}},
		{"rename of a descendant", func(g *guards) { g.rename = false }, []string{"rename_descendant_new_location"}},
		{"collision detection", func(g *guards) { g.collisions = false }, []string{"member_collision_lossy_encoder"}},
		{"member charset", func(g *guards) { g.fieldEnc = laxField; g.enumEnc = laxEnum }, []string{"member_charset"}},
		{"member set over the cap is empty", func(g *guards) { g.emptyOnCap = false }, []string{"too_many_members"}},
		{"kustomize skip", func(g *guards) { g.parse.kustomize = false }, []string{"kustomize_skipped", "kustomize_yml_component_skipped"}},
		{"kustomize proof", func(g *guards) { g.parse.kustomizeProof = false }, []string{"kustomize_crd_marker", "kustomize_patches", "kustomize_foreign_apiversion", "kustomize_malformed", "kustomize_two_documents", "kustomize_wrong_kind"}},
		{"quoted flow scalars", func(g *guards) { g.parse.quotedFlow = false }, []string{"flow_quoted_double", "flow_quoted_single", "flow_quoted_mixed", "flow_quoted_coercible_strings", "flow_quoted_enum_strings"}},
		{"quoted flow proof", func(g *guards) { g.parse.quotedProof = false }, []string{"flow_quoted_escape", "flow_quoted_hex_escape", "flow_quoted_single_escape", "flow_quoted_multiline"}},
		{"kustomize marker scan is case-insensitive", func(g *guards) { g.parse.kustomizeMarker = false }, []string{"kustomize_crd_marker", "kustomize_crd_marker_upper"}},
		{"kustomize strict yaml", func(g *guards) { g.parse.kustomizeStrict = false }, []string{"kustomize_duplicate_key", "kustomize_anchor"}},
		{"kustomize resource entries are strings", func(g *guards) { g.parse.kustomizeEntries = false }, []string{"kustomize_resource_entry_map"}},
		{"kustomize size limit", func(g *guards) { g.parse.kustomizeSize = false }, []string{"kustomize_oversize"}},
		{"quoted flow: other line breaks", func(g *guards) { g.parse.quotedBreaks = false }, []string{"flow_quoted_after_unicode_break"}},
		{"member too long", func(g *guards) { g.fieldEnc = laxField }, []string{"member_too_long"}},
		{"member ambiguous", func(g *guards) { g.fieldEnc = laxField; g.enumEnc = laxEnum }, []string{"member_reserved_name", "member_slash_name", "enum_value_with_slash"}},
	}
	for _, m := range mutations {
		t.Run(m.guard, func(t *testing.T) {
			g := defaultGuards()
			m.off(&g)
			failed := 0
			for _, name := range m.fails {
				c, ok := byName[name]
				if !ok {
					t.Fatalf("no case %q", name)
				}
				if check(c, g) != nil {
					failed++
				}
			}
			if failed == 0 {
				t.Fatalf("switching off %q failed none of %v: the guard is not tested", m.guard, m.fails)
			}
			// The same cases pass with the guard on.
			for _, name := range m.fails {
				if err := check(byName[name], defaultGuards()); err != nil {
					t.Fatalf("%s with guards on: %v", name, err)
				}
			}
		})
	}
}

// Secret content must not reach any output, error or omission.
func TestSecretCanaryNeverPrinted(t *testing.T) {
	for _, c := range allCases(t) {
		res, err := Derive(context.Background(), c.reader(), testTarget, commitA, commitB)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		b, _ := res.Canonical()
		if bytes.Contains(b, []byte("CANARY")) || bytes.Contains(b, []byte("0xC0FFEE")) {
			t.Fatalf("%s: canary leaked into output", c.name)
		}
	}
	c := allCases(t)
	for _, tc := range c {
		if tc.name == "secret_document" {
			if !bytes.Contains(tc.to["crd/crd.yaml"], []byte("CANARY")) {
				t.Fatal("canary fixture lost its canary")
			}
		}
	}
}

// Re-deriving with a recording reader, a reversed listing and a second run
// gives byte-identical canonical output.
func TestDeterministicRederivation(t *testing.T) {
	for _, c := range allCases(t) {
		first := c.reader()
		rec := extract.NewRecorder(first)
		r1, err := Derive(context.Background(), rec, testTarget, commitA, commitB)
		if err != nil {
			t.Fatal(err)
		}
		second := c.reader()
		second.reverse = true
		r2, err := Derive(context.Background(), second, testTarget, commitA, commitB)
		if err != nil {
			t.Fatal(err)
		}
		b1, _ := r1.Canonical()
		b2, _ := r2.Canonical()
		if !bytes.Equal(b1, b2) {
			t.Fatalf("%s: output differs between runs:\n%s\n%s", c.name, b1, b2)
		}
		for _, f := range rec.CommitReads(repo, commitB) {
			if f.SHA256 == "" {
				t.Fatalf("%s: unrecorded read", c.name)
			}
		}
	}
}

func TestMembersAreEngineValid(t *testing.T) {
	for _, c := range allCases(t) {
		res, _ := Derive(context.Background(), c.reader(), testTarget, commitA, commitB)
		for _, set := range [][]string{res.Fields.Members, res.Enums.Members} {
			if !sort.StringsAreSorted(set) {
				t.Fatalf("%s: members not sorted", c.name)
			}
			for _, m := range set {
				if len(m) > 128 || strings.ContainsAny(m, "[]*@#= :") {
					t.Fatalf("%s: member %q is not pattern form", c.name, m)
				}
			}
		}
	}
}

func TestReaderErrorsAbort(t *testing.T) {
	c := allCases(t)[0]
	boom := errors.New("mirror blob missing")
	m := c.reader()
	m.readErr = boom
	if _, err := Derive(context.Background(), m, testTarget, commitA, commitB); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped reader error", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Derive(ctx, c.reader(), testTarget, commitA, commitB); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestRootDirAndDot(t *testing.T) {
	if err := (Target{Repo: repo, Dirs: []string{""}}).validate(); err != nil {
		t.Fatalf("root dir rejected: %v", err)
	}
	for _, tg := range []Target{{Repo: repo, Dirs: []string{"."}}, {Repo: repo, Files: []string{"."}}, {Repo: repo, Files: []string{""}}} {
		if err := tg.validate(); err == nil {
			t.Errorf("%+v accepted", tg)
		}
	}
}

func TestBadInputs(t *testing.T) {
	m := newMem()
	for _, tc := range []struct {
		name     string
		t        Target
		from, to string
	}{
		{"short sha", testTarget, "abc", commitB},
		{"upper sha", testTarget, strings.ToUpper(commitA), commitB},
		{"no paths", Target{Repo: repo}, commitA, commitB},
		{"dotdot", Target{Repo: repo, Files: []string{"../x.yaml"}}, commitA, commitB},
		{"absolute", Target{Repo: repo, Files: []string{"/x.yaml"}}, commitA, commitB},
		{"unclean", Target{Repo: repo, Dirs: []string{"a//b"}}, commitA, commitB},
	} {
		if _, err := Derive(context.Background(), m, tc.t, tc.from, tc.to); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
}

func TestFilesAndSourceKinds(t *testing.T) {
	m := newMem()
	m.put(commitA, "deploy/crd.yaml", simpleCRD("k", "x"))
	m.put(commitB, "deploy/crd.yaml", simpleCRD("k"))
	m.put(commitB, "deploy/notes.txt", []byte("ignored"))
	tg := Target{Repo: repo, Files: []string{"deploy/crd.yaml", "deploy/crd.yaml"}}
	res, err := Derive(context.Background(), m, tg, commitA, commitB)
	if err != nil || !reflect.DeepEqual(res.Fields.Members, []string{"example.io/Widget/spec/x"}) || !res.Fields.Complete {
		t.Fatalf("file target: %+v %v", res, err)
	}
	// A symlink in a listed directory is not followed and withholds.
	m.put(commitB, "crd/link.yaml", []byte("x"))
	m.modes["crd/link.yaml"] = "120000"
	m.put(commitA, "crd/link.yaml", []byte("x"))
	m.put(commitA, "crd/crd.yaml", simpleCRD("k"))
	m.put(commitB, "crd/crd.yaml", simpleCRD("k"))
	res, err = Derive(context.Background(), m, testTarget, commitA, commitB)
	if err != nil || res.Fields.Complete || !strings.Contains(strings.Join(lines(res.Omissions), ","), "INVENTORY_FAULT_source_kind") {
		t.Fatalf("symlink: %+v %v", res, err)
	}
}

func TestCodeDigestCoversEncoder(t *testing.T) {
	files, err := extract.CodeFiles(SourceSet())
	if err != nil {
		t.Fatal(err)
	}
	var own, enc bool
	for _, f := range files {
		if strings.HasSuffix(f.Path, "_test.go") {
			t.Fatalf("test file %s in digest", f.Path)
		}
		own = own || f.Path == "extract/crdschema/derive.go"
		enc = enc || f.Path == "extract/crdschema/membercode_membercode.go"
	}
	if !own || !enc {
		t.Fatalf("digest files %v miss own=%v encoder=%v", files, own, enc)
	}
}
