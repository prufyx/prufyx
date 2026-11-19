// SPDX-License-Identifier: AGPL-3.0-only

package onboardbundle

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixture copies testdata/valid into a temp dir and lets edit change it.
func fixture(t *testing.T, edit func(dir string)) string {
	t.Helper()
	dir := t.TempDir()
	entries, err := os.ReadDir("testdata/valid")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join("testdata/valid", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if edit != nil {
		edit(dir)
	}
	return dir
}

func rewrite(t *testing.T, dir, name, from, to string) {
	t.Helper()
	p := filepath.Join(dir, name)
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(from)) {
		t.Fatalf("%s does not contain %q", name, from)
	}
	if err := os.WriteFile(p, bytes.Replace(raw, []byte(from), []byte(to), 1), 0o644); err != nil {
		t.Fatal(err)
	}
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestValidFixtureHasNoFindings(t *testing.T) {
	findings, err := Validate(fixture(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings: %v", findings)
	}
}

func TestFindings(t *testing.T) {
	secret := "gh" + "p_" + strings.Repeat("a", 30)
	cases := []struct {
		name string
		edit func(t *testing.T, dir string)
		want string
	}{
		{"unknown file", func(t *testing.T, d string) { write(t, d, "notes.json", "{}") }, "notes.json: not a bundle file"},
		{"forbidden file", func(t *testing.T, d string) { write(t, d, "rules.json", "{}") }, "rules.json: forbidden file"},
		{"forbidden signature prefix", func(t *testing.T, d string) { write(t, d, "signature.json", "{}") }, "signature.json: forbidden file"},
		{"subdirectory", func(t *testing.T, d string) { write(t, d, "sub/x.json", "{}") }, "sub/: directory not allowed"},
		{"bad extract file", func(t *testing.T, d string) { write(t, d, "extract-run/other.json", "{}") }, "extract-run/other.json: only extract-run"},
		{"nested extract dir", func(t *testing.T, d string) { write(t, d, "extract-run/deep/manifest.json", "{}") }, "extract-run/deep/: directory not allowed"},
		{"symlink", func(t *testing.T, d string) {
			if err := os.Symlink("project.json", filepath.Join(d, "link.json")); err != nil {
				t.Skip("symlinks unavailable")
			}
		}, "link.json: symlink refused"},
		{"oversize", func(t *testing.T, d string) {
			write(t, d, "scan-notes.json", `{"x":"`+strings.Repeat("a", MaxFileBytes)+`"}`)
		}, "scan-notes.json: over 262144 bytes"},
		{"too many files", func(t *testing.T, d string) {
			for _, n := range []string{"a", "b", "c", "d", "e", "f", "g"} {
				write(t, d, "extra-"+n+".json", "{}")
			}
		}, "13 files, more than 12"},
		{"missing required", func(t *testing.T, d string) { _ = os.Remove(filepath.Join(d, "scan-notes.json")) }, "scan-notes.json: missing"},
		{"not json", func(t *testing.T, d string) { write(t, d, "project.json", "{nope") }, "project.json: not strict UTF-8 JSON"},
		{"trailing data", func(t *testing.T, d string) { write(t, d, "project.json", "{} {}") }, "project.json: not strict UTF-8 JSON"},
		{"duplicate key", func(t *testing.T, d string) { write(t, d, "project.json", `{"a":1,"a":2}`) }, "duplicate key"},
		{"invalid utf8", func(t *testing.T, d string) { write(t, d, "project.json", "{\"a\":\"\xff\"}") }, "invalid UTF-8"},
		{"deep nesting", func(t *testing.T, d string) {
			write(t, d, "project.json", strings.Repeat("[", 40)+strings.Repeat("]", 40))
		}, "nesting deeper than 24"},
		{"secret", func(t *testing.T, d string) { rewrite(t, d, "scan-notes.json", `"note": "`, `"note": "`+secret+` `) }, "secret-shaped value"},
		{"home path", func(t *testing.T, d string) {
			rewrite(t, d, "scan-notes.json", `"note": "`, `"note": "/Users/someone/work `)
		}, "internal/owner-environment name"},
		{"private ip", func(t *testing.T, d string) { rewrite(t, d, "scan-notes.json", `"note": "`, `"note": "10.1.2.3 `) }, "internal/owner-environment name"},
		{"unknown field", func(t *testing.T, d string) { rewrite(t, d, "project.json", `"slug"`, `"extra": 1, "slug"`) }, "project.json: unknown field extra"},
		{"bad slug", func(t *testing.T, d string) {
			rewrite(t, d, "project.json", `"slug": "example-operator"`, `"slug": "Example_Operator"`)
		}, "project.json.slug: does not match"},
		{"factProject hyphen", func(t *testing.T, d string) {
			rewrite(t, d, "target-draft.json", `"minFrom"`, `"factProject": "example-operator", "minFrom"`)
		}, "target-draft.json.target.factProject: does not match"},
		{"project differs", func(t *testing.T, d string) {
			rewrite(t, d, "target-draft.json", `"project": "example-operator"`, `"project": "other"`)
		}, "target-draft.json: project/repo differ from project.json"},
		{"digest mismatch", func(t *testing.T, d string) { rewrite(t, d, "project.json", `"Apache-2.0"`, `"MIT"`) }, "receipt.json: bundleSha256 does not match"},
		{"bad lead span", func(t *testing.T, d string) { rewrite(t, d, "leads.json", `"endLine": 12`, `"endLine": 14`) }, "line span does not match the text"},
		{"lead trailing newline", func(t *testing.T, d string) {
			rewrite(t, d, "leads.json", `instead."`, `instead.\n"`)
		}, "text must not end with a newline"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := Validate(fixture(t, func(d string) { tc.edit(t, d) }))
			if err != nil {
				t.Fatal(err)
			}
			if !contains(findings, tc.want) {
				t.Fatalf("want a finding containing %q, got %v", tc.want, findings)
			}
		})
	}
}

func TestFactProjectUnderscoreAccepted(t *testing.T) {
	d := fixture(t, func(d string) {
		rewrite(t, d, "target-draft.json", `"minFrom"`, `"factProject": "example_operator", "minFrom"`)
	})
	findings, err := Validate(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if strings.Contains(f, "factProject") {
			t.Fatalf("underscore factProject must pass the schema: %v", findings)
		}
	}
}

func TestQuoteMayContainInternalLookingText(t *testing.T) {
	// A byte-exact release-note quote is upstream text; only secrets and control
	// characters are refused there.
	d := fixture(t, func(d string) {
		rewrite(t, d, "leads.json", "Removed the spec.legacyMode field", "Removed /home/user paths")
	})
	findings, _ := Validate(d)
	for _, f := range findings {
		if strings.Contains(f, "internal/owner-environment") {
			t.Fatalf("quote text must not be checked for internal names: %v", findings)
		}
	}
}

func TestUpstreamPathWithHomeSegmentIsNotInternal(t *testing.T) {
	d := fixture(t, func(d string) { rewrite(t, d, "scan-notes.json", `"note": "`, `"note": "see pkg/home/handler.go and `) })
	findings, _ := Validate(d)
	if contains(findings, "internal/owner-environment") {
		t.Fatalf("pkg/home/ must not be flagged: %v", findings)
	}
}

func TestNewlineInPlainStringRefused(t *testing.T) {
	d := fixture(t, func(d string) { rewrite(t, d, "scan-notes.json", `"note": "`, `"note": "a\r\nb `) })
	findings, _ := Validate(d)
	if !contains(findings, "control character") {
		t.Fatalf("want control character finding: %v", findings)
	}
}

func TestValidateRejectsNonDirectory(t *testing.T) {
	if _, err := Validate(filepath.Join(fixture(t, nil), "project.json")); err == nil {
		t.Fatal("want an error for a file path")
	}
	if _, err := Validate(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("want an error for a missing path")
	}
}

func TestRunExitCodes(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Run([]string{"validate", fixture(t, nil)}, &out, &errb); code != 0 {
		t.Fatalf("valid bundle: code %d, out %q", code, out.String())
	}
	out.Reset()
	bad := fixture(t, func(d string) { write(t, d, "rules.json", "{}") })
	if code := Run([]string{"validate", fixture(t, nil), bad}, &out, &errb); code != 1 || !strings.Contains(out.String(), "FAIL") {
		t.Fatalf("bad bundle: code %d, out %q", code, out.String())
	}
	for _, args := range [][]string{nil, {"validate"}, {"check", "x"}, {"validate", filepath.Join(t.TempDir(), "absent")}} {
		if code := Run(args, &out, &errb); code != 2 {
			t.Fatalf("args %v: code %d, want 2", args, code)
		}
	}
}

func TestRunDirIsSlug(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Run([]string{"validate", "--dir-is-slug", fixture(t, nil)}, &out, &errb); code != 1 || !strings.Contains(out.String(), "differs from the directory name") {
		t.Fatalf("temp dir name is not the slug: code %d, out %q", code, out.String())
	}
	named := filepath.Join(t.TempDir(), "example-operator")
	if err := os.Mkdir(named, 0o755); err != nil {
		t.Fatal(err)
	}
	src := fixture(t, nil)
	entries, _ := os.ReadDir(src)
	for _, e := range entries {
		raw, _ := os.ReadFile(filepath.Join(src, e.Name()))
		_ = os.WriteFile(filepath.Join(named, e.Name()), raw, 0o644)
	}
	out.Reset()
	if code := Run([]string{"validate", "--dir-is-slug", named}, &out, &errb); code != 0 {
		t.Fatalf("matching dir name: code %d, out %q", code, out.String())
	}
}

func TestFindingsAreDeterministic(t *testing.T) {
	d := fixture(t, func(d string) {
		write(t, d, "b.json", "{}")
		write(t, d, "a.json", "{}")
	})
	first, _ := Validate(d)
	for i := 0; i < 5; i++ {
		again, _ := Validate(d)
		if strings.Join(first, "\n") != strings.Join(again, "\n") {
			t.Fatal("findings order changed between runs")
		}
	}
}

func contains(findings []string, want string) bool {
	for _, f := range findings {
		if strings.Contains(f, want) {
			return true
		}
	}
	return false
}

func TestKeysAndVersionsScanned(t *testing.T) {
	secret := "gh" + "p_" + strings.Repeat("a", 30)
	cases := []struct {
		name    string
		content string
		want    string // empty: no such finding expected
	}{
		{"secret-shaped key", `{"` + secret + `": 1}`, "secret-shaped value"},
		{"path key", `{"/Users/someone/work": true}`, "internal/owner-environment name"},
		{"nested private-ip key", `{"a": {"192.168.1.5": 1}}`, "internal/owner-environment name"},
		{"control char key", `{"a\nb": 1}`, "control character"},
		{"version with 10 after dotted component accepted", `{"v": "1.10.2.3.4"}`, ""},
		{"prefixed version with 192.168 accepted", `{"v": "v1.192.168.0.1"}`, ""},
		{"version with 172.16 after dotted component accepted", `{"v": "2.172.16.4.5"}`, ""},
		{"plain key accepted", `{"harmless": "1.2.3"}`, ""},
		{"private 10 ip refused", `{"v": "host 10.1.2.3"}`, "internal/owner-environment name"},
		{"private 192 ip refused", `{"v": "192.168.0.1"}`, "internal/owner-environment name"},
		{"private 172 ip refused", `{"v": "x=172.20.1.1"}`, "internal/owner-environment name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := fixture(t, func(d string) { write(t, d, "extract-run/candidates.json", tc.content) })
			findings, err := Validate(d)
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == "" {
				for _, f := range findings {
					if strings.Contains(f, "internal/owner-environment") || strings.Contains(f, "secret-shaped") || strings.Contains(f, "control character") {
						t.Fatalf("unexpected finding: %v", findings)
					}
				}
				return
			}
			if !contains(findings, tc.want) {
				t.Fatalf("want a finding containing %q, got %v", tc.want, findings)
			}
		})
	}
}

// The declared licence identifier is a closed allowlist in the schema. Anything
// else, including source-available and proprietary identifiers, spelling and
// case variants, and an empty or missing value, must produce a finding.
func TestLicenceDispositionRefused(t *testing.T) {
	refused := []string{
		"BUSL-1.1", "BSL-1.1", "busl-1.1", "BUSL", "Elastic-2.0", "ELv2", "elv2",
		"SSPL-1.0", "sspl-1.0", "SSPL", "proprietary", "Proprietary", "unlicensed",
		"UNLICENSED", "NONE", "NOASSERTION", "unknown", "",
		" Apache-2.0", "Apache-2.0 ", "apache-2.0", "APACHE-2.0", "mit", "Apache 2.0",
		"Apache-2.0 OR BUSL-1.1", "MIT AND SSPL-1.0", "LicenseRef-proprietary",
		"Apache-2.0\n", "Apache-2.0​",
	}
	for _, id := range refused {
		t.Run("spdxGuess "+id, func(t *testing.T) {
			findings, err := Validate(fixture(t, func(d string) {
				rewrite(t, d, "project.json", `"spdxGuess": "Apache-2.0"`, `"spdxGuess": `+jsonString(id))
			}))
			if err != nil {
				t.Fatal(err)
			}
			if !contains(findings, "licence.spdxGuess: not one of") {
				t.Fatalf("want a licence.spdxGuess finding for %q, got %v", id, findings)
			}
		})
	}
	nonString := []string{"null", "1", "true", `["MIT"]`, `{"id":"MIT"}`}
	for _, v := range nonString {
		t.Run("spdxGuess type "+v, func(t *testing.T) {
			findings, err := Validate(fixture(t, func(d string) {
				rewrite(t, d, "project.json", `"spdxGuess": "Apache-2.0"`, `"spdxGuess": `+v)
			}))
			if err != nil {
				t.Fatal(err)
			}
			if !contains(findings, "licence.spdxGuess") {
				t.Fatalf("want a licence.spdxGuess finding for %s, got %v", v, findings)
			}
		})
	}
	t.Run("missing spdxGuess", func(t *testing.T) {
		findings, err := Validate(fixture(t, func(d string) {
			rewrite(t, d, "project.json", ",\n    \"spdxGuess\": \"Apache-2.0\"", "")
		}))
		if err != nil {
			t.Fatal(err)
		}
		if !contains(findings, "missing spdxGuess") {
			t.Fatalf("want a licence finding, got %v", findings)
		}
	})
	t.Run("missing licence object", func(t *testing.T) {
		findings, err := Validate(fixture(t, func(d string) {
			src := mustRead(t, "testdata/valid/project.json")
			i := strings.Index(src, "  \"licence\": {")
			j := strings.Index(src[i:], "},\n")
			write(t, d, "project.json", src[:i]+src[i+j+3:])
		}))
		if err != nil {
			t.Fatal(err)
		}
		if !contains(findings, "missing licence") {
			t.Fatalf("want a licence finding, got %v", findings)
		}
	})
	for _, ok := range []string{"Apache-2.0", "MIT", "BSD-3-Clause", "MPL-2.0", "AGPL-3.0"} {
		t.Run("accepted "+ok, func(t *testing.T) {
			findings, err := Validate(fixture(t, func(d string) {
				rewrite(t, d, "project.json", `"spdxGuess": "Apache-2.0"`, `"spdxGuess": "`+ok+`"`)
			}))
			if err != nil {
				t.Fatal(err)
			}
			if contains(findings, "licence.spdxGuess") {
				t.Fatalf("unexpected licence finding for %q: %v", ok, findings)
			}
		})
	}
}

func jsonString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestReadmeListsSchemaScanNoteClasses(t *testing.T) {
	raw, err := os.ReadFile("schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	var find func(v any) []any
	find = func(v any) []any {
		switch x := v.(type) {
		case map[string]any:
			if c, ok := x["class"].(map[string]any); ok {
				if e, ok := c["enum"].([]any); ok {
					return e
				}
			}
			for _, child := range x {
				if e := find(child); e != nil {
					return e
				}
			}
		case []any:
			for _, child := range x {
				if e := find(child); e != nil {
					return e
				}
			}
		}
		return nil
	}
	want := map[string]bool{}
	for _, c := range find(schema) {
		want[c.(string)] = true
	}
	if len(want) == 0 {
		t.Fatal("no class enum in schema")
	}
	doc, err := os.ReadFile("../../../../contrib/onboard-bundles/README.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(doc)
	i := strings.Index(text, "### Scan-notes classes")
	if i < 0 {
		t.Fatal("README has no scan-notes class section")
	}
	section := text[i:]
	if j := strings.Index(section, "\n## "); j >= 0 {
		section = section[:j]
	}
	got := map[string]bool{}
	for _, line := range strings.Split(section, "\n") {
		if strings.HasPrefix(line, "| `") {
			got[strings.Split(line, "`")[1]] = true
		}
	}
	if len(got) != len(want) {
		t.Fatalf("README classes %v, schema classes %v", got, want)
	}
	for c := range want {
		if !got[c] {
			t.Fatalf("README misses class %s", c)
		}
	}
}

func TestReadmeFieldTableCoversSchema(t *testing.T) {
	raw, err := os.ReadFile("schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Defs map[string]any `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile("../../../../contrib/onboard-bundles/README.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(doc)
	i := strings.Index(text, "## Where each field comes from")
	j := strings.Index(text, "### Scan-notes classes")
	if i < 0 || j < i {
		t.Fatal("README field table section missing")
	}
	table := text[i:j]
	var walk func(v any, prefix string, out *[]string)
	walk = func(v any, prefix string, out *[]string) {
		m, _ := v.(map[string]any)
		props, _ := m["properties"].(map[string]any)
		for k, c := range props {
			*out = append(*out, prefix+k)
			walk(c, prefix+k+".", out)
			if cm, ok := c.(map[string]any); ok && cm["items"] != nil {
				walk(cm["items"], prefix+k+"[].", out)
			}
		}
	}
	files := map[string]string{"project": "project.json", "targetDraft": "target-draft.json", "scanNotes": "scan-notes.json", "relnotesSources": "relnotes-sources.json", "leads": "leads.json", "receipt": "receipt.json"}
	for def, file := range files {
		var paths []string
		walk(schema.Defs[def], "", &paths)
		if len(paths) == 0 {
			t.Fatalf("no properties for %s", def)
		}
		for _, p := range paths {
			if !strings.Contains(table, "| `"+file+"` `"+p+"` |") {
				t.Errorf("README field table misses %s %s", file, p)
			}
		}
	}
}
