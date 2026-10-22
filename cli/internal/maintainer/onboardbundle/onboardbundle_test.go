// SPDX-License-Identifier: AGPL-3.0-only

package onboardbundle

import (
	"bytes"
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
