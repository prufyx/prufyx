// SPDX-License-Identifier: AGPL-3.0-only

package changelogcli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/changelogentries"
)

func rowsFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	base := filepath.Join(root, "github.com", "example", "notes")
	c := strings.Repeat("a", 40)
	if err := os.MkdirAll(filepath.Join(base, "commits", c), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "tags.json"), []byte(`{"v1.0.0":"`+c+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	for p, v := range files {
		full := filepath.Join(base, "commits", c, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestRowsCheckExitCodes(t *testing.T) {
	row := func(path string) []changelogentries.Target {
		return []changelogentries.Target{{
			Component: "notes", Repo: extract.RepoRef{Key: "github.com/example/notes"},
			Form: changelogentries.FormPerVersionFile, Path: path,
		}}
	}
	fx := rowsFixture(t, map[string]string{"docs/v1.0.0.md": "## Changes\n\n- fix a\n"})
	cases := []struct {
		name string
		tbl  []changelogentries.Target
		args []string
		code int
		want string
	}{
		{"pass", row("docs/v{version}.md"), []string{"rows-check", "--fixture", fx}, 0, "PASS notes form=changelog-per-version-file tags=1 located=1"},
		{"pass one component", row("docs/v{version}.md"), []string{"rows-check", "--fixture", fx, "--component", "notes"}, 0, "failed=0"},
		{"path never resolves", row("nowhere/v{version}.md"), []string{"rows-check", "--fixture", fx}, 1, "FAIL notes"},
		{"unknown component", row("docs/v{version}.md"), []string{"rows-check", "--fixture", fx, "--component", "x"}, 2, ""},
		{"no source", row("docs/v{version}.md"), []string{"rows-check"}, 2, ""},
		{"both sources", row("docs/v{version}.md"), []string{"rows-check", "--fixture", fx, "--mirror-state", fx}, 2, ""},
		{"extra arg", row("docs/v{version}.md"), []string{"rows-check", "--fixture", fx, "x"}, 2, ""},
		{"unknown flag", row("docs/v{version}.md"), []string{"rows-check", "--fixture", fx, "--tag", "v1.0.0"}, 2, ""},
		{"repeated flag", row("docs/v{version}.md"), []string{"rows-check", "--fixture", fx, "--fixture", fx}, 2, ""},
		{"empty table", nil, []string{"rows-check", "--fixture", fx}, 2, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			code := run(c.args, c.tbl, &out, &errb)
			if code != c.code || !strings.Contains(out.String(), c.want) {
				t.Fatalf("code %d (want %d)\nout: %s\nerr: %s", code, c.code, out.String(), errb.String())
			}
			if code == 2 && out.Len() != 0 {
				t.Fatalf("stdout on refusal: %s", out.String())
			}
		})
	}
}

func TestProposeRowsCLI(t *testing.T) {
	fx := rowsFixture(t, map[string]string{"docs/releases/v1.0.0.md": "## Changes\n\n- fix a\n"})
	a := func(extra ...string) []string {
		return append([]string{"propose-rows", "--fixture", fx, "--component", "notes", "--repo", "github.com/example/notes"}, extra...)
	}
	var out, errb bytes.Buffer
	if code := run(a(), nil, &out, &errb); code != 0 || !strings.Contains(out.String(), `"path": "docs/releases/v{version}.md"`) {
		t.Fatalf("%d %s %s", code, out.String(), errb.String())
	}
	out.Reset()
	toml := rowsFixture(t, map[string]string{"releases/v1.0.0.toml": "- a\n- b\n"})
	if code := run([]string{"propose-rows", "--fixture", toml, "--component", "notes", "--repo", "github.com/example/notes"}, nil, &out, &errb); code != 1 || !strings.Contains(out.String(), "NO-ROW NON_MARKDOWN_SOURCE") {
		t.Fatalf("%d %s", code, out.String())
	}
	for name, args := range map[string][]string{
		"no component": {"propose-rows", "--fixture", fx, "--repo", "github.com/example/notes"},
		"no source":    {"propose-rows", "--component", "notes", "--repo", "github.com/example/notes"},
		"bad tag":      a("--tags", "v9.9.9"),
		"repeated":     a("--repo", "github.com/example/notes"),
		"extra":        a("x"),
	} {
		var o, e bytes.Buffer
		if code := run(args, nil, &o, &e); code != 2 || o.Len() != 0 {
			t.Fatalf("%s: %d %s", name, code, o.String())
		}
	}
}
