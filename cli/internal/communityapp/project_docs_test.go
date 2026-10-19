// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const projectDocsDir = "../../docs/projects"

// TestProjectDocsFresh: cli/docs/projects equals what the generator renders.
// Run with PRUFYX_UPDATE_DOCS=1 to rewrite the pages. It is not parallel and
// reads no knowledge pack, so it holds under the synthetic-knowledge build too.
func TestProjectDocsFresh(t *testing.T) {
	want := renderProjectDocs()
	if os.Getenv("PRUFYX_UPDATE_DOCS") == "1" {
		if err := os.MkdirAll(projectDocsDir, 0o755); err != nil {
			t.Fatal(err)
		}
		old, _ := filepath.Glob(filepath.Join(projectDocsDir, "*.md"))
		for _, p := range old {
			if _, ok := want[filepath.Base(p)]; !ok {
				if err := os.Remove(p); err != nil {
					t.Fatal(err)
				}
			}
		}
		for name, body := range want {
			if err := os.WriteFile(filepath.Join(projectDocsDir, name), body, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	have, err := filepath.Glob(filepath.Join(projectDocsDir, "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range have {
		names = append(names, filepath.Base(p))
	}
	var wantNames []string
	for n := range want {
		wantNames = append(wantNames, n)
	}
	sort.Strings(names)
	sort.Strings(wantNames)
	if strings.Join(names, ",") != strings.Join(wantNames, ",") {
		t.Fatalf("cli/docs/projects is stale: files %v, generator wants %v; run PRUFYX_UPDATE_DOCS=1 go test ./internal/communityapp -run TestProjectDocsFresh", names, wantNames)
	}
	for name, body := range want {
		got, err := os.ReadFile(filepath.Join(projectDocsDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, body) {
			t.Errorf("cli/docs/projects/%s is stale; run PRUFYX_UPDATE_DOCS=1 go test ./internal/communityapp -run TestProjectDocsFresh", name)
		}
	}
}

// TestProjectDocsAreDeterministic: two renders are byte-identical.
func TestProjectDocsAreDeterministic(t *testing.T) {
	a, b := renderProjectDocs(), renderProjectDocs()
	if len(a) != len(b) {
		t.Fatal("page sets differ")
	}
	for name, body := range a {
		if !bytes.Equal(body, b[name]) {
			t.Fatalf("%s differs between renders", name)
		}
	}
}

// TestLegacyUsageLinesAreDocumented: every non-blank line of the former long
// help texts occurs in a generated page, so moving the text out of -h lost
// nothing.
func TestLegacyUsageLinesAreDocumented(t *testing.T) {
	var all strings.Builder
	for _, body := range renderProjectDocs() {
		all.Write(body)
	}
	for _, s := range legacySources {
		for _, l := range parseLegacy(s.text) {
			if !strings.Contains(all.String(), l.text) {
				t.Errorf("%s: line not in any generated page: %.120s", s.route, l.text)
			}
		}
	}
}

func TestLegacyParsing(t *testing.T) {
	lines := parseLegacy("Usage:\n  prufyx check project --project grafana|kibana --effective-config FILE\n    note: Kibana 9 needs --x\n  prufyx check cncf --project SLUG --input FILE\nprose")
	if len(lines) != 4 || !lines[0].usage || lines[0].route != "check project" || strings.Join(lines[0].slugs, ",") != "grafana,kibana" || len(lines[0].notes) != 1 {
		t.Fatalf("%+v", lines)
	}
	if len(lines[2].slugs) != 0 || lines[3].usage {
		t.Fatalf("%+v", lines)
	}
}

func TestWrapUsageNeverExceedsWidthOnShortWords(t *testing.T) {
	for _, l := range wrapUsage("  ", strings.Repeat("--flag VALUE ", 30), 100) {
		if len(l) > 100 {
			t.Fatalf("line of %d chars: %s", len(l), l)
		}
	}
}

func shortHelp(t *testing.T, args ...string) string {
	t.Helper()
	t.Setenv("PRUFYX_COLOR", "never")
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), args, &stdout, &stderr, "test"); code != ExitOK || stderr.Len() != 0 {
		t.Fatalf("%v: code=%d stderr=%q", args, code, stderr.String())
	}
	return stdout.String()
}

// TestShortHelpIsShort: the check and prepare helps fit a screen.
func TestShortHelpIsShort(t *testing.T) {
	for _, args := range [][]string{
		{"check", "-h"}, {"check", "help"}, {"help", "check"},
		{"prepare", "-h"}, {"help", "prepare"},
		{"check", "cncf", "--help"}, {"prepare", "cncf", "-h"},
		{"check", "project", "--help"}, {"prepare", "project", "--help"},
	} {
		out := shortHelp(t, args...)
		lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
		if len(lines) > 40 {
			t.Errorf("%v: %d lines", args, len(lines))
		}
		for _, l := range lines {
			if len(l) > 100 {
				t.Errorf("%v: line of %d chars: %s", args, len(l), l)
			}
		}
	}
}

// TestProjectHelpPrintsThatProjectsUsage: --project SLUG --help prints the
// usage lines of that project, wrapped, and a docs pointer.
func TestProjectHelpPrintsThatProjectsUsage(t *testing.T) {
	out := shortHelp(t, "prepare", "cncf", "--project", "cilium", "--help")
	for _, pair := range []string{"--from 1.18.6 --to 1.19.0", "--from 1.18.13 --to 1.19.7"} {
		if !strings.Contains(strings.Join(strings.Fields(out), " "), "--project cilium --input FILE "+pair) {
			t.Fatalf("cilium pair %q missing:\n%s", pair, out)
		}
	}
	if !strings.Contains(out, "projects/cilium.md") {
		t.Fatalf("no docs pointer:\n%s", out)
	}
	for _, l := range strings.Split(out, "\n") {
		if len(l) > 100 {
			t.Fatalf("line of %d chars: %s", len(l), l)
		}
	}
	if out := shortHelp(t, "check", "cncf", "--project=no-such-project", "-h"); !strings.Contains(out, "No project-specific form") {
		t.Fatalf("unknown slug:\n%s", out)
	}
	if out := shortHelp(t, "check", "project", "--project", "kibana", "--help"); !strings.Contains(out, "--full-status-without-monitor-required") {
		t.Fatalf("kibana note missing:\n%s", out)
	}
}

func TestHelpAllListsHiddenCommands(t *testing.T) {
	root := shortHelp(t, "help")
	if strings.Contains(root, "community-preview") {
		t.Fatalf("root help shows a hidden command:\n%s", root)
	}
	all := shortHelp(t, "help", "--all")
	for _, want := range []string{"Check an upgrade:", "community-preview", "demo-prometheus-mode", "--knowledge-bundle-digest"} {
		if !strings.Contains(all, want) {
			t.Fatalf("help --all lacks %q:\n%s", want, all)
		}
	}
}
