// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func helpOut(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), args, &stdout, &stderr, "test")
	return code, stdout.String()
}

func TestRootHelpIsShortAndGrouped(t *testing.T) {
	t.Setenv("PRUFYX_COLOR", "")
	for _, args := range [][]string{nil, {"help"}, {"--help"}, {"-h"}} {
		code, out := helpOut(t, args...)
		if code != ExitOK {
			t.Fatalf("%v: code=%d", args, code)
		}
		if n := strings.Count(out, "\n"); n > 30 {
			t.Fatalf("%v: %d lines", args, n)
		}
		for _, want := range []string{"Check an upgrade:", "Prepare inputs:", "Knowledge:", "Other:", "Run 'prufyx <command> help' for details", "https://", "--strict-exit"} {
			if !strings.Contains(out, want) {
				t.Fatalf("%v: missing %q in %s", args, want, out)
			}
		}
		for _, g := range helpGroups {
			for _, e := range g.entries {
				if !strings.Contains(out, e.name) {
					t.Fatalf("missing command %s", e.name)
				}
			}
		}
		if strings.Contains(out, "\x1b") {
			t.Fatal("piped output has ESC")
		}
	}
}

func TestPerCommandHelpForms(t *testing.T) {
	t.Setenv("PRUFYX_COLOR", "never")
	for _, name := range []string{"scan", "assess", "prepare", "check", "catalog", "db", "version", "community-preview"} {
		_, want := helpOut(t, "help", name)
		if !strings.Contains(want, "prufyx "+name) || len(want) < 60 {
			t.Fatalf("%s: help=%q", name, want)
		}
		for _, flag := range []string{"help", "--help", "-h"} {
			code, got := helpOut(t, name, flag)
			if code != ExitOK || got != want {
				t.Fatalf("%s %s: code=%d differs", name, flag, code)
			}
		}
	}
	if _, out := helpOut(t, "check", "help"); !strings.Contains(out, "prufyx check cncf") || !strings.Contains(out, "Exit status for check batch") {
		t.Fatalf("check help lost usage lines: %s", out)
	}
	if code, _ := helpOut(t, "help", "nope"); code != ExitUsage {
		t.Fatalf("unknown command code=%d", code)
	}
}

func TestHelpHasNoMariaDBExamples(t *testing.T) {
	t.Setenv("PRUFYX_COLOR", "never")
	for _, args := range [][]string{nil, {"help", "scan"}, {"help", "assess"}, {"help", "prepare"}, {"help", "check"}, {"help", "catalog"}, {"help", "db"}, {"help", "community-preview"}, {"prepare", "project", "--help"}, {"check", "project", "--help"}, {"prepare", "cncf", "--help"}, {"check", "cncf", "--help"}} {
		if _, out := helpOut(t, args...); strings.Contains(strings.ToLower(out), "mariadb") {
			t.Fatalf("%v mentions mariadb", args)
		}
	}
}

func TestHelpColourRules(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		esc  bool
	}{
		{"piped default", map[string]string{}, false},
		{"always", map[string]string{"PRUFYX_COLOR": "always"}, true},
		{"always beats NO_COLOR", map[string]string{"PRUFYX_COLOR": "always", "NO_COLOR": "1"}, true},
		{"never", map[string]string{"PRUFYX_COLOR": "never"}, false},
		{"NO_COLOR", map[string]string{"NO_COLOR": "1", "PRUFYX_COLOR": ""}, false},
		{"dumb", map[string]string{"TERM": "dumb", "PRUFYX_COLOR": "auto"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, k := range []string{"PRUFYX_COLOR", "NO_COLOR", "TERM"} {
				t.Setenv(k, "")
			}
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			for _, args := range [][]string{nil, {"check", "help"}} {
				if _, out := helpOut(t, args...); strings.Contains(out, "\x1b") != c.esc {
					t.Fatalf("%v: esc=%v want %v", args, !c.esc, c.esc)
				}
			}
		})
	}
	t.Run("always with TERM=dumb", func(t *testing.T) {
		t.Setenv("TERM", "dumb")
		t.Setenv("PRUFYX_COLOR", "always")
		if _, out := helpOut(t); !strings.Contains(out, "\x1b[") {
			t.Fatal("always should force colour")
		}
	})
}
