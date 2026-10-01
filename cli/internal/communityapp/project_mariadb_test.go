// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProjectCLIMariaDB_SyntheticExamples(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]int{"broken.cnf": ExitBlocked, "fixed.cnf": ExitOK, "unknown.cnf": ExitUnknown} {
		name, want := name, want
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			raw, err := os.ReadFile(filepath.Join("..", "..", "examples", "projects", "mariadb", name))
			if err != nil {
				t.Fatal(err)
			}
			path := writePrivateProjectFixture(t, string(raw))
			var stdout, stderr bytes.Buffer
			requirement := "false"
			if name == "broken.cnf" {
				requirement = "true"
			}
			exit := Run(t.Context(), []string{"check", "project", "--project", "mariadb", "--effective-config", path, "--from", "10.11.8", "--to", "11.4.2", "--effective-config-complete", "--precedence-resolved", "--upstream-distribution", "--require-innodb-defragmentation", requirement, "--now", "2026-09-12T12:00:00Z", "--format", "json"}, &stdout, &stderr, "test")
			if exit != want || stderr.Len() != 0 || strings.Contains(stdout.String(), path) || strings.Contains(stdout.String(), "synthetic-reader") {
				t.Fatalf("exit=%d want=%d stdout=%q stderr=%q", exit, want, stdout.String(), stderr.String())
			}
		})
	}
}

func TestProjectCLIMariaDB_BLOCKED_PASS_UNKNOWNAndPrivacy(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, body, requirement, omit string
		want                          int
		status                        string
	}{
		{"blocked-required-on", "[client]\nuser=private-user\n[mariadb]\ninnodb_defragment=ON\n", "true", "", ExitBlocked, "BLOCKED"},
		{"blocked-required-absent", "[server]\nmax_connections=17\n", "true", "", ExitBlocked, "BLOCKED"},
		{"pass-present-but-waived", "[mariadb]\ninnodb_defragment=ON\n", "false", "", ExitOK, "PASS"},
		{"pass-off-and-waived", "[mariadbd]\ninnodb_defragment=OFF\n", "false", "", ExitOK, "PASS"},
		{"include-unknown", "!includedir /private/mysql\n[mariadbd]\nmax_connections=17\n", "false", "", ExitUnknown, "UNKNOWN"},
		{"alias-unknown", "[server]\nloose_innodb_defragment=ON\n", "false", "", ExitUnknown, "UNKNOWN"},
		{"no-server-unknown", "[client]\nuser=private-user\n", "false", "", ExitUnknown, "UNKNOWN"},
		{"missing-intent-unknown", "[mariadb]\ninnodb_defragment=ON\n", "", "", ExitUnknown, "UNKNOWN"},
		{"incomplete-unknown", "[mariadb]\ninnodb_defragment=ON\n", "false", "complete", ExitUnknown, "UNKNOWN"},
		{"unbound-distribution-unknown", "[mariadb]\ninnodb_defragment=ON\n", "false", "distribution", ExitUnknown, "UNKNOWN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := writePrivateProjectFixture(t, tc.body)
			args := []string{"check", "project", "--project", "mariadb", "--effective-config", path, "--from", "10.11.8", "--to", "11.4.2", "--effective-config-complete", "--precedence-resolved", "--upstream-distribution", "--now", "2026-09-12T12:00:00Z", "--format", "json"}
			if tc.requirement != "" {
				args = append(args, "--require-innodb-defragmentation", tc.requirement)
			}
			if tc.omit == "complete" {
				args = removeArgument(args, "--effective-config-complete")
			}
			if tc.omit == "distribution" {
				args = removeArgument(args, "--upstream-distribution")
			}
			var stdout, stderr bytes.Buffer
			exit := Run(t.Context(), args, &stdout, &stderr, "test")
			if exit != tc.want || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"status":"`+tc.status+`"`) {
				t.Fatalf("exit=%d want=%d stdout=%q stderr=%q", exit, tc.want, stdout.String(), stderr.String())
			}
			for _, private := range []string{path, "private-user", "/private/mysql", "max_connections=17", "innodb_defragment=ON"} {
				if strings.Contains(stdout.String()+stderr.String(), private) {
					t.Fatalf("private MariaDB input leaked: %q", private)
				}
			}
		})
	}
}

func TestProjectCLIMariaDB_FreshnessAndExactSourceScope(t *testing.T) {
	t.Parallel()
	path := writePrivateProjectFixture(t, "[mariadbd]\ninnodb_defragment=ON\n")
	for _, tc := range []struct {
		name, now string
		want      int
		contains  string
	}{
		{"active", "2026-09-12T12:00:00Z", ExitBlocked, "mariadb-v11-4-2-removed-option-handler"},
		{"stale", "2026-12-11T12:00:00Z", ExitUnknown, "RULE_EVIDENCE_STALE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			exit := Run(t.Context(), []string{"check", "project", "--project", "mariadb", "--effective-config", path, "--from", "10.11.8", "--to", "11.4.2", "--effective-config-complete", "--precedence-resolved", "--upstream-distribution", "--require-innodb-defragmentation", "true", "--now", tc.now, "--format", "json"}, &stdout, &stderr, "test")
			if exit != tc.want || stderr.Len() != 0 || !strings.Contains(stdout.String(), tc.contains) || strings.Contains(stdout.String(), path) {
				t.Fatalf("exit=%d want=%d stdout=%q stderr=%q", exit, tc.want, stdout.String(), stderr.String())
			}
		})
	}
}

func TestProjectCLIMariaDB_RejectsDistributionFlagForOtherProjects(t *testing.T) {
	t.Parallel()
	path := writePrivateProjectFixture(t, "[unified_alerting]\nenabled=true\n")
	var stdout, stderr bytes.Buffer
	exit := Run(t.Context(), []string{"check", "project", "--project", "grafana", "--effective-config", path, "--from", "10.4.0", "--to", "11.0.0", "--effective-config-complete", "--precedence-resolved", "--upstream-distribution", "--require-innodb-defragmentation", "false", "--now", "2026-09-12T12:00:00Z"}, &stdout, &stderr, "test")
	if exit != ExitUsage || strings.Contains(stdout.String()+stderr.String(), path) {
		t.Fatalf("exit=%d stdout=%q stderr=%q", exit, stdout.String(), stderr.String())
	}
}

func removeArgument(args []string, remove string) []string {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		if arg != remove {
			out = append(out, arg)
		}
	}
	return out
}
