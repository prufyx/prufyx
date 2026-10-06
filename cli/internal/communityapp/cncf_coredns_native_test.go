// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCoreDNSNativeCorefileRoute(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, raw, status string
		code              int
	}{
		{"direct federation", ".:53 {\n health\n ready\n federation\n cache 30\n}\n", "BLOCKED", ExitBlocked},
		{"realistic brace-body absence", ".:53 {\n health {\n  lameduck 5s\n }\n ready\n kubernetes cluster.local {\n  pods insecure\n }\n forward . 1.1.1.1 {\n  next federation\n }\n cache 30 {\n  success 9984\n }\n}\n", "PASS", ExitOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeCNCFFile(t, "Corefile", []byte(tc.raw), 0o600)
			args := []string{"check", "cncf", "--project", "coredns", "--coredns-corefile", path, "--coredns-corefile-digest", cncfDigest([]byte(tc.raw)), "--coredns-corefile-complete", "--coredns-distribution", "official", "--from", "1.13.2", "--to", "1.14.7", "--now", "2026-09-13T10:30:00Z", "--format", "json"}
			code, output, stderr := runCNCFCLI(t, args...)
			if code != tc.code || stderr != "" || !strings.Contains(output, `"status":"`+tc.status+`"`) || strings.Contains(output, path) || strings.Contains(output, "1.1.1.1") {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, output, stderr)
			}
		})
	}
}

func TestCoreDNSNativeCorefileUnknownBoundaries(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, raw string
	}{
		{"import", ". {\n import private-child\n}\n"},
		{"snippet", "(shared) {\n federation\n}\n. {\n import shared\n}\n"},
		{"substitution", ". {\n {$PRIVATE_PLUGIN}\n}\n"},
		{"quote", ". {\n forward . \"federation\"\n}\n"},
		{"unbalanced", ". {\n forward . 1.1.1.1\n"},
		{"direct followed by import", ". {\n federation\n import private-child\n}\n"},
		{"direct followed by unmatched brace", ". {\n federation\n"},
		{"direct followed by quote", ". {\n federation\n forward . \"private\"\n}\n"},
		{"direct followed by substitution", ". {\n federation\n {$PRIVATE_PLUGIN}\n}\n"},
		{"multiple opening braces", ". {\n forward . { {\n }\n}\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeCNCFFile(t, "Corefile", []byte(tc.raw), 0o600)
			code, output, stderr := runCNCFCLI(t, "check", "cncf", "--project", "coredns", "--coredns-corefile", path, "--coredns-corefile-complete", "--coredns-distribution", "official", "--from", "1.13.2", "--to", "1.14.7", "--now", "2026-09-13T10:30:00Z", "--format", "json")
			if code != ExitUnknown || stderr != "" || !strings.Contains(output, `"status":"UNKNOWN"`) || strings.Contains(output, path) || strings.Contains(output, "private") {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, output, stderr)
			}
		})
	}
}

func TestCoreDNSNativeCorefileGuardsAndClosedFlags(t *testing.T) {
	t.Parallel()
	raw := []byte(". {\n forward . 1.1.1.1\n}\n")
	path := writeCNCFFile(t, "Corefile", raw, 0o600)
	base := []string{"check", "cncf", "--project", "coredns", "--coredns-corefile", path, "--coredns-corefile-complete", "--coredns-distribution", "official", "--from", "1.13.2", "--to", "1.14.7", "--now", "2026-09-13T10:30:00Z", "--format", "json"}
	for _, tc := range []struct {
		name string
		args []string
		code int
	}{
		{"wrong pair", replaceCoreDNSArg(base, "1.13.2", "1.13.1"), ExitUnknown},
		{"custom distribution", replaceCoreDNSArg(base, "official", "custom"), ExitUnknown},
		{"missing complete", removeCoreDNSArg(base, "--coredns-corefile-complete"), ExitUnknown},
		{"bad pin", append(append([]string{}, base...), "--coredns-corefile-digest", "sha256:"+strings.Repeat("0", 64)), ExitIntegrity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runCNCFCLI(t, tc.args...)
			if code != tc.code || (tc.code == ExitIntegrity && stdout != "") || strings.Contains(stdout+stderr, path) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
	private := filepath.Join(t.TempDir(), "private-corefile")
	for _, args := range [][]string{
		{"check", "cncf", "--project", "thanos", "--input", private, "--coredns-corefile", private, "--now", "2026-09-13T10:30:00Z"},
		append(append([]string{}, base...), "--input", path),
	} {
		code, stdout, stderr := runCNCFCLI(t, args...)
		if code != ExitUsage || stdout != "" || strings.Contains(stdout+stderr, private) {
			t.Fatalf("closed flags code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	}
}

func TestCoreDNSCorefilePrepareRoute(t *testing.T) {
	t.Parallel()
	raw := []byte(".:53 {\n health\n federation\n}\n")
	path := writeCNCFFile(t, "Corefile", raw, 0o600)
	args := []string{"prepare", "cncf", "--project", "coredns", "--coredns-corefile", path, "--coredns-corefile-digest", cncfDigest(raw), "--coredns-corefile-complete", "--coredns-distribution", "official", "--from", "1.13.2", "--to", "1.14.7", "--format", "input"}
	code, canonical, stderr := runCNCFCLI(t, args...)
	if code != ExitOK || stderr != "" || !strings.Contains(canonical, `"id":"component.coredns.distribution","state":"declared","enumValue":"official"`) || !strings.Contains(canonical, `"id":"component.coredns.federation_directive_present","state":"declared","boolValue":true`) || strings.Contains(canonical, path) || strings.Contains(canonical, "health") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, canonical, stderr)
	}
	for _, extra := range [][]string{
		{"--input", path},
		{"--coredns-distribution", "official"},
		{"--cilium-config-map", path},
	} {
		code, stdout, stderr := runCNCFCLI(t, append(append([]string{}, args...), extra...)...)
		if code != ExitUsage || stdout != "" || strings.Contains(stdout+stderr, path) {
			t.Fatalf("extra=%q code=%d stdout=%q stderr=%q", extra, code, stdout, stderr)
		}
	}
}

func TestCoreDNSCorefileAuthorityGuardsMatchPrepareAndCheck(t *testing.T) {
	t.Parallel()
	raw := []byte(". {\n forward . 1.1.1.1\n}\n")
	path := writeCNCFFile(t, "Corefile", raw, 0o600)
	base := []string{"--project", "coredns", "--coredns-corefile", path, "--from", "1.13.2"}
	for _, tc := range []struct {
		name  string
		extra []string
		to    string
		want  int
	}{
		{"omitted completeness", []string{"--coredns-distribution", "official"}, "", ExitUnknown},
		{"false completeness", []string{"--coredns-distribution", "official", "--coredns-corefile-complete=false"}, "", ExitUnknown},
		{"missing distribution", []string{"--coredns-corefile-complete"}, "", ExitUnknown},
		{"custom distribution", []string{"--coredns-corefile-complete", "--coredns-distribution", "custom"}, "", ExitUnknown},
		{"wrong pair", []string{"--coredns-corefile-complete", "--coredns-distribution", "official"}, "1.14.6", ExitUnknown},
		{"bogus distribution", []string{"--coredns-corefile-complete", "--coredns-distribution", "bogus"}, "", ExitUsage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			to := tc.to
			if to == "" {
				to = "1.14.7"
			}
			prepareArgs := append(append([]string{"prepare", "cncf"}, base...), tc.extra...)
			prepareArgs = append(prepareArgs, "--to", to)
			prepareArgs = append(prepareArgs, "--format", "json")
			prepareCode, prepared, prepareErr := runCNCFCLI(t, prepareArgs...)
			checkArgs := append(append([]string{"check", "cncf"}, base...), tc.extra...)
			checkArgs = append(checkArgs, "--to", to)
			checkArgs = append(checkArgs, "--now", "2026-09-13T10:30:00Z", "--format", "json")
			checkCode, checked, checkErr := runCNCFCLI(t, checkArgs...)
			if prepareCode != tc.want || checkCode != tc.want || strings.Contains(prepared+prepareErr+checked+checkErr, path) {
				t.Fatalf("prepare=(%d,%q,%q) check=(%d,%q,%q)", prepareCode, prepared, prepareErr, checkCode, checked, checkErr)
			}
			if tc.want == ExitUnknown && (!strings.Contains(prepared, `"state":"UNKNOWN"`) || !strings.Contains(checked, `"status":"UNKNOWN"`)) {
				t.Fatalf("prepare=%q check=%q", prepared, checked)
			}
			if tc.want == ExitUsage && (prepared != "" || checked != "") {
				t.Fatalf("prepare=%q check=%q", prepared, checked)
			}
		})
	}
}

func TestCoreDNSCorefileExamples(t *testing.T) {
	t.Parallel()
	exampleRoot := filepath.Join("..", "..", "examples", "cncf", "coredns-corefile")
	for _, tc := range []struct {
		name, status string
		code         int
	}{
		{"blocked", "BLOCKED", ExitBlocked},
		{"fixed", "PASS", ExitOK},
		{"unknown", "UNKNOWN", ExitUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(exampleRoot, tc.name+".Corefile"))
			if err != nil {
				t.Fatal(err)
			}
			path := writeCNCFFile(t, "Corefile", raw, 0o600)
			code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "coredns", "--coredns-corefile", path, "--coredns-corefile-complete", "--coredns-distribution", "official", "--from", "1.13.2", "--to", "1.14.7", "--now", "2026-09-13T10:30:00Z", "--format", "json")
			if code != tc.code || stderr != "" || !strings.Contains(stdout, `"status":"`+tc.status+`"`) || strings.Contains(stdout, path) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

func replaceCoreDNSArg(args []string, old, new string) []string {
	result := append([]string{}, args...)
	for index, value := range result {
		if value == old {
			result[index] = new
			return result
		}
	}
	return result
}

func removeCoreDNSArg(args []string, value string) []string {
	result := make([]string, 0, len(args))
	for _, item := range args {
		if item != value {
			result = append(result, item)
		}
	}
	return result
}
