// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// ciDownloadProblems checks the supply-chain shape of the release-binary
// downloads in ci.yml: every curl fails on HTTP errors (an error page must
// never become a file), retries, is bounded in time and writes to a named
// file; every downloaded archive is checked against its pinned digest before
// it is extracted; the secret scan stays a gating step.
func ciDownloadProblems(raw []byte) []string {
	return ciDownloadProblemsFor(raw, ciVerifiedDownloads)
}

// ciVerifiedDownloads are the only two network downloads allowed in a run
// step, compared as exact whole lines (no leading space, no prefix, no pipe).
var ciVerifiedDownloads = []string{
	`curl --fail --silent --show-error --location --retry 5 --retry-all-errors --retry-delay 15 --connect-timeout 20 --max-time 180 --retry-max-time 300 -o staticcheck_linux_amd64.tar.gz "https://github.com/dominikh/go-tools/releases/download/${STATICCHECK_VERSION}/staticcheck_linux_amd64.tar.gz"`,
	`curl --fail --silent --show-error --location --retry 5 --retry-all-errors --retry-delay 15 --connect-timeout 20 --max-time 180 --retry-max-time 300 -o "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"`,
}

// ciDownloadTool matches a curl or wget token anywhere in a run step: command
// substitutions, pipes, sh -c strings, env prefixes, absolute paths.
var ciDownloadTool = regexp.MustCompile(`\b(curl|wget)\b`)

func ciDownloadProblemsFor(raw []byte, verified []string) []string {
	var wf ciWorkflowFile
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		return []string{"ci.yml does not parse: " + err.Error()}
	}
	var problems []string
	sawGitleaksInstall, sawScan := false, false
	for jobID, job := range wf.Jobs {
		for _, st := range job.Steps {
			lines := strings.Split(st.Run, "\n")
			curlSeen := false
			for _, ln := range lines {
				if ciDownloadTool.MatchString(ln) && !slices.Contains(verified, ln) {
					problems = append(problems, jobID+": download tool outside the verified downloads: "+strings.TrimSpace(ln))
				}
				t := strings.TrimSpace(ln)
				if !strings.HasPrefix(t, "curl ") {
					continue
				}
				curlSeen = true
				for _, need := range []string{"--fail", "--retry 5", "--retry-all-errors", "--connect-timeout", "--max-time", "--retry-max-time 300", " -o "} {
					if !strings.Contains(t, need) {
						problems = append(problems, jobID+": curl without "+strings.TrimSpace(need)+": "+t)
					}
				}
			}
			if curlSeen {
				verify, extract := strings.Index(st.Run, "sha256sum -c -"), strings.Index(st.Run, "tar -x")
				if verify < 0 {
					problems = append(problems, jobID+": downloaded archive is not digest-checked")
				} else if extract >= 0 && extract < verify {
					problems = append(problems, jobID+": archive extracted before the digest check")
				}
				if strings.Contains(st.Run, "gitleaks_") {
					sawGitleaksInstall = true
				}
			}
			if strings.TrimSpace(st.Run) == "gitleaks dir ." {
				sawScan = true
				if ciSoftFail(st.ContinueOnError) {
					problems = append(problems, jobID+": the secret scan is soft-fail")
				}
			}
		}
		if ciSoftFail(job.ContinueOnError) && job.Name == "Secret scan (gitleaks)" {
			problems = append(problems, jobID+": the secret-scan job is soft-fail")
		}
	}
	if !sawGitleaksInstall {
		problems = append(problems, "no digest-checked gitleaks download step found")
	}
	if !sawScan {
		problems = append(problems, "the gitleaks dir scan step is missing")
	}
	return problems
}

func TestCIDownloadsFailClosed(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ciDownloadProblems(raw) {
		t.Error(p)
	}
}

func TestCIDownloadGuardRejectsWeakening(t *testing.T) {
	const flags = "--fail --silent --show-error --location --retry 5 --retry-all-errors --retry-delay 15 --connect-timeout 20 --max-time 180 --retry-max-time 300"
	build := func(curl, verify, extract, scan, scanExtra string) []byte {
		return []byte("jobs:\n  s:\n    name: Secret scan (gitleaks)\n    steps:\n" +
			"      - run: |\n          " + curl + "\n          " + verify + "\n          " + extract + "\n          gitleaks_x\n" +
			"      - run: " + scan + "\n" + scanExtra)
	}
	curl := "curl " + flags + " -o gitleaks_x.tgz https://example.invalid/x"
	verify := `echo "${D}  gitleaks_x.tgz" | sha256sum -c -`
	extract := "tar -xzf gitleaks_x.tgz gitleaks"
	if got := ciDownloadProblemsFor(build(curl, verify, extract, "gitleaks dir .", ""), []string{curl}); len(got) != 0 {
		t.Fatalf("good shape rejected: %v", got)
	}
	cases := map[string][]byte{
		"curl without --fail":   build(strings.Replace(curl, "--fail ", "", 1), verify, extract, "gitleaks dir .", ""),
		"curl -sSLO form":       build("curl -sSLO https://example.invalid/x", verify, extract, "gitleaks dir .", ""),
		"no retry":              build(strings.Replace(curl, "--retry-all-errors ", "", 1), verify, extract, "gitleaks dir .", ""),
		"no max-time":           build(strings.Replace(curl, "--max-time 180", "", 1), verify, extract, "gitleaks dir .", ""),
		"no digest check":       build(curl, "true", extract, "gitleaks dir .", ""),
		"extract before verify": build(curl, extract, verify, "gitleaks dir .", ""),
		"scan step removed":     build(curl, verify, extract, "true", ""),
		"scan step soft-fail":   build(curl, verify, extract, "gitleaks dir .", ""),
		"scan job soft-fail":    nil,
	}
	cases["scan step soft-fail"] = []byte(strings.Replace(string(build(curl, verify, extract, "gitleaks dir .", "")), "      - run: gitleaks dir .\n", "      - run: gitleaks dir .\n        continue-on-error: true\n", 1))
	cases["scan job soft-fail"] = []byte(strings.Replace(string(build(curl, verify, extract, "gitleaks dir .", "")), "    name: Secret scan (gitleaks)\n", "    name: Secret scan (gitleaks)\n    continue-on-error: true\n", 1))
	for name, raw := range cases {
		if len(ciDownloadProblemsFor(raw, []string{curl})) == 0 {
			t.Errorf("%s: guard accepted a weakened workflow", name)
		}
	}
}

// Any curl or wget token inside a run step that is not exactly one of the
// verified downloads must fail the guard.
func TestCIDownloadGuardRejectsOtherDownloaders(t *testing.T) {
	const flags = "--fail --silent --show-error --location --retry 5 --retry-all-errors --retry-delay 15 --connect-timeout 20 --max-time 180 --retry-max-time 300"
	curl := "curl " + flags + " -o gitleaks_x.tgz https://example.invalid/x"
	verify := `echo "${D}  gitleaks_x.tgz" | sha256sum -c -`
	build := func(extra string) []byte {
		return []byte("jobs:\n  s:\n    name: Secret scan (gitleaks)\n    steps:\n" +
			"      - run: |\n          " + curl + "\n          " + verify + "\n          tar -xzf gitleaks_x.tgz gitleaks\n          gitleaks_x\n" +
			"      - run: |\n          " + extra + "\n" +
			"      - run: gitleaks dir .\n")
	}
	if got := ciDownloadProblemsFor(build("true"), []string{curl}); len(got) != 0 {
		t.Fatalf("good shape rejected: %v", got)
	}
	for name, extra := range map[string]string{
		"third download via wget":     "wget -O x.tgz https://example.invalid/y",
		"command substitution":        `X="$(curl -s https://example.invalid/y)"`,
		"curl piped to sh":            "curl -sSL https://example.invalid/i.sh | sh",
		"leading space":               " curl " + flags + " -o gitleaks_x.tgz https://example.invalid/x",
		"env prefix":                  "FOO=1 curl " + flags + " -o gitleaks_x.tgz https://example.invalid/x",
		"sh -c":                       `sh -c "curl -s https://example.invalid/y -o z"`,
		"verified curl plus pipe":     curl + " | sh",
		"verified curl plus trailing": curl + " && curl https://example.invalid/y",
		"absolute path":               "/usr/bin/curl https://example.invalid/y",
		"wget in pipe":                "echo x | wget -qO- https://example.invalid/y",
		"different url same flags":    "curl " + flags + " -o gitleaks_x.tgz https://example.invalid/other",
	} {
		if len(ciDownloadProblemsFor(build(extra), []string{curl})) == 0 {
			t.Errorf("%s: guard accepted an unverified download", name)
		}
	}
}

// Dropping --retry-max-time from either real download must fail the guard,
// even when the weakened line is otherwise accepted as the verified form.
func TestCIDownloadGuardRealFileMutations(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range ciVerifiedDownloads {
		if strings.Count(string(raw), want) != 1 {
			t.Fatalf("verified download %d not found exactly once in ci.yml", i)
		}
		weak := strings.Replace(want, " --retry-max-time 300", "", 1)
		mut := []byte(strings.Replace(string(raw), want, weak, 1))
		if len(ciDownloadProblems(mut)) == 0 {
			t.Errorf("download %d: dropping --retry-max-time accepted", i)
		}
		// flag check alone (exact-form allow-list widened to the weak line)
		if len(ciDownloadProblemsFor(mut, []string{ciVerifiedDownloads[1-i], weak})) == 0 {
			t.Errorf("download %d: flag check does not catch missing --retry-max-time", i)
		}
	}
}
