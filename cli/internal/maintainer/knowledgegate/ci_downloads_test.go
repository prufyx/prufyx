// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"os"
	"path/filepath"
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
				t := strings.TrimSpace(ln)
				if !strings.HasPrefix(t, "curl ") {
					continue
				}
				curlSeen = true
				for _, need := range []string{"--fail", "--retry 5", "--retry-all-errors", "--connect-timeout", "--max-time", " -o "} {
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
	const flags = "--fail --silent --show-error --location --retry 5 --retry-all-errors --retry-delay 15 --connect-timeout 20 --max-time 180"
	build := func(curl, verify, extract, scan, scanExtra string) []byte {
		return []byte("jobs:\n  s:\n    name: Secret scan (gitleaks)\n    steps:\n" +
			"      - run: |\n          " + curl + "\n          " + verify + "\n          " + extract + "\n          gitleaks_x\n" +
			"      - run: " + scan + "\n" + scanExtra)
	}
	curl := "curl " + flags + " -o gitleaks_x.tgz https://example.invalid/x"
	verify := `echo "${D}  gitleaks_x.tgz" | sha256sum -c -`
	extract := "tar -xzf gitleaks_x.tgz gitleaks"
	if got := ciDownloadProblems(build(curl, verify, extract, "gitleaks dir .", "")); len(got) != 0 {
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
		if len(ciDownloadProblems(raw)) == 0 {
			t.Errorf("%s: guard accepted a weakened workflow", name)
		}
	}
}
