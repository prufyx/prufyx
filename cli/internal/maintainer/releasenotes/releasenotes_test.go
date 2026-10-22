// SPDX-License-Identifier: AGPL-3.0-only

package releasenotes

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

const readmeTmpl = "# Prufyx\n\n<!-- coverage:begin -->\nGenerated on %DATE% by `scripts/readme-coverage.sh` (do not edit this block by hand).\n\n" +
	"Version-coverage depth, measured over the last five minor upgrades of each of the %PROJ% projects with a release-line snapshot (%PAIRS% upgrades between consecutive release lines):\n\n" +
	"| Status | Upgrades | Share |\n| --- | --- | --- |\n" +
	"| Decided for the whole release-line pair (A attested, B bounded) | %AB% | 3% |\n" +
	"| Rule for one exact version pair only (S) | %S% | 10.7% |\n" +
	"| Gap, no valid rule (G) | %G% | 86.1% |\n\n<!-- coverage:end -->\n"

func readme(date, proj, pairs, ab, s, g string) string {
	r := strings.NewReplacer("%DATE%", date, "%PROJ%", proj, "%PAIRS%", pairs, "%AB%", ab, "%S%", s, "%G%", g)
	return r.Replace(readmeTmpl)
}

func fixtureRules(entries string, lines string) string {
	return `{"entries":[` + entries + `],"lineAttestations":[` + lines + `]}`
}

func entry(project, id string) string {
	return `{"project":"` + project + `","rule":{"id":"` + id + `"}}`
}

func att(component, line string) string {
	return `{"component":"pkg:github/` + component + `","line":"` + line + `"}`
}

const k8s = "kubernetes/kubernetes"

func fromFiles() map[string]string {
	return map[string]string{
		cncfRulesPath: fixtureRules(strings.Join([]string{entry("a", "a.1"), entry("a", "a.2"), entry("b", "b.1")}, ","),
			strings.Join([]string{att(k8s, "1.36"), att("x/lib", "1.9")}, ",")),
		projectRulesPath: fixtureRules("", ""),
		inventoryPath: `{"counts":{"selectedSourceProjects":2,"selectedSourceOnlyProjects":0,"executableProjects":2,"cncfSourceRules":3,"cncfRuleProjects":2,"communityProjectSourceRules":0,"communityProjectRuleProjects":0},
"projects":[{"projectID":"a","displayName":"A","supportState":"executable"},{"projectID":"b","displayName":"B","supportState":"selected_source_only"}],"withdrawnRules":[]}`,
		readmePath: readme("2026-10-08", "70", "350", "10", "40", "300"),
	}
}

func toFiles() map[string]string {
	return map[string]string{
		cncfRulesPath: fixtureRules(strings.Join([]string{entry("a", "a.1"), entry("a", "a.3"), entry("b", "b.1"), entry("c", "c.1"), entry("c", "c.2")}, ","),
			strings.Join([]string{att(k8s, "1.36"), att(k8s, "1.37"), att("x/lib", "1.9"), att("x/lib", "1.10")}, ",")),
		projectRulesPath: fixtureRules(entry("d", "d.1"), ""),
		inventoryPath: `{"counts":{"selectedSourceProjects":5,"selectedSourceOnlyProjects":1,"executableProjects":4,"cncfSourceRules":4,"cncfRuleProjects":3,"communityProjectSourceRules":1,"communityProjectRuleProjects":1},
"projects":[{"projectID":"a","displayName":"A","supportState":"executable"},{"projectID":"b","displayName":"B","supportState":"executable_with_selected_source_records"},
{"projectID":"c","displayName":"C","supportState":"executable"},{"projectID":"d","displayName":"D","supportState":"executable"},{"projectID":"e","displayName":"E","supportState":"selected_source_only"}],
"withdrawnRules":[{"ruleID":"a.3"}]}`,
		readmePath: readme("2026-10-20", "78", "390", "12", "42", "336"),
		onboardingDir + "/ob-1.json": `{"schema":"s","record":{"batchId":"ob-1","decision":"approve","projects":[
{"slug":"dex","catalog":"cncf","kind":"new","proof":{"pair":{"fromTag":"v2.45.0","toTag":"v2.46.0"}}},
{"slug":"k8up","catalog":"cncf","kind":"new","proof":{"pair":{"fromTag":"v2.15.0","toTag":"v2.16.0"}}}]}}`,
		onboardingDir + "/ob-2.json": `{"schema":"s","record":{"batchId":"ob-2","decision":"reject","projects":[
{"slug":"zed","catalog":"community","kind":"new","proof":{"pair":{"fromTag":"v1","toTag":"v2"}}}]}}`,
	}
}

func render(t *testing.T, from, to map[string]string) string {
	t.Helper()
	a, err := ReadSnapshot(DirTree{writeTree(t, from)})
	if err != nil {
		t.Fatal(err)
	}
	b, err := ReadSnapshot(DirTree{writeTree(t, to)})
	if err != nil {
		t.Fatal(err)
	}
	return Render(a, b, Options{FromLabel: "v1", ToLabel: "main", PRs: []PR{{Number: 7, Title: "Add thing"}, {Title: "Merge branch 'x'"}}})
}

func TestRenderFixtureTrees(t *testing.T) {
	out := render(t, fromFiles(), toFiles())
	for _, want := range []string{
		"| Projects with at least one executable check | 2 | 4 | +2 |",
		"| Projects catalogued with retained public sources | 2 | 5 | +3 |",
		"| CNCF source rules, active | 3 | 4 | +1 |",
		"| Line attestations | 2 | 4 | +2 |",
		"| Kubernetes minors with a line attestation | 1 | 2 | +1 |",
		"| Decided for the whole release-line pair (A+B) | 10 | 12 | +2 |",
		"| Gap, no valid rule (G) | 300 | 336 | +36 |",
		"| Upgrades between consecutive release lines | 350 | 390 | +40 |",
		"generated on 2026-10-08 (v1) and 2026-10-20 (main)",
		"### Projects added to the catalogue (3)",
		"- `c` (C): executable check",
		"- `e` (E): source-only, no check",
		"### Catalogued projects that gained their first executable check (1)\n\n- `b` (B)",
		"### Rules by project (4 added, 1 removed)",
		"| CNCF | `a` | 1 | 1 | 2 |",
		"| CNCF | `c` | 2 | 0 | 2 |",
		"| community-project | `d` | 1 | 0 | 1 |",
		"### Rules newly withdrawn (1)\n\n- `a.3`",
		"- `x/lib`: 2 now; new lines 1.10",
		"- `kubernetes/kubernetes`: 2 now; new lines 1.37",
		"Lines with a line attestation (2): 1.36, 1.37. New since `v1`: 1.37.",
		"### Onboarding batches (1 approved, 2 project entries)",
		"- batch `ob-1`, decision `approve`:\n  - `dex` (cncf, new): proof pair v2.45.0 to v2.46.0",
		"- batch `ob-2`, decision `reject`:",
		"- #7 Add thing\n- Merge branch 'x'",
		"decided is not safe",
		"A catalogued project is not tested coverage",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "does not exist") {
		t.Errorf("unexpected missing-file note:\n%s", out)
	}
	if again := render(t, fromFiles(), toFiles()); again != out {
		t.Error("output is not deterministic")
	}
}

func TestRenderEmptyFromTree(t *testing.T) {
	out := render(t, map[string]string{"unrelated": "x"}, toFiles())
	for _, want := range []string{
		"`" + cncfRulesPath + "` does not exist in `v1`; it counts as empty there.",
		"`" + readmePath + "` does not exist in `v1`",
		"| Projects with at least one executable check | n/a | n/a | n/a |",
		"| Decided for the whole release-line pair (A+B) | n/a | n/a | n/a |",
		"The release-line figures (A+B, S, G) are n/a",
		"### Projects added to the catalogue (5)",
		"### Rules by project (6 added, 0 removed)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q\n%s", want, out)
		}
	}
}

func TestRenderNoChange(t *testing.T) {
	out := render(t, toFiles(), toFiles())
	for _, want := range []string{
		"### Projects added to the catalogue (0)\n\nNo project was added.",
		"No rule was added or removed.",
		"### Onboarding batches (0 approved, 0 project entries)",
		"No line attestation was added or removed.",
		"| Projects with at least one executable check | 4 | 4 | 0 |",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q\n%s", want, out)
		}
	}
}

func TestReadSnapshotRejectsBadData(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"bad json":          {cncfRulesPath: "{"},
		"rule without id":   {cncfRulesPath: `{"entries":[{"project":"a","rule":{}}]}`},
		"batch without id":  {onboardingDir + "/x.json": `{"record":{}}`},
		"inventory garbage": {inventoryPath: `[]`},
	} {
		if _, err := ReadSnapshot(DirTree{writeTree(t, files)}); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestParseDepthRefusesRewordedBlock(t *testing.T) {
	if parseDepth(readme("2026-10-08", "1", "2", "3", "4", "5")) == nil {
		t.Fatal("well-formed block not parsed")
	}
	for _, bad := range []string{
		"",
		strings.Replace(readme("2026-10-08", "1", "2", "3", "4", "5"), "Gap, no valid rule", "Gap", 1),
		strings.Replace(readme("2026-10-08", "1", "2", "3", "4", "5"), "<!-- coverage:end -->", "", 1),
		strings.Replace(readme("2026-10-08", "1", "2", "3", "4", "5"), "Generated on", "Made on", 1),
	} {
		if parseDepth(bad) != nil {
			t.Errorf("parsed a reworded block: %q", bad)
		}
	}
}

func TestLineOrder(t *testing.T) {
	got := sortedLines(map[string]bool{"1.10": true, "1.9": true, "0.50": true, "1.2": true, "1.1": true})
	if want := "0.50 1.1 1.2 1.9 1.10"; strings.Join(got, " ") != want {
		t.Errorf("order = %v, want %s", got, want)
	}
}

func TestParsePRs(t *testing.T) {
	log := "Merge pull request #12 from prufyx/feat/x\x1f\nAdd the thing\n\nMore text\x1e\n" +
		"Merge pull request #13 from prufyx/feat/y\x1f\x1e\n" +
		"Merge branch 'main' of somewhere\x1f\x1e\n"
	got := parsePRs(log)
	want := []PR{{12, "Add the thing"}, {13, "Merge pull request #13 from prufyx/feat/y"}, {0, "Merge branch 'main' of somewhere"}}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("pr %d = %v, want %v", i, got[i], want[i])
		}
	}
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=T", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestGitTreesAndMergedPRs(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	repo := writeTree(t, fromFiles())
	git(t, repo, "init", "-q", "-b", "main")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-q", "-m", "base")
	git(t, repo, "tag", "-a", "v1", "-m", "v1")
	git(t, repo, "checkout", "-q", "-b", "feat")
	for name, content := range toFiles() {
		p := filepath.Join(repo, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-q", "-m", "data")
	git(t, repo, "checkout", "-q", "main")
	git(t, repo, "merge", "-q", "--no-ff", "feat", "-m", "Merge pull request #5 from prufyx/feat\n\nOnboard project c")

	a, err := ReadSnapshot(GitTree{Repo: repo, Rev: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := ReadSnapshot(GitTree{Repo: repo, Rev: "HEAD"})
	if err != nil {
		t.Fatal(err)
	}
	want := render(t, fromFiles(), toFiles())
	prs, err := MergedPRs(repo, "v1", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if len(prs) != 1 || prs[0] != (PR{5, "Onboard project c"}) {
		t.Fatalf("prs = %v", prs)
	}
	got := Render(a, b, Options{FromLabel: "v1", ToLabel: "main", PRs: []PR{{Number: 7, Title: "Add thing"}, {Title: "Merge branch 'x'"}}})
	if got != want {
		t.Errorf("git trees and directory trees disagree:\n%s", got)
	}

	if _, err := (GitTree{Repo: repo, Rev: "nope"}).Read(readmePath); err == nil {
		t.Error("unknown revision accepted")
	}
	if _, err := (GitTree{Repo: repo, Rev: "-x"}).Read(readmePath); err == nil {
		t.Error("option-shaped revision accepted")
	}
	if _, err := (GitTree{Repo: repo, Rev: "v1"}).Read("missing"); err == nil || !isNotExist(err) {
		t.Errorf("missing path error = %v", err)
	}
	if names, err := (GitTree{Repo: repo, Rev: "v1"}).List(onboardingDir); err != nil || len(names) != 0 {
		t.Errorf("v1 onboarding = %v, %v", names, err)
	}
	if names, err := (GitTree{Repo: repo, Rev: "HEAD"}).List(onboardingDir); err != nil || len(names) != 2 {
		t.Errorf("HEAD onboarding = %v, %v", names, err)
	}
	if _, err := MergedPRs(repo, "-x", "HEAD"); err == nil {
		t.Error("option-shaped revision accepted by MergedPRs")
	}
}

func isNotExist(err error) bool { return strings.Contains(err.Error(), fs.ErrNotExist.Error()) }
