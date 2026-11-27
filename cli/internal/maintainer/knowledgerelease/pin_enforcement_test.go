// SPDX-License-Identifier: AGPL-3.0-only

package knowledgerelease

// Holding tests for what enforces the pin proof: the CI step and the code
// owners. They live here because a code owner covers this directory.

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgepinguard"
	"gopkg.in/yaml.v3"
)

const (
	pinStepName      = "Pinned client and client floors"
	pinStepCondition = "${{ matrix.group == 'core-commands' }}"
)

type pinCIStep struct {
	Name             string            `yaml:"name"`
	If               string            `yaml:"if"`
	Run              string            `yaml:"run"`
	Shell            string            `yaml:"shell"`
	WorkingDirectory string            `yaml:"working-directory"`
	ContinueOnError  any               `yaml:"continue-on-error"`
	Env              map[string]string `yaml:"env"`
}

// pinCIJobs decodes only the job names: other jobs use expression shapes.
type pinCIJobs struct {
	Jobs map[string]yaml.Node `yaml:"jobs"`
}

type pinCIJob struct {
	If              string `yaml:"if"`
	Needs           any    `yaml:"needs"`
	ContinueOnError any    `yaml:"continue-on-error"`
	Strategy        struct {
		Matrix struct {
			Include []struct {
				Group string `yaml:"group"`
			} `yaml:"include"`
		} `yaml:"matrix"`
	} `yaml:"strategy"`
	Steps []pinCIStep `yaml:"steps"`
}

// pinStepTests are the tests the step names, each of which must pass in it.
var pinStepTests = map[string]string{
	"TestOldestSupportedClientPinProof":                   "internal/cncfcheck",
	"TestListedFamilyFloorIsAboveTheOtherFloorsAndThePin": "internal/cncfcheck",
	"TestListedFamilyFloorAgainstTheRealTags":             "internal/cncfcheck",
	"TestProviderFactsAreNotPublishable":                  "internal/cncfcheck",
	"TestOldestClientRefusesListedFamilyTooNew":           "internal/maintainer/knowledgerelease",
	"TestOldestClientRefusesOptInTooNew":                  "internal/maintainer/knowledgerelease",
	"TestWriteFloorFixtures":                              "internal/maintainer/knowledgerelease",
	"TestPinnedClientAdmitsReachedFloors":                 "internal/maintainer/knowledgerelease",
	"TestAdmitCheckRefusesClientLackingFeature":           "internal/maintainer/knowledgerelease",
}

func pinStep(raw []byte) (pinCIStep, []string) {
	var wf pinCIJobs
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		return pinCIStep{}, []string{err.Error()}
	}
	node, ok := wf.Jobs["test-core"]
	if !ok {
		return pinCIStep{}, []string{"no test-core job"}
	}
	var job pinCIJob
	if err := node.Decode(&job); err != nil {
		return pinCIStep{}, []string{err.Error()}
	}
	var problems []string
	if job.If != "" || job.ContinueOnError != nil || job.Needs != nil {
		problems = append(problems, "test-core must run unconditionally and fail on a failure")
	}
	group := false
	for _, include := range job.Strategy.Matrix.Include {
		group = group || include.Group == "core-commands"
	}
	if !group {
		problems = append(problems, "test-core has no core-commands group")
	}
	var found []pinCIStep
	for _, step := range job.Steps {
		if step.Name == pinStepName {
			found = append(found, step)
		}
	}
	if len(found) != 1 {
		return pinCIStep{}, append(problems, "test-core needs exactly one step "+pinStepName)
	}
	return found[0], problems
}

// pinStepProblems lists every way the workflow no longer runs the proof.
func pinStepProblems(raw []byte) []string {
	step, problems := pinStep(raw)
	if step.If != pinStepCondition || step.ContinueOnError != nil || step.Shell != "" || step.WorkingDirectory != "cli" || len(step.Env) != 0 {
		problems = append(problems, "the step's condition, directory, shell, environment or failure handling changed")
	}
	legacyRef, _, err := knowledgepinguard.ParsePin([]byte(knowledgepinguard.LegacyPin))
	if err != nil {
		return append(problems, err.Error())
	}
	lines := map[string]bool{}
	for _, line := range strings.Split(step.Run, "\n") {
		lines[strings.TrimSpace(line)] = true
	}
	for _, line := range []string{
		"set -euo pipefail",
		`legacy_ref="` + legacyRef + `"`,
		`source_of "${legacy_ref}" "${work}/legacy"`,
		`source_of HEAD "${work}/head"`,
		`write_fixtures "${work}/head" "${work}/head-fixtures"`,
		`if ! printf 'ref=%s\nversion=` + knowledgepinguard.LegacyVersion + `\n' "${legacy_ref}" | cmp -s - "${pin}"; then`,
		`source_of "${ref#ref=}" "${work}/pinned"`,
		`write_fixtures "${work}/pinned" "${work}/pinned-fixtures"`,
		`require_pass "${work}/pin-proof.log" TestOldestSupportedClientPinProof TestListedFamilyFloorIsAboveTheOtherFloorsAndThePin TestListedFamilyFloorAgainstTheRealTags TestProviderFactsAreNotPublishable`,
		`require_pass "${work}/legacy.log" TestOldestClientRefusesListedFamilyTooNew TestOldestClientRefusesOptInTooNew`,
		`require_pass "$2.log" TestWriteFloorFixtures`,
		`require_pass "${work}/head.log" TestPinnedClientAdmitsReachedFloors TestAdmitCheckRefusesClientLackingFeature`,
		`require_pass "${work}/pinned.log" TestPinnedClientAdmitsReachedFloors`,
		`grep -qE "^--- PASS: ${name} \(" "${log}" || { echo "::error::${name} did not pass" >&2; exit 1; }`,
	} {
		if !lines[line] {
			problems = append(problems, "the step lacks the line: "+line)
		}
	}
	if strings.Contains(step.Run, "|| true") || strings.Contains(step.Run, "set +") {
		problems = append(problems, "the step swallows a failure")
	}
	for _, line := range strings.Split(step.Run, "\n") {
		if strings.Contains(line, "go test") && (!strings.Contains(line, " -count=1 ") || !strings.Contains(line, " -v ") || !strings.Contains(line, " -run '^")) {
			problems = append(problems, "every test run needs -count=1, -v and an anchored -run: "+strings.TrimSpace(line))
		}
	}
	return problems
}

func repositoryFile(t *testing.T, parts ...string) []byte {
	t.Helper()
	root := filepath.Join("..", "..", "..", "..")
	if _, err := os.Stat(filepath.Join(root, ".github")); os.IsNotExist(err) {
		t.Skip("no .github directory: staged release source tree")
	}
	raw, err := os.ReadFile(filepath.Join(append([]string{root}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCIHoldsThePinStep(t *testing.T) {
	raw := repositoryFile(t, ".github", "workflows", "ci.yml")
	if p := pinStepProblems(raw); len(p) != 0 {
		t.Fatalf("ci.yml:\n%s", strings.Join(p, "\n"))
	}
	for name, pkg := range pinStepTests {
		files, err := filepath.Glob(filepath.Join("..", "..", "..", filepath.FromSlash(pkg), "*_test.go"))
		if err != nil {
			t.Fatal(err)
		}
		declared := 0
		for _, file := range files {
			source, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			declared += len(regexp.MustCompile(`(?m)^func `+name+`\(t \*testing\.T\)`).FindAll(source, -1))
		}
		if declared != 1 {
			t.Errorf("%s is declared %d times in %s", name, declared, pkg)
		}
	}
	text := string(raw)
	for name, edit := range map[string][2]string{
		"condition removed":    {"        if: " + pinStepCondition + "\n        working-directory: cli\n        run: |\n          set -euo pipefail\n          pin=", "        if: false\n        working-directory: cli\n        run: |\n          set -euo pipefail\n          pin="},
		"another legacy ref":   {`legacy_ref="0a58`, `legacy_ref="1a58`},
		"a test not required":  {` TestAdmitCheckRefusesClientLackingFeature` + "\n", "\n"},
		"cached":               {"-count=1 -run '^TestPinnedClientAdmitsReachedFloors$'", "-run '^TestPinnedClientAdmitsReachedFloors$'"},
		"failure swallowed":    {`require_pass "${work}/pinned.log" TestPinnedClientAdmitsReachedFloors`, `require_pass "${work}/pinned.log" TestPinnedClientAdmitsReachedFloors || true`},
		"no head run":          {`source_of HEAD "${work}/head"`, `source_of "${legacy_ref}" "${work}/head"`},
		"continue on error":    {"      - name: " + pinStepName + "\n", "      - name: " + pinStepName + "\n        continue-on-error: true\n"},
		"step renamed":         {"      - name: " + pinStepName + "\n", "      - name: Other\n"},
		"group renamed":        {"          - group: core-commands\n", "          - group: core-other\n"},
		"job made conditional": {"  test-core:\n", "  test-core:\n    if: false\n"},
	} {
		changed := strings.Replace(text, edit[0], edit[1], 1)
		if changed == text {
			t.Fatalf("setup: %s changes nothing", name)
		}
		if p := pinStepProblems([]byte(changed)); len(p) == 0 {
			t.Errorf("%s accepted", name)
		}
	}
}

// The step's script itself, run with stand-ins for go and git: it succeeds only
// when every named test prints its pass line, and runs the pinned client for a
// pin other than the legacy one.
func TestPinStepScriptRequiresEveryPassLine(t *testing.T) {
	step, problems := pinStep(repositoryFile(t, ".github", "workflows", "ci.yml"))
	if len(problems) != 0 {
		t.Fatal(problems)
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	const fakeGo = `#!/usr/bin/env bash
run=""
while [ $# -gt 0 ]; do
  if [ "$1" = -run ]; then run="$2"; shift; fi
  shift
done
echo "${PRUFYX_FLOOR_RUN:-none} ${run}" >> "${FAKE_CALLS}"
run="${run#^}"; run="${run%\$}"; run="${run#(}"; run="${run%)}"
IFS='|' read -r -a names <<< "${run}"
for name in "${names[@]}"; do
  if [ "${name}@${PRUFYX_FLOOR_RUN:-none}" = "${FAKE_SKIP}" ]; then
    echo "--- SKIP: ${name} (0.00s)"
  elif [ "${name}@${PRUFYX_FLOOR_RUN:-none}" != "${FAKE_MISSING}" ]; then
    echo "--- PASS: ${name} (0.00s)"
  fi
done
[ "${FAKE_EXIT}" = "${PRUFYX_FLOOR_RUN:-none}" ] && exit 1
exit 0
`
	const fakeGit = `#!/usr/bin/env bash
tar -c -C "${FAKE_TREE}" cli
`
	moved := "ref=" + strings.Repeat("a", 40) + "\nversion=v0.1.0-beta.3\n"
	run := func(t *testing.T, pin, skip, missing, exit string) (string, string, error) {
		t.Helper()
		dir := t.TempDir()
		write := func(path, content string, mode os.FileMode) {
			full := filepath.Join(dir, path)
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, []byte(content), mode); err != nil {
				t.Fatal(err)
			}
		}
		write("bin/go", fakeGo, 0o755)
		write("bin/git", fakeGit, 0o755)
		write("tree/cli/go.mod", "module x\n", 0o644)
		write("repo/knowledge/oldest-supported-client.txt", pin, 0o644)
		write("temp/.keep", "", 0o644)
		write("step.sh", step.Run, 0o644)
		cmd := exec.Command(bash, "--noprofile", "--norc", "-e", "-o", "pipefail", filepath.Join(dir, "step.sh"))
		cmd.Dir = filepath.Join(dir, "repo")
		cmd.Env = []string{"PATH=" + filepath.Join(dir, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"),
			"RUNNER_TEMP=" + filepath.Join(dir, "temp"), "GITHUB_WORKSPACE=" + dir, "FAKE_TREE=" + filepath.Join(dir, "tree"),
			"FAKE_CALLS=" + filepath.Join(dir, "calls"), "FAKE_SKIP=" + skip, "FAKE_MISSING=" + missing, "FAKE_EXIT=" + exit}
		out, err := cmd.CombinedOutput()
		calls, _ := os.ReadFile(filepath.Join(dir, "calls"))
		return string(out), string(calls), err
	}
	for _, pin := range []string{knowledgepinguard.LegacyPin, moved} {
		out, calls, err := run(t, pin, "", "", "")
		if err != nil {
			t.Fatalf("control, pin %q: %v\n%s", pin, err, out)
		}
		if got := strings.Contains(calls, "pin ^TestPinnedClientAdmitsReachedFloors$"); got != (pin == moved) {
			t.Fatalf("pin %q: pinned-client run %v:\n%s", pin, got, calls)
		}
		if !strings.Contains(calls, "head ^(TestPinnedClientAdmitsReachedFloors|TestAdmitCheckRefusesClientLackingFeature)$") {
			t.Fatalf("pin %q: no head run:\n%s", pin, calls)
		}
	}
	cases := []string{"TestPinnedClientAdmitsReachedFloors@head", "TestPinnedClientAdmitsReachedFloors@pin", "TestAdmitCheckRefusesClientLackingFeature@head"}
	for name := range pinStepTests {
		if name != "TestPinnedClientAdmitsReachedFloors" && name != "TestAdmitCheckRefusesClientLackingFeature" {
			cases = append(cases, name+"@none")
		}
	}
	for _, c := range cases {
		if out, _, err := run(t, moved, c, "", ""); err == nil {
			t.Errorf("a skipped %s passed the step:\n%s", c, out)
		}
		if out, _, err := run(t, moved, "", c, ""); err == nil {
			t.Errorf("a %s that matched nothing passed the step:\n%s", c, out)
		}
	}
	for _, exit := range []string{"none", "head", "pin"} {
		if out, _, err := run(t, moved, "", "", exit); err == nil {
			t.Errorf("a failing %s run passed the step:\n%s", exit, out)
		}
	}
	for _, pin := range []string{"", "ref=abc\nversion=v0.1.0-beta.3\n", moved + "x\n"} {
		if out, _, err := run(t, pin, "", "", ""); err == nil {
			t.Errorf("pin %q passed the step:\n%s", pin, out)
		}
	}
}

// ownersOf is the owners CODEOWNERS gives exactly pattern; a later line wins.
func ownersOf(raw, pattern string) []string {
	var owners []string
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == pattern {
			owners = fields[1:]
		}
	}
	return owners
}

func TestPinProofPathsAreOwned(t *testing.T) {
	raw := string(repositoryFile(t, ".github", "CODEOWNERS"))
	for _, pattern := range []string{
		"/cli/knowledge/oldest-supported-client.txt",
		"/cli/internal/maintainer/knowledgerelease/",
		"/cli/internal/maintainer/knowledgepinguard/",
		"/cli/internal/maintainer/releaseworkflow/knowledge_publish_yml_test.go",
		"/cli/cmd/prufyx-maintainer/knowledge_pin_guard.go",
		"/cli/internal/maintainer/knowledgepublish/",
		"/cli/internal/buildidentity/",
		"/cli/internal/maintainer/knowledgegate/",
		"/cli/internal/cncfcheck/",
		"/.github/",
	} {
		if got := ownersOf(raw, pattern); len(got) != 1 || got[0] != "@airstand" {
			t.Errorf("%s: owners %v", pattern, got)
		}
		if _, err := os.Stat(filepath.Join("..", "..", "..", "..", filepath.FromSlash(pattern))); err != nil {
			t.Errorf("%s does not exist: %v", pattern, err)
		}
		if got := ownersOf(raw+"\n"+pattern+" @other\n", pattern); len(got) != 1 || got[0] != "@other" {
			t.Errorf("setup: a later line does not win for %s", pattern)
		}
	}
	if got := ownersOf(raw, "/cli/absent/"); got != nil {
		t.Errorf("an absent pattern has owners %v", got)
	}
}
