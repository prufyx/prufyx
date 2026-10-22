// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// ciFanInName is the required status check. The test jobs are sharded, so
// this job is the only one that stands for all of them.
const ciFanInName = "Build, vet, test"

// ciNonGateJobs run go test but are deliberately not part of the required
// check (the race detector is advisory and sharded on its own).
var ciNonGateJobs = map[string]bool{"race": true}

type ciWorkflowFile struct {
	Jobs map[string]ciWorkflowJob `yaml:"jobs"`
}

type ciWorkflowJob struct {
	Name            string            `yaml:"name"`
	If              string            `yaml:"if"`
	ContinueOnError any               `yaml:"continue-on-error"`
	Needs           ciStringList      `yaml:"needs"`
	Steps           []ciWorkflowStep  `yaml:"steps"`
	Env             map[string]string `yaml:"env"`
	Strategy        struct {
		Matrix map[string]any `yaml:"matrix"`
	} `yaml:"strategy"`
}

type ciWorkflowStep struct {
	Run             string            `yaml:"run"`
	Env             map[string]string `yaml:"env"`
	ContinueOnError any               `yaml:"continue-on-error"`
}

// ciSoftFail reports a continue-on-error value other than absent or false.
func ciSoftFail(v any) bool {
	return v != nil && v != false && v != "false"
}

// ciStringList accepts a scalar or a sequence, as GitHub does for needs.
type ciStringList []string

func (l *ciStringList) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		*l = ciStringList{n.Value}
		return nil
	}
	var s []string
	if err := n.Decode(&s); err != nil {
		return err
	}
	*l = s
	return nil
}

// ciGoTestRe matches a step line that runs go test, directly or through the
// shard script (scripts/ci-test-shard.sh runs go test for one shard of a package).
var ciGoTestRe = regexp.MustCompile(`(^|[\s;&|(])(go test|(\S*/)?ci-test-shard\.sh)(\s|$)`)

// ciFanInProblems returns every way the ci.yml text lets a test job skip the
// required check.
func ciFanInProblems(raw []byte) []string {
	var wf ciWorkflowFile
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		return []string{"ci.yml does not parse: " + err.Error()}
	}
	var problems []string
	var fanID string
	for id, job := range wf.Jobs {
		if job.Name == ciFanInName {
			if fanID != "" {
				problems = append(problems, "two jobs are named "+ciFanInName)
			}
			fanID = id
		}
	}
	if fanID == "" {
		return append(problems, "no job is named "+ciFanInName)
	}
	fan := wf.Jobs[fanID]
	needs := map[string]bool{}
	for _, n := range fan.Needs {
		needs[n] = true
	}
	var ids []string
	for id := range wf.Jobs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		job := wf.Jobs[id]
		if id == fanID || ciNonGateJobs[id] {
			continue
		}
		runsTests := false
		for _, st := range job.Steps {
			for _, line := range strings.Split(st.Run, "\n") {
				if ciGoTestRe.MatchString(line) {
					runsTests = true
					if ciSoftFail(st.ContinueOnError) || strings.Contains(line, "|| true") {
						problems = append(problems, "job "+id+" lets a go test step fail without failing the job")
					}
				}
			}
		}
		if (runsTests || needs[id]) && ciSoftFail(job.ContinueOnError) {
			problems = append(problems, "job "+id+" sets continue-on-error, so its failure reports success to the fan-in")
		}
		if runsTests && !needs[id] {
			problems = append(problems, "job "+id+" runs go test but is not in the "+ciFanInName+" needs")
		}
	}
	for n := range needs {
		if _, ok := wf.Jobs[n]; !ok {
			problems = append(problems, "needs lists unknown job "+n)
		}
		if ciNonGateJobs[n] {
			problems = append(problems, "needs lists the advisory job "+n)
		}
	}
	if strings.ReplaceAll(strings.TrimSpace(fan.If), " ", "") != "always()" {
		problems = append(problems, ciFanInName+" must have if: always(), else a failed shard skips it and a skipped required check can pass")
	}
	if ciSoftFail(fan.ContinueOnError) {
		problems = append(problems, ciFanInName+" must not set continue-on-error")
	}
	checked := false
	for _, st := range fan.Steps {
		var results string
		for _, v := range st.Env {
			if strings.Contains(v, "needs.*.result") {
				results = v
			}
		}
		if strings.Contains(st.Run, "needs.*.result") {
			results = st.Run
		}
		if results == "" {
			continue
		}
		// Anything but success (failure, cancelled, skipped) must fail the job.
		if strings.Contains(st.Run, `!= "success"`) && strings.Contains(st.Run, "exit 1") {
			checked = true
		}
	}
	if !checked {
		problems = append(problems, ciFanInName+" lacks a step that fails unless every needs.*.result is success")
	}
	return problems
}

// TestCIFanInCoversEveryTestJob: the test jobs of ci.yml are sharded behind
// one fan-in job that carries the required check name. A shard that is not
// in the fan-in needs, or a fan-in that does not fail on a skipped or
// cancelled shard, would let a merge through without its tests.
func TestCIFanInCoversEveryTestJob(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ciFanInProblems(raw) {
		t.Error(p)
	}
}

// The guard itself must fail on each way of breaking the fan-in.
func TestCIFanInGuardRejectsBrokenFanIn(t *testing.T) {
	good := `
jobs:
  shard-a:
    name: A
    steps:
      - run: go test ./...
  shard-b:
    name: B
    steps:
      - run: |
          set -e
          go test -tags x ./a/
  race:
    name: Race
    steps:
      - run: go test -race ./...
  fan:
    name: Build, vet, test
    needs: [shard-a, shard-b]
    if: always()
    steps:
      - env:
          RESULTS: ${{ join(needs.*.result, ' ') }}
        run: |
          for r in ${RESULTS}; do
            if [ "${r}" != "success" ]; then
              exit 1
            fi
          done
`
	if p := ciFanInProblems([]byte(good)); len(p) != 0 {
		t.Fatalf("good workflow rejected: %v", p)
	}
	cases := map[string]func(string) string{
		"shard missing from needs": func(s string) string { return strings.Replace(s, "[shard-a, shard-b]", "[shard-a]", 1) },
		"no if always":             func(s string) string { return strings.Replace(s, "if: always()", "", 1) },
		"if success":               func(s string) string { return strings.Replace(s, "if: always()", "if: success()", 1) },
		"no success check":         func(s string) string { return strings.Replace(s, `!= "success"`, `== "failure"`, 1) },
		"no result env":            func(s string) string { return strings.Replace(s, "needs.*.result", "needs.shard-a.result", 1) },
		"continue on error": func(s string) string {
			return strings.Replace(s, "if: always()", "if: always()\n    continue-on-error: true", 1)
		},
		"shard continue-on-error": func(s string) string {
			return strings.Replace(s, "  shard-a:\n    name: A", "  shard-a:\n    name: A\n    continue-on-error: true", 1)
		},
		"test step continue-on-error": func(s string) string {
			return strings.Replace(s, "      - run: go test ./...", "      - continue-on-error: true\n        run: go test ./...", 1)
		},
		"test or true":   func(s string) string { return strings.Replace(s, "go test ./...", "go test ./... || true", 1) },
		"race in needs":  func(s string) string { return strings.Replace(s, "[shard-a, shard-b]", "[shard-a, shard-b, race]", 1) },
		"fan-in renamed": func(s string) string { return strings.Replace(s, "name: Build, vet, test", "name: Gate", 1) },
	}
	for name, mutate := range cases {
		if p := ciFanInProblems([]byte(mutate(good))); len(p) == 0 {
			t.Errorf("%s: broken fan-in accepted", name)
		}
	}
}

// TestCIShardsAreComplete: a job that runs scripts/ci-test-shard.sh must run
// every shard 1..SHARDS. A matrix that drops a shard, or a SHARDS value that
// differs from the matrix, would leave tests that no job runs.
func TestCIShardsAreComplete(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ciShardProblems(raw) {
		t.Error(p)
	}
	broken := map[string]string{
		"dropped shard": strings.Replace(string(raw), "shard: [1, 2, 3]", "shard: [1, 2]", 1),
		"total differs": strings.Replace(string(raw), `SHARDS: "3"`, `SHARDS: "4"`, 1),
		"no shard env":  strings.Replace(string(raw), `"${SHARD}" "${SHARDS}"`, `"1" "3"`, 1),
		"shard pinned":  strings.Replace(string(raw), "SHARD: ${{ matrix.shard }}", `SHARD: "1"`, 1),
		"step SHARDS":   strings.Replace(string(raw), "SHARD: ${{ matrix.shard }}", "SHARD: ${{ matrix.shard }}\n          SHARDS: \"1\"", 1),
	}
	for name, text := range broken {
		if text == string(raw) {
			t.Fatalf("%s: the mutation changed nothing", name)
		}
		if len(ciShardProblems([]byte(text))) == 0 {
			t.Errorf("%s: broken shard matrix accepted", name)
		}
	}
}

// ciShardProblems returns every way a sharded job can leave tests unrun.
func ciShardProblems(raw []byte) []string {
	var wf ciWorkflowFile
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		return []string{"ci.yml does not parse: " + err.Error()}
	}
	var problems []string
	sharded := 0
	for id, job := range wf.Jobs {
		uses := false
		for _, st := range job.Steps {
			if strings.Contains(st.Run, "ci-test-shard.sh") {
				uses = true
				if !strings.Contains(st.Run, `"${SHARD}" "${SHARDS}"`) {
					problems = append(problems, "job "+id+" must pass the matrix shard and SHARDS to the shard script")
				}
				if strings.ReplaceAll(st.Env["SHARD"], " ", "") != "${{matrix.shard}}" {
					problems = append(problems, "job "+id+" must set the step env SHARD to ${{ matrix.shard }}")
				}
				if _, ok := st.Env["SHARDS"]; ok || strings.Contains(st.Run, "SHARDS=") {
					problems = append(problems, "job "+id+" must not override SHARDS in the shard step")
				}
			}
		}
		if !uses {
			continue
		}
		sharded++
		total, err := strconv.Atoi(job.Env["SHARDS"])
		if err != nil || total < 2 {
			problems = append(problems, "job "+id+" needs env SHARDS of at least 2")
			continue
		}
		list, _ := job.Strategy.Matrix["shard"].([]any)
		seen := map[int]bool{}
		for _, v := range list {
			n, ok := v.(int)
			if !ok {
				problems = append(problems, "job "+id+" has a non-integer shard in its matrix")
				continue
			}
			seen[n] = true
		}
		if len(list) != total || len(seen) != total {
			problems = append(problems, "job "+id+" matrix lists a different number of shards than SHARDS")
		}
		for i := 1; i <= total; i++ {
			if !seen[i] {
				problems = append(problems, "job "+id+" matrix lacks shard "+strconv.Itoa(i))
			}
		}
	}
	if sharded == 0 {
		problems = append(problems, "no job uses the shard script; the guard reads the wrong file")
	}
	return problems
}

// TestCICoreGroupsAreComplete: the "rest" group of test-core is computed by
// excluding CORE_GROUPED, so CORE_GROUPED must be exactly the packages of the
// other groups, and exactly one group may be the catch-all (empty packages).
func TestCICoreGroupsAreComplete(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ciCoreGroupProblems(raw) {
		t.Error(p)
	}
	text := string(raw)
	broken := map[string]string{
		"package dropped from an include": strings.Replace(text, "packages: ./internal/maintainer/evidencereattest/\n", "packages: \"\"\n", 1),
		"package not excluded":            strings.Replace(text, "        ./internal/maintainer/evidencereattest/\n        ./cmd/prufyx-maintainer/", "        ./cmd/prufyx-maintainer/", 1),
		"no catch-all":                    strings.Replace(text, `packages: ""`, "packages: ./internal/x/", 1),
	}
	for name, mutated := range broken {
		if mutated == text {
			t.Fatalf("%s: the mutation changed nothing", name)
		}
		if len(ciCoreGroupProblems([]byte(mutated))) == 0 {
			t.Errorf("%s: broken core groups accepted", name)
		}
	}
}

func ciCoreGroupProblems(raw []byte) []string {
	var wf struct {
		Jobs map[string]struct {
			Env      map[string]string `yaml:"env"`
			Strategy struct {
				Matrix struct {
					Include []struct {
						Packages string `yaml:"packages"`
					} `yaml:"include"`
				} `yaml:"matrix"`
			} `yaml:"strategy"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		return []string{"ci.yml does not parse: " + err.Error()}
	}
	job, ok := wf.Jobs["test-core"]
	if !ok {
		return []string{"no test-core job"}
	}
	var problems []string
	grouped := map[string]bool{}
	for _, f := range strings.Fields(job.Env["CORE_GROUPED"]) {
		grouped[f] = true
	}
	union := map[string]bool{}
	catchAll := 0
	for _, inc := range job.Strategy.Matrix.Include {
		if strings.TrimSpace(inc.Packages) == "" {
			catchAll++
			continue
		}
		for _, f := range strings.Fields(inc.Packages) {
			union[f] = true
		}
	}
	if catchAll != 1 {
		problems = append(problems, "test-core needs exactly one catch-all include (empty packages), has "+strconv.Itoa(catchAll))
	}
	for pkg := range union {
		if !grouped[pkg] {
			problems = append(problems, "test-core: "+pkg+" is in a group but not in CORE_GROUPED, so the catch-all runs it twice")
		}
	}
	for pkg := range grouped {
		if !union[pkg] {
			problems = append(problems, "test-core: "+pkg+" is in CORE_GROUPED but in no group, so no job runs it")
		}
	}
	return problems
}
