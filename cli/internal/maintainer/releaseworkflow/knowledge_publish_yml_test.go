// SPDX-License-Identifier: AGPL-3.0-only

package releaseworkflow

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type publishJob struct {
	If          string            `yaml:"if"`
	Needs       any               `yaml:"needs"`
	Environment any               `yaml:"environment"`
	Permissions map[string]string `yaml:"permissions"`
	Steps       []workflowStep    `yaml:"steps"`
}

type publishWorkflow struct {
	On          map[string]any        `yaml:"on"`
	Permissions map[string]string     `yaml:"permissions"`
	Jobs        map[string]publishJob `yaml:"jobs"`
}

func loadPublishWorkflow(t *testing.T) (publishWorkflow, string) {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the test source")
	}
	repo := filepath.Join(filepath.Dir(self), "..", "..", "..", "..")
	if _, err := os.Stat(filepath.Join(repo, ".github")); os.IsNotExist(err) {
		t.Skip("no .github directory: staged release source tree")
	}
	raw, err := os.ReadFile(filepath.Join(repo, ".github", "workflows", "knowledge-publish.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var wf publishWorkflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatal(err)
	}
	return wf, string(raw)
}

func samePermissions(got, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}

// The publish workflow holds the online TUF keys in one job and the Pages
// deploy token in another; these properties keep the two apart.
func TestKnowledgePublishWorkflowIsHardened(t *testing.T) {
	wf, raw := loadPublishWorkflow(t)
	if wf.Permissions == nil || len(wf.Permissions) != 0 {
		t.Errorf("top-level permissions = %v, want {}", wf.Permissions)
	}
	if _, ok := wf.On["pull_request"]; ok {
		t.Error("must not trigger on pull_request")
	}
	if _, ok := wf.On["pull_request_target"]; ok {
		t.Error("must not trigger on pull_request_target")
	}
	if len(wf.On) != 2 || wf.On["schedule"] == nil || wf.On["workflow_dispatch"] == nil {
		t.Errorf("triggers = %v, want schedule and workflow_dispatch only", wf.On)
	}
	plan, cancel, probe, sign, deploy := wf.Jobs["plan"], wf.Jobs["cancel-stale"], wf.Jobs["token-probe"], wf.Jobs["sign"], wf.Jobs["deploy"]
	if len(wf.Jobs) != 5 || len(plan.Steps) == 0 || len(cancel.Steps) == 0 || len(probe.Steps) == 0 || len(sign.Steps) == 0 || len(deploy.Steps) == 0 {
		t.Fatalf("jobs = %d, want exactly plan, cancel-stale, token-probe, sign and deploy", len(wf.Jobs))
	}
	// Only the sign job runs in the approval environment; no other job has one
	// except the Pages deploy.
	if env, _ := sign.Environment.(string); env != "knowledge-release" {
		t.Errorf("sign environment = %v, want knowledge-release", sign.Environment)
	}
	for name, job := range map[string]publishJob{"plan": plan, "cancel-stale": cancel, "token-probe": probe} {
		if job.Environment != nil {
			t.Errorf("%s must not use an environment", name)
		}
	}
	if env, _ := deploy.Environment.(map[string]any); env["name"] != "github-pages" {
		t.Errorf("deploy environment = %v, want github-pages", deploy.Environment)
	}
	for _, name := range []string{"plan", "sign"} {
		for _, want := range []string{"refs/heads/main", "KNOWLEDGE_RELEASE_ENABLED"} {
			if !strings.Contains(wf.Jobs[name].If, want) {
				t.Errorf("%s if %q lacks %s", name, wf.Jobs[name].If, want)
			}
		}
	}
	// A dry run can never reach sign; the sign job needs the plan decision.
	for _, want := range []string{"!inputs.dry_run", "needs.plan.result == 'success'", "needs.plan.outputs.sign_ok == 'true'"} {
		if !strings.Contains(sign.If, want) {
			t.Errorf("sign if %q lacks %s", sign.If, want)
		}
	}
	if sign.Needs != "plan" || deploy.Needs != "sign" || cancel.Needs != "plan" || probe.Needs != "plan" {
		t.Errorf("needs: sign=%v deploy=%v cancel=%v probe=%v", sign.Needs, deploy.Needs, cancel.Needs, probe.Needs)
	}
	if !strings.Contains(deploy.If, "needs.sign.result == 'success'") {
		t.Errorf("deploy if %q must require a successful sign job", deploy.If)
	}
	if !strings.Contains(probe.If, "workflow_dispatch") || !strings.Contains(probe.If, "inputs.dry_run") {
		t.Errorf("token-probe if %q must be limited to dry-run dispatches", probe.If)
	}
	// Per-job permissions, each exact: the signing job has no write scope, the
	// deploy job has the Pages scopes and no key, and the two jobs with actions
	// write hold no secret and no environment.
	if !samePermissions(plan.Permissions, map[string]string{"contents": "read", "actions": "read", "pull-requests": "read", "checks": "read", "statuses": "read"}) {
		t.Errorf("plan permissions = %v", plan.Permissions)
	}
	if !samePermissions(sign.Permissions, map[string]string{"contents": "read", "actions": "read"}) {
		t.Errorf("sign permissions = %v", sign.Permissions)
	}
	if !samePermissions(deploy.Permissions, map[string]string{"pages": "write", "id-token": "write", "actions": "read", "contents": "read"}) {
		t.Errorf("deploy permissions = %v", deploy.Permissions)
	}
	if !samePermissions(cancel.Permissions, map[string]string{"actions": "write", "contents": "read"}) {
		t.Errorf("cancel-stale permissions = %v", cancel.Permissions)
	}
	if !samePermissions(probe.Permissions, map[string]string{"actions": "write"}) {
		t.Errorf("token-probe permissions = %v", probe.Permissions)
	}
	for name, job := range wf.Jobs {
		for k, v := range job.Permissions {
			if v == "write" && !map[string]bool{"cancel-stale/actions": true, "token-probe/actions": true, "deploy/pages": true, "deploy/id-token": true}[name+"/"+k] {
				t.Errorf("%s: unexpected write permission %s", name, k)
			}
		}
	}
	// Secrets: referenced nowhere but the four key env entries of the Sign step
	// of the sign job (not in any if, with, run, output or other job).
	inSign := 0
	for name, job := range wf.Jobs {
		for _, step := range job.Steps {
			text := step.If + step.Run
			for _, v := range step.Env {
				if name == "sign" && step.Name == "Sign" {
					continue
				}
				text += v
			}
			for _, v := range step.With {
				if s, ok := v.(string); ok {
					text += s
				}
			}
			if secretsDot.MatchString(text) {
				t.Errorf("%s: step %q references secrets outside the Sign step", name, step.Name)
			}
			if name == "sign" && step.Name == "Sign" {
				for _, v := range step.Env {
					if strings.Contains(v, "secrets.") {
						inSign++
					}
				}
			}
		}
	}
	if inSign != 4 {
		t.Errorf("the Sign step holds %d secret references, want the four key entries", inSign)
	}
	rawSecrets := 0
	for _, line := range strings.Split(raw, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			rawSecrets += strings.Count(line, "secrets.")
		}
	}
	if rawSecrets != 4 {
		t.Errorf("workflow text has %d non-comment secrets references, want exactly the four in the Sign step", rawSecrets)
	}
	for name, job := range wf.Jobs {
		for _, step := range job.Steps {
			switch {
			case strings.HasPrefix(step.Uses, "actions/setup-go@"):
				if v, ok := step.With["cache"].(bool); !ok || v {
					t.Errorf("%s: setup-go must set cache: false", name)
				}
			case strings.HasPrefix(step.Uses, "actions/checkout@"):
				if v, ok := step.With["persist-credentials"].(bool); !ok || v {
					t.Errorf("%s: checkout must set persist-credentials: false", name)
				}
			case strings.HasPrefix(step.Uses, "actions/cache"):
				t.Errorf("%s: must not use actions/cache", name)
			}
		}
	}
	pinned := regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+@[0-9a-f]{40}$`)
	for name, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Uses != "" && !pinned.MatchString(step.Uses) {
				t.Errorf("%s: action %q is not pinned by a 40-hex commit SHA", name, step.Uses)
			}
			if name == "deploy" {
				for _, v := range step.Env {
					if strings.Contains(v, "secrets.") {
						t.Error("deploy must not reference secrets")
					}
				}
				for _, v := range step.With {
					if s, ok := v.(string); ok && strings.Contains(s, "secrets.") {
						t.Error("deploy must not reference secrets")
					}
				}
			}
		}
	}
	// The previous-state digest is passed to `db verify` with its prefix.
	if !strings.Contains(raw, `expected_digest="sha256:${aname##*-}"`) {
		t.Error("the artifact-name digest must be passed to db verify as sha256:<hex>")
	}
}

var secretsRef = regexp.MustCompile(`\bsecrets\b`)
var secretsDot = regexp.MustCompile(`\bsecrets\.`)

func stepIndex(steps []workflowStep, name string) int {
	for i, s := range steps {
		if s.Name == name {
			return i
		}
	}
	return -1
}

// The oldest-supported-client gate runs in the sign job after the keys are
// gone and before the package upload, holds no secret, builds a commit-pinned
// client and cannot be skipped; the deploy job only receives the uploaded
// package and uploads the site after re-verifying it.
func TestKnowledgePublishOldestClientGate(t *testing.T) {
	wf, _ := loadPublishWorkflow(t)
	steps := wf.Jobs["sign"].Steps
	signed := stepIndex(steps, "Sign")
	verified := stepIndex(steps, "Verify the signed package")
	read := stepIndex(steps, "Read the oldest supported client pin")
	checkout := stepIndex(steps, "Check out the oldest supported client")
	gate := stepIndex(steps, "Verify with the oldest supported client")
	upload := stepIndex(steps, "Upload the signed package")
	if signed < 0 || verified < 0 || read < 0 || checkout < 0 || gate < 0 || upload < 0 {
		t.Fatalf("missing step: sign=%d verified=%d read=%d checkout=%d gate=%d upload=%d", signed, verified, read, checkout, gate, upload)
	}
	if !(signed < verified && verified < read && read < checkout && checkout < gate && gate < upload) {
		t.Errorf("step order wrong: sign=%d verified=%d read=%d checkout=%d gate=%d upload=%d", signed, verified, read, checkout, gate, upload)
	}
	// Pages path: the artifact reaches deploy only through the sign job's
	// upload (after the gate); deploy verifies it again before the site upload.
	ds := wf.Jobs["deploy"].Steps
	dl := stepIndex(ds, "Download the signed package")
	assemble := stepIndex(ds, "Verify and assemble the site")
	follow := stepIndex(ds, "Refuse unless the candidate follows the live package")
	site := stepIndex(ds, "Upload the site")
	deployed := stepIndex(ds, "Deploy to Pages")
	if dl < 0 || assemble < 0 || follow < 0 || site < 0 || deployed < 0 {
		t.Fatalf("deploy: missing step: download=%d follow=%d assemble=%d site=%d deploy=%d", dl, follow, assemble, site, deployed)
	}
	if !(dl < follow && follow < assemble && assemble < site && site < deployed) {
		t.Errorf("deploy order wrong: download=%d follow=%d assemble=%d site=%d deploy=%d", dl, follow, assemble, site, deployed)
	}
	for _, i := range []int{read, checkout, gate} {
		st := steps[i]
		if st.If != "" {
			t.Errorf("%q: if %q: the gate steps must run on every signing run, never be skipped", st.Name, st.If)
		}
		if st.ContinueOnError != nil {
			t.Errorf("%q: must not set continue-on-error", st.Name)
		}
		if strings.Contains(st.If, "||") {
			t.Errorf("%q: if %q must not contain ||", st.Name, st.If)
		}
		for k, v := range st.Env {
			if secretsRef.MatchString(v) {
				t.Errorf("%q: env %s references secrets", st.Name, k)
			}
		}
		for k, v := range st.With {
			if s, ok := v.(string); ok && secretsRef.MatchString(s) {
				t.Errorf("%q: with %s references secrets", st.Name, k)
			}
		}
		if secretsRef.MatchString(st.Run) || strings.Contains(st.Run, "github.token") || strings.Contains(st.Run, "GH_TOKEN") {
			t.Errorf("%q: run block touches a token or secret", st.Name)
		}
	}
	if !strings.Contains(wf.Jobs["sign"].If, "needs.plan.outputs.sign_ok == 'true'") {
		t.Error("the sign job (and so the gate) must run only on an approved plan")
	}
	if steps[signed].ID != "sign" {
		t.Errorf("signing step id = %q", steps[signed].ID)
	}
	co := steps[checkout]
	if !regexp.MustCompile(`^actions/checkout@[0-9a-f]{40}$`).MatchString(co.Uses) {
		t.Errorf("oldest checkout %q is not pinned by a 40-hex SHA", co.Uses)
	}
	if v, ok := co.With["persist-credentials"].(bool); !ok || v {
		t.Error("oldest checkout must set persist-credentials: false")
	}
	if co.With["path"] != "oldest" {
		t.Errorf("oldest checkout path = %v, want oldest", co.With["path"])
	}
	if ref, _ := co.With["ref"].(string); !strings.Contains(ref, "steps.oldest.outputs.ref") {
		t.Errorf("oldest checkout ref = %q, must come from the pin file", ref)
	}
	run := steps[gate].Run
	for _, want := range []string{
		"buildidentity.Version=${OLDEST_VERSION}",
		"GOTOOLCHAIN=local",
		"db verify",
		"--expected-package-digest",
		"--expected-revision",
		"jq -e '.status == \"VERIFIED\"'",
		"--bootstrap-root",
		"the oldest supported client (",
		"the feed keeps the last package",
	} {
		if !strings.Contains(run, want) {
			t.Errorf("gate run block lacks %q", want)
		}
	}
	if strings.Contains(run, "|| true") {
		t.Error("gate must not swallow a failure")
	}
}

var (
	oldestRefLine     = regexp.MustCompile(`^ref=[0-9a-f]{40}$`)
	oldestVersionLine = regexp.MustCompile(`^version=v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+\.[0-9]+)?$`)
)

func TestOldestSupportedClientPin(t *testing.T) {
	_, self, _, _ := runtime.Caller(0)
	repo := filepath.Join(filepath.Dir(self), "..", "..", "..", "..")
	if _, err := os.Stat(filepath.Join(repo, ".github")); os.IsNotExist(err) {
		t.Skip("no .github directory: staged release source tree")
	}
	raw, err := os.ReadFile(filepath.Join(repo, "cli", "knowledge", "oldest-supported-client.txt"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) != 2 || !strings.HasSuffix(string(raw), "\n") {
		t.Fatalf("pin file must hold exactly two newline-terminated lines, got %q", raw)
	}
	if !oldestRefLine.MatchString(lines[0]) {
		t.Errorf("ref line %q is not a 40-hex commit", lines[0])
	}
	if !oldestVersionLine.MatchString(lines[1]) {
		t.Errorf("version line %q is not vMAJOR.MINOR.PATCH[-pre.N]", lines[1])
	}
	for _, bad := range []string{"version=0.1.0", "version=v0.1", "version=v01.1.0", "version=v0.1.0-beta", "version=v0.1.0 ", "ref=abc"} {
		if oldestVersionLine.MatchString(bad) || oldestRefLine.MatchString(bad) {
			t.Errorf("%q must not match", bad)
		}
	}
}

func readRepoFile(t *testing.T, rel ...string) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the test source")
	}
	repo := filepath.Join(filepath.Dir(self), "..", "..", "..", "..")
	raw, err := os.ReadFile(filepath.Join(append([]string{repo}, rel...)...))
	if err != nil {
		t.Skip("source file not present: " + filepath.Join(rel...))
	}
	return string(raw)
}

func stepRun(t *testing.T, job publishJob, name string) string {
	t.Helper()
	i := stepIndex(job.Steps, name)
	if i < 0 {
		t.Fatalf("step %q not found", name)
	}
	return job.Steps[i].Run
}

// The live package is the newest live artifact across the content family and
// the refresh family. Plan picks it from both, sign and deploy re-check both
// families unconditionally (an empty recorded run id is a state to compare, not
// a reason to skip), and nothing reads only the content family any more.
func TestKnowledgePublishLivenessSpansBothFamilies(t *testing.T) {
	wf, raw := loadPublishWorkflow(t)
	if !strings.Contains(stepRun(t, wf.Jobs["plan"], "Find and verify the previous state"), "knowledge-daily.sh\" live-runs") {
		t.Error("plan must pick the live package with live-runs (both families)")
	}
	if !strings.Contains(stepRun(t, wf.Jobs["sign"], "Re-derive state, digests and version"), "knowledge-daily.sh check-live \"${plan}\"") {
		t.Error("sign must re-check liveness over both families with check-live")
	}
	if !strings.Contains(stepRun(t, wf.Jobs["deploy"], "Refuse unless the candidate follows the live package"), "check-live \"${plan}\"") {
		t.Error("deploy must re-check liveness over both families with check-live")
	}
	if strings.Contains(raw, "latest-run") {
		t.Error("the single-family latest-run lookup is still used")
	}
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if strings.Contains(line, `-z "${prun}"`) {
			t.Errorf("liveness skipped on an empty recorded run id: %s", strings.TrimSpace(line))
		}
	}
	// The sign version is the live timestamp version plus one, from the live-state
	// of the package the plan holds (the live package), never a copy of an older one.
	rd := stepRun(t, wf.Jobs["sign"], "Re-derive state, digests and version")
	if !strings.Contains(rd, `version="$(jq -er '.minNextVersion' <<< "${state}")"`) || !strings.Contains(rd, "--expect-package-digest") {
		t.Error("the signing version must be the live-state minNextVersion of the live package")
	}
	sg := stepRun(t, wf.Jobs["sign"], "Sign")
	if !strings.Contains(sg, `--expect-previous-package-digest "$(jq -er '.previous.packageDigest'`) {
		t.Error("release must be pinned to the live package digest")
	}
	dg := stepRun(t, wf.Jobs["deploy"], "Refuse unless the candidate follows the live package")
	if !strings.Contains(dg, "deploy-guard") || !strings.Contains(dg, `--live-package "${prev}"`) || !strings.Contains(dg, `--predecessor-digest "$(jq -er '.previous.packageDigest'`) {
		t.Error("deploy-guard must get the live package and its digest")
	}
}

// Recovery over an orphan refresh must be handed the refresh package itself
// (digest bound), and every deploy compares the served feed with the recorded
// predecessor: neither the owner-supplied package nor a CDN-lagged feed may
// let a candidate replace a state that is not the predecessor.
func TestKnowledgePublishBindsOrphanAndServedFeed(t *testing.T) {
	wf, raw := loadPublishWorkflow(t)
	pv := stepRun(t, wf.Jobs["plan"], "Find and verify the previous state")
	if !strings.Contains(pv, `knowledge-daily.sh" orphan-bind `) {
		t.Error("recovery over an orphan refresh must call orphan-bind")
	}
	if !strings.Contains(pv, `expected_digest="$(`) || !strings.Contains(pv, "orphan-bind") {
		t.Error("the orphan refresh digest must become the expected digest of the verify call")
	}
	if i, j := strings.Index(pv, "orphan-bind"), strings.Index(pv, `if verify "${pkg}"`); i < 0 || j < 0 || i > j {
		t.Error("orphan-bind must run before the previous package is verified")
	}
	dg := stepRun(t, wf.Jobs["deploy"], "Refuse unless the candidate follows the live package")
	if !strings.Contains(dg, `knowledge-daily.sh" served-check `) {
		t.Error("deploy must compare the served feed with the recorded predecessor (served-check)")
	}
	if !strings.Contains(dg, `-- "${FEED_URL}"`) || !strings.Contains(dg, "Cache-Control: no-cache") || !strings.Contains(dg, "--proto '=https'") || !strings.Contains(dg, "--max-redirs 0") {
		t.Error("the served feed must be fetched over https, without redirects and without cache")
	}
	if i, j := strings.Index(dg, "served-check"), strings.Index(dg, "deploy-guard"); i < 0 || j < 0 || i > j {
		t.Error("served-check must run before the deploy guard")
	}
	if strings.Contains(dg, `= recovery`) {
		t.Error("served-check must apply to every mode")
	}
	if !strings.Contains(raw, `FEED_URL: "https://prufyx.github.io/prufyx/knowledge/cncf-projects.tar"`) {
		t.Error("deploy must pin the feed URL")
	}
}

// The packet digest the workflow consumes is entriesDigest. The keyless export
// contentDigest that binds the signature keeps its name and is never read from
// the packet; the step summary shows both with distinct labels.
func TestKnowledgePublishPacketDigestIsEntriesDigest(t *testing.T) {
	wf, raw := loadPublishWorkflow(t)
	plan := stepRun(t, wf.Jobs["plan"], "Build the packet and the plan")
	if !strings.Contains(plan, `jq -er '.entriesDigest' "${stage}/packet.json"`) {
		t.Error("the plan summary must read entriesDigest from the packet")
	}
	for _, label := range []string{"export content digest (binds the signature)", "packet entries digest"} {
		if !strings.Contains(plan, label) {
			t.Errorf("plan summary lacks the label %q", label)
		}
	}
	if !strings.Contains(raw, "entriesDigest: $p[0].entriesDigest") {
		t.Error("status.json must carry the packet entriesDigest next to the export contentDigest")
	}
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if strings.Contains(line, "packet.json") && strings.Contains(line, ".contentDigest") {
			t.Errorf("the packet digest is read as contentDigest: %s", strings.TrimSpace(line))
		}
	}
}

// Key presence is owner-verified; the Sign step refuses an empty key input before
// any key file or directory exists, and nothing lists repository secrets.
func TestKnowledgePublishSignRefusesEmptyKeyInputsFirst(t *testing.T) {
	wf, raw := loadPublishWorkflow(t)
	sg := stepRun(t, wf.Jobs["sign"], "Sign")
	guard := strings.Index(sg, "TARGETS_KEY SNAPSHOT_KEY TIMESTAMP_KEY PASSPHRASE")
	if guard < 0 || !strings.Contains(sg, `[ -n "${!name//[[:space:]]/}" ]`) {
		t.Fatal("the Sign step has no empty-input guard over all four key inputs")
	}
	for _, later := range []string{"mktemp", "printf", "> \"${keys}"} {
		if i := strings.Index(sg, later); i >= 0 && i < guard {
			t.Errorf("%q comes before the key input guard", later)
		}
	}
	script := readRepoFile(t, "scripts", "knowledge-daily.sh")
	for _, s := range []string{raw, script} {
		for _, line := range strings.Split(s, "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "#") && strings.Contains(line, "actions/secrets") {
				t.Errorf("repository secrets are listed: %s", strings.TrimSpace(line))
			}
		}
	}
}

// The trusted marker authors are pinned numeric ids in the script; a login
// lookup may only cross-check them.
func TestKnowledgeDailyPinsTrustedUserIDs(t *testing.T) {
	script := readRepoFile(t, "scripts", "knowledge-daily.sh")
	for _, want := range []string{"OWNER_USER_ID=11156623", "BOT_USER_ID=343087959"} {
		if !strings.Contains(script, want) {
			t.Errorf("script lacks the pinned constant %s", want)
		}
	}
	_, raw := loadPublishWorkflow(t)
	if strings.Contains(raw, "users/") || strings.Contains(raw, "gh api users") {
		t.Error("the workflow resolves trusted ids from logins")
	}
}

// Merge order is stated where an editor will see it: the workflow header, and the
// docs section "Daily signing".
func TestDailySigningStatesMergeOrderAndOwnerVerifiedKeys(t *testing.T) {
	_, raw := loadPublishWorkflow(t)
	var header []string
	for _, l := range strings.Split(raw, "\n") {
		if !strings.HasPrefix(l, "#") {
			break
		}
		header = append(header, strings.ToLower(l))
	}
	h := strings.Join(header, "\n")
	for _, want := range []string{"merge order", "draft", "knowledge-refresh", "#460", "#461", "#462", "#463", "owner steps", "owner-verified"} {
		if !strings.Contains(h, want) {
			t.Errorf("workflow header lacks %q", want)
		}
	}
	doc := readRepoFile(t, "cli", "docs", "knowledge-publisher.md")
	i := strings.Index(doc, "Daily signing")
	if i < 0 {
		t.Fatal("docs have no Daily signing section")
	}
	section := strings.ToLower(doc[i:])
	for _, want := range []string{"merge order", "draft", "key presence is owner-verified", "knowledge-refresh-<revision>"} {
		if !strings.Contains(section, want) {
			t.Errorf("docs 'Daily signing' lacks %q", want)
		}
	}
}
