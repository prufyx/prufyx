// SPDX-License-Identifier: AGPL-3.0-only

package releaseworkflow

import (
	"strings"
	"testing"
)

// The pin guard is its own job that sign needs: it runs on every trigger
// before anything is signed, with no environment, no secret and a read-only
// token, and its refusal exit code reaches the job.
func TestKnowledgePublishPinGuardJob(t *testing.T) {
	wf, raw := loadPublishWorkflow(t)
	guard, ok := wf.Jobs["pin_guard"]
	if !ok {
		t.Fatal("no pin_guard job")
	}
	sign := wf.Jobs["sign"]
	if needs, _ := sign.Needs.(string); needs != "pin_guard" {
		t.Errorf("sign needs = %v, want pin_guard", sign.Needs)
	}
	if guard.Environment != nil {
		t.Errorf("pin_guard must have no environment: %v", guard.Environment)
	}
	if guard.If != sign.If {
		t.Errorf("pin_guard if %q differs from sign if %q: it must run whenever sign would", guard.If, sign.If)
	}
	if !samePermissions(guard.Permissions, map[string]string{"contents": "read", "actions": "read", "attestations": "read"}) {
		t.Errorf("pin_guard permissions = %v", guard.Permissions)
	}
	for _, st := range guard.Steps {
		for k, v := range st.Env {
			if secretsRef.MatchString(v) {
				t.Errorf("%q: env %s references secrets", st.Name, k)
			}
		}
		if secretsRef.MatchString(st.Run) || st.ContinueOnError != nil {
			t.Errorf("%q: secrets or continue-on-error", st.Name)
		}
	}
	i := stepIndex(guard.Steps, "Check the pin names a published, attested release")
	if i < 0 {
		t.Fatal("no guard step")
	}
	run := guard.Steps[i].Run
	for _, want := range []string{"pin-guard", `exit "${rc}"`} {
		if !strings.Contains(run, want) {
			t.Errorf("guard step lacks %q", want)
		}
	}
	// The override is never effective in the job that has no environment.
	if strings.Contains(run, "--allow-downgrade") {
		t.Error("pin_guard must not pass --allow-downgrade: the override belongs to the sign job")
	}
	if strings.Contains(run, "|| true") || strings.Contains(run, "|| exit 0") {
		t.Error("guard step swallows its exit code")
	}
	// No trigger may skip it: the guard job has no event filter, and the
	// workflow still runs on push, dispatch and schedule.
	for _, ev := range []string{"push", "schedule", "workflow_dispatch"} {
		if _, ok := wf.On[ev]; !ok {
			t.Errorf("workflow lost trigger %s", ev)
		}
	}
	if strings.Contains(guard.If, "github.event_name") {
		t.Errorf("pin_guard if %q filters on the event", guard.If)
	}
	// The pin is no longer read for the first time after the keys were used.
	if !strings.Contains(raw, "allow_pin_downgrade") {
		t.Error("the owner downgrade input is missing")
	}
}

// The override and the second tag resolution live in the sign job, which is
// the owner-approved environment; the deploy job resolves the tag once more.
func TestKnowledgePublishPinGuardRerun(t *testing.T) {
	wf, _ := loadPublishWorkflow(t)
	sign := wf.Jobs["sign"]
	if env, _ := sign.Environment.(string); env != "knowledge-release" {
		t.Fatalf("sign environment = %v", sign.Environment)
	}
	i := stepIndex(sign.Steps, "Re-run the pin guard before signing")
	prev := stepIndex(sign.Steps, "Find and verify the previous state")
	signed := stepIndex(sign.Steps, "Build, sign and verify")
	if i < 0 || prev < 0 || signed < 0 || !(i < prev && i < signed) {
		t.Fatalf("order: rerun=%d prev=%d sign=%d", i, prev, signed)
	}
	st := sign.Steps[i]
	for k, v := range st.Env {
		if secretsRef.MatchString(v) {
			t.Errorf("env %s references secrets", k)
		}
	}
	if secretsRef.MatchString(st.Run) || st.ContinueOnError != nil || !strings.Contains(st.Run, "--allow-downgrade") || !strings.Contains(st.Run, `exit "${rc}"`) || !strings.Contains(st.Run, "GITHUB_STEP_SUMMARY") {
		t.Errorf("rerun step is wrong: %q", st.Run)
	}
	d := wf.Jobs["deploy"]
	j := stepIndex(d.Steps, "Re-resolve the pinned tag before deploying")
	dl := stepIndex(d.Steps, "Download the signed package")
	if j < 0 || dl < 0 || j > dl {
		t.Fatalf("deploy recheck=%d download=%d", j, dl)
	}
	if run := d.Steps[j].Run; !strings.Contains(run, "--recheck-tag") || strings.Contains(run, "--allow-downgrade") || strings.Contains(run, "|| true") {
		t.Errorf("deploy recheck is wrong: %q", run)
	}
}
