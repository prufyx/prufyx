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
	for _, want := range []string{"pin-guard", `exit "${rc}"`, "--allow-downgrade"} {
		if !strings.Contains(run, want) {
			t.Errorf("guard step lacks %q", want)
		}
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
