// SPDX-License-Identifier: AGPL-3.0-only

package rulecheck

import (
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// noticeCandidate turns a real reviewed entry into a notice_one_way
// candidate: no constraint of its own, the fixed reason code and reviewed
// before-you-upgrade text.
func noticeCandidate(t *testing.T) map[string]any {
	t.Helper()
	entry := firstRealEntry(t)
	setRuleID(t, entry, "notice-test.one-way.1-0-0-to-2-0-0")
	body := rule(entry)
	for _, key := range []string{"condition", "setCondition", "appliesWhen", "dependency", "intermediate"} {
		delete(body, key)
	}
	body["operator"] = constraintengine.OperatorNoticeOneWay
	body["reasonCode"] = constraintengine.ReasonOneWayTransition
	body["nextAction"] = "back up every custom resource and verify a restore before upgrading"
	entry["requiredFacts"] = []any{}
	return entry
}

func TestRulecheckNotice(t *testing.T) {
	result, err := Validate(candidateFile(t, noticeCandidate(t)), Options{})
	if err != nil || !result.Valid {
		t.Fatalf("valid notice candidate rejected: err=%v findings=%+v", err, result.Findings)
	}
	for name, mutate := range map[string]func(map[string]any){
		"other reason code": func(e map[string]any) { rule(e)["reasonCode"] = "REVIEWED_SOURCE_CONSTRAINT" },
		"safe wording":      func(e map[string]any) { rule(e)["nextAction"] = "rolling back is safe" },
		"intermediate":      func(e map[string]any) { rule(e)["intermediate"] = "1.5.0" },
	} {
		entry := noticeCandidate(t)
		mutate(entry)
		result, err := Validate(candidateFile(t, entry), Options{})
		if err != nil || result.Valid || checks(result) != "engine-rejected" {
			t.Fatalf("%s: err=%v checks=%s findings=%+v", name, err, checks(result), result.Findings)
		}
	}
}
