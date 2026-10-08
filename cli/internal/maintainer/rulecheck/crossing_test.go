// SPDX-License-Identifier: AGPL-3.0-only

package rulecheck

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// crossingCandidate turns a real reviewed ranged entry into a synthetic
// crossing candidate: the range is dropped, and a crossing at the anchor's
// target (the removal release C) is cited to the rule's first evidence
// source, reviewed through the second minor line after C.
func crossingCandidate(t *testing.T) map[string]any {
	t.Helper()
	entry := firstRangedEntry(t)
	body := rule(entry)
	delete(body, "range")
	subject := body["subject"].(map[string]any)
	var major, minor, patch int
	if _, err := fmt.Sscanf(subject["to"].(string), "%d.%d.%d", &major, &minor, &patch); err != nil {
		t.Fatal(err)
	}
	source := sources(entry)[0].(map[string]any)["id"].(string)
	body["crossing"] = map[string]any{
		"change":  map[string]any{"version": subject["to"], "basis": "REMOVED_IN_RELEASE", "sourceId": source},
		"horizon": map[string]any{"lt": fmt.Sprintf("%d.%d.0", major, minor+2), "basis": "REVIEWED_THROUGH_MINOR_LINE", "sourceId": source},
	}
	setRuleID(t, entry, "crossing-test.removal.synthetic")
	return entry
}

func crossingObject(entry map[string]any) map[string]any {
	return rule(entry)["crossing"].(map[string]any)
}

// crossingBody reads the candidate's rule as the gate sees it.
func crossingBody(t *testing.T, entry map[string]any) ruleBody {
	t.Helper()
	raw, err := json.Marshal(rule(entry))
	if err != nil {
		t.Fatal(err)
	}
	var body ruleBody
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	return body
}

// minorOf returns the candidate's change version as major and minor.
func minorOf(t *testing.T, entry map[string]any) (int, int) {
	t.Helper()
	var major, minor, patch int
	if _, err := fmt.Sscanf(crossingObject(entry)["change"].(map[string]any)["version"].(string), "%d.%d.%d", &major, &minor, &patch); err != nil {
		t.Fatal(err)
	}
	return major, minor
}

// TestRulecheckCrossingGate: the candidate is accepted, and every unsafe shape
// is rejected by the gate itself with a message specific to that shape. Each
// case is checked three ways: crossingProblems on its own (so the gate is
// pinned without the engine behind it), the "crossing" finding Validate
// reports, and, for the shapes the engine's parser also refuses, the
// engine-rejected finding (so the gate and the engine cannot drift apart).
func TestRulecheckCrossingGate(t *testing.T) {
	result, err := Validate(candidateFile(t, crossingCandidate(t)), Options{})
	if err != nil || !result.Valid {
		t.Fatalf("valid crossing candidate rejected: err=%v findings=%+v", err, result.Findings)
	}
	if problems := crossingProblems(crossingBody(t, crossingCandidate(t))); len(problems) != 0 {
		t.Fatalf("gate rejects the valid candidate: %v", problems)
	}
	sub := func(entry map[string]any, name string) map[string]any {
		return crossingObject(entry)[name].(map[string]any)
	}
	// restored sets a well-formed restoration of the given version.
	restored := func(e map[string]any, version string) {
		crossingObject(e)["restored"] = map[string]any{"version": version, "basis": "RESTORED_IN_RELEASE", "sourceId": sub(e, "change")["sourceId"]}
	}
	// minorAbove is C plus n minor lines, a minor-line start.
	minorAbove := func(t *testing.T, e map[string]any, n int) string {
		major, minor := minorOf(t, e)
		return fmt.Sprintf("%d.%d.0", major, minor+n)
	}
	type shape struct {
		mutate func(*testing.T, map[string]any)
		want   string // message fragment only this check can produce
		// engine is false for a shape the gate refuses and the engine's
		// parser would accept.
		engine bool
	}
	cases := map[string]shape{
		"uncited horizon: empty source":   {func(_ *testing.T, e map[string]any) { sub(e, "horizon")["sourceId"] = "" }, "horizon.sourceId", true},
		"uncited horizon: foreign source": {func(_ *testing.T, e map[string]any) { sub(e, "horizon")["sourceId"] = "invented-source" }, "horizon.sourceId", true},
		"uncited change":                  {func(_ *testing.T, e map[string]any) { sub(e, "change")["sourceId"] = "invented-source" }, "change.sourceId", true},
		"infinite horizon: empty":         {func(_ *testing.T, e map[string]any) { sub(e, "horizon")["lt"] = "" }, "open-ended horizon is rejected", true},
		"infinite horizon: wildcard":      {func(_ *testing.T, e map[string]any) { sub(e, "horizon")["lt"] = "*" }, "open-ended horizon is rejected", true},
		"infinite horizon: pre-release":   {func(_ *testing.T, e map[string]any) { sub(e, "horizon")["lt"] = "99.0.0-rc.1" }, "open-ended horizon is rejected", true},
		"horizon 999.0.0":                 {func(_ *testing.T, e map[string]any) { sub(e, "horizon")["lt"] = "999.0.0" }, "at most 12 minor lines", true},
		"horizon in the next major line":  {func(_ *testing.T, e map[string]any) { sub(e, "horizon")["lt"] = "2.0.0" }, "at most 12 minor lines", true},
		"horizon past the limit": {func(t *testing.T, e map[string]any) {
			sub(e, "horizon")["lt"] = minorAbove(t, e, 13)
		}, "at most 12 minor lines", true},
		"horizon not a minor-line start": {func(t *testing.T, e map[string]any) {
			sub(e, "horizon")["lt"] = strings.TrimSuffix(minorAbove(t, e, 2), ".0") + ".1"
		}, "horizon.lt \"", true},
		"horizon below change": {func(_ *testing.T, e map[string]any) { sub(e, "horizon")["lt"] = "1.1.0" }, "horizon.lt must be above", true},
		"horizon basis wrong":  {func(_ *testing.T, e map[string]any) { sub(e, "horizon")["basis"] = "TARGET_SERIES" }, "crossing.horizon.basis", true},
		"change basis changed not removed": {func(_ *testing.T, e map[string]any) {
			sub(e, "change")["basis"] = "CHANGED_IN_RELEASE"
		}, "crossing.change.basis", true},
		"change not a minor-line start": {func(t *testing.T, e map[string]any) {
			major, minor := minorOf(t, e)
			sub(e, "change")["version"] = fmt.Sprintf("%d.%d.3", major, minor)
		}, "change.version \"", true},
		"anchor does not cross the change version": {func(t *testing.T, e map[string]any) {
			major, minor := minorOf(t, e)
			rule(e)["subject"].(map[string]any)["to"] = fmt.Sprintf("%d.%d.9", major, minor-1)
		}, "must cross crossing.change.version", true},
		"wrong operator": {func(_ *testing.T, e map[string]any) {
			rule(e)["operator"] = "forbid_target_version"
			delete(rule(e), "condition")
			delete(rule(e), "setCondition")
		}, "only valid on forbid_predicate_value", true},
		"consensus basis": {func(_ *testing.T, e map[string]any) { rule(e)["evidence"].(map[string]any)["basis"] = "consensus" }, "cannot sit on a consensus or lead rule", true},
		"restored bad basis": {func(t *testing.T, e map[string]any) {
			restored(e, minorAbove(t, e, 1))
			crossingObject(e)["restored"].(map[string]any)["basis"] = "REMOVED_IN_RELEASE"
		}, "crossing.restored.basis", true},
		"restored uncited": {func(t *testing.T, e map[string]any) {
			restored(e, minorAbove(t, e, 1))
			crossingObject(e)["restored"].(map[string]any)["sourceId"] = "invented-source"
		}, "restored.sourceId", true},
		"restored not finite": {func(_ *testing.T, e map[string]any) { restored(e, "*") }, "restored.version \"*\"", true},
		"restored a patch": {func(t *testing.T, e map[string]any) {
			restored(e, strings.TrimSuffix(minorAbove(t, e, 1), ".0")+".4")
		}, "restored.version \"", true},
		"restored at the change version": {func(t *testing.T, e map[string]any) { restored(e, minorAbove(t, e, 0)) }, "restored.version must be above crossing.change.version", true},
		"restored above the horizon":     {func(t *testing.T, e map[string]any) { restored(e, minorAbove(t, e, 3)) }, "restored.version must not be above crossing.horizon.lt", true},
		"restored below the range end": {func(t *testing.T, e map[string]any) {
			// A range wider than the engine's width cap, so the rule keeps
			// the gate's own message distinct from the range checks.
			major, minor := minorOf(t, e)
			rule(e)["range"] = map[string]any{
				"from": map[string]any{"gte": fmt.Sprintf("%d.%d.0", major, minor-1), "lt": minorAbove(t, e, 0)},
				"to":   map[string]any{"gte": minorAbove(t, e, 0), "lt": minorAbove(t, e, 2)},
			}
			restored(e, minorAbove(t, e, 1))
		}, "must not be below the end of the rule's range target side", true},
		"range pins another release": {func(t *testing.T, e map[string]any) {
			major, minor := minorOf(t, e)
			rule(e)["range"] = map[string]any{
				"from": map[string]any{"gte": fmt.Sprintf("%d.%d.0", major, minor-1), "lt": fmt.Sprintf("%d.%d.0", major, minor-1)},
				"to":   map[string]any{"gte": minorAbove(t, e, 0), "lt": minorAbove(t, e, 1)},
			}
		}, "must equal range.from.lt and range.to.gte", true},
		"distributions empty":      {func(_ *testing.T, e map[string]any) { crossingObject(e)["distributions"] = []any{} }, "must be non-empty when present", true},
		"distributions unreviewed": {func(_ *testing.T, e map[string]any) { crossingObject(e)["distributions"] = []any{"eks"} }, "is not a reviewed distribution", true},
		"distributions unsorted":   {func(_ *testing.T, e map[string]any) { crossingObject(e)["distributions"] = []any{"upstream", "gke"} }, "strictly ascending", true},
		"distributions duplicate":  {func(_ *testing.T, e map[string]any) { crossingObject(e)["distributions"] = []any{"gke", "gke"} }, "strictly ascending", true},
	}
	for name, tc := range cases {
		entry := crossingCandidate(t)
		tc.mutate(t, entry)
		if problems := strings.Join(crossingProblems(crossingBody(t, entry)), "\n"); !strings.Contains(problems, tc.want) {
			t.Errorf("%s: the gate alone does not produce %q: %q", name, tc.want, problems)
		}
		result, err := Validate(candidateFile(t, entry), Options{})
		if err != nil || result.Valid {
			t.Errorf("%s: err=%v valid=%v", name, err, result.Valid)
			continue
		}
		var gate bool
		for _, finding := range result.Findings {
			if finding.Check == "crossing" && strings.Contains(finding.Message, tc.want) {
				gate = true
			}
		}
		if !gate {
			t.Errorf("%s: no crossing finding with %q: %+v", name, tc.want, result.Findings)
		}
		if tc.engine && !strings.Contains(checks(result), "engine-rejected") {
			t.Errorf("%s: the gate refuses it but the engine's parser does not: %s", name, checks(result))
		}
	}
	// Shapes the closed rule schema refuses before the gate runs.
	structural := map[string]func(map[string]any){
		"distributions wrong type":    func(e map[string]any) { crossingObject(e)["distributions"] = "gke" },
		"unknown key inside crossing": func(e map[string]any) { crossingObject(e)["open"] = true },
		"unknown key inside horizon":  func(e map[string]any) { sub(e, "horizon")["gte"] = "1.0.0" },
	}
	for name, mutate := range structural {
		entry := crossingCandidate(t)
		mutate(entry)
		if result, err := Validate(candidateFile(t, entry), Options{}); err != nil || result.Valid {
			t.Errorf("%s: err=%v valid=%v", name, err, result.Valid)
		}
	}
	accepted := map[string]func(*testing.T, map[string]any){
		"restored at the horizon": func(t *testing.T, e map[string]any) { restored(e, sub(e, "horizon")["lt"].(string)) },
		"restored inside":         func(t *testing.T, e map[string]any) { restored(e, minorAbove(t, e, 1)) },
		"horizon at the limit":    func(t *testing.T, e map[string]any) { sub(e, "horizon")["lt"] = minorAbove(t, e, 12) },
		"distributions":           func(_ *testing.T, e map[string]any) { crossingObject(e)["distributions"] = []any{"gke", "upstream"} },
	}
	for name, mutate := range accepted {
		entry := crossingCandidate(t)
		mutate(t, entry)
		if problems := crossingProblems(crossingBody(t, entry)); len(problems) != 0 {
			t.Errorf("%s: the gate rejects it: %v", name, problems)
		}
		if result, err := Validate(candidateFile(t, entry), Options{}); err != nil || !result.Valid {
			t.Errorf("%s: rejected: err=%v findings=%+v", name, err, result.Findings)
		}
	}
}

// TestRulecheckCrossingGateIsExercised: Validate applies the gate for the
// community path and for the maintainer self-check alike, and reports the
// gate's message, not just the engine's. The shapes the gate refuses on its
// own are pinned case by case in TestRulecheckCrossingGate; this keeps the
// two option paths honest.
func TestRulecheckCrossingGateIsExercised(t *testing.T) {
	entry := crossingCandidate(t)
	crossingObject(entry)["horizon"].(map[string]any)["sourceId"] = ""
	for _, opts := range []Options{{}, {AllowRange: true}} {
		result, err := Validate(candidateFile(t, entry), opts)
		if err != nil || result.Valid || !strings.Contains(checks(result), "crossing") {
			t.Fatalf("opts=%+v: err=%v valid=%v checks=%s", opts, err, result.Valid, checks(result))
		}
		var message bool
		for _, finding := range result.Findings {
			message = message || finding.Check == "crossing" && strings.Contains(finding.Message, "horizon.sourceId")
		}
		if !message {
			t.Fatalf("opts=%+v: no gate message about the horizon citation: %+v", opts, result.Findings)
		}
	}
}
