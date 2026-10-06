// SPDX-License-Identifier: AGPL-3.0-only

package rulecheck

import (
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

// TestRulecheckCrossingGate: the candidate is accepted, and every unsafe
// shape is rejected by the rulecheck gate itself (the finding carries the
// "crossing" check), not merely by the engine parse behind it.
func TestRulecheckCrossingGate(t *testing.T) {
	result, err := Validate(candidateFile(t, crossingCandidate(t)), Options{})
	if err != nil || !result.Valid {
		t.Fatalf("valid crossing candidate rejected: err=%v findings=%+v", err, result.Findings)
	}
	sub := func(entry map[string]any, name string) map[string]any {
		return crossingObject(entry)[name].(map[string]any)
	}
	cases := map[string]func(map[string]any){
		"uncited horizon: empty source":    func(e map[string]any) { sub(e, "horizon")["sourceId"] = "" },
		"uncited horizon: foreign source":  func(e map[string]any) { sub(e, "horizon")["sourceId"] = "invented-source" },
		"uncited change":                   func(e map[string]any) { sub(e, "change")["sourceId"] = "invented-source" },
		"infinite horizon: empty":          func(e map[string]any) { sub(e, "horizon")["lt"] = "" },
		"infinite horizon: wildcard":       func(e map[string]any) { sub(e, "horizon")["lt"] = "*" },
		"infinite horizon: pre-release":    func(e map[string]any) { sub(e, "horizon")["lt"] = "99.0.0-rc.1" },
		"horizon below change":             func(e map[string]any) { sub(e, "horizon")["lt"] = "1.1.0" },
		"horizon basis wrong":              func(e map[string]any) { sub(e, "horizon")["basis"] = "TARGET_SERIES" },
		"change basis changed not removed": func(e map[string]any) { sub(e, "change")["basis"] = "CHANGED_IN_RELEASE" },
		"wrong operator": func(e map[string]any) {
			rule(e)["operator"] = "forbid_target_version"
			delete(rule(e), "condition")
			delete(rule(e), "setCondition")
		},
		"consensus basis": func(e map[string]any) { rule(e)["evidence"].(map[string]any)["basis"] = "consensus" },
		"restored bad basis": func(e map[string]any) {
			crossingObject(e)["restored"] = map[string]any{"version": "99.0.0", "basis": "REMOVED_IN_RELEASE", "sourceId": sub(e, "change")["sourceId"]}
		},
		"restored uncited": func(e map[string]any) {
			crossingObject(e)["restored"] = map[string]any{"version": "1.30.0", "basis": "RESTORED_IN_RELEASE", "sourceId": "invented-source"}
		},
		"distributions empty":         func(e map[string]any) { crossingObject(e)["distributions"] = []any{} },
		"distributions unreviewed":    func(e map[string]any) { crossingObject(e)["distributions"] = []any{"eks"} },
		"distributions unsorted":      func(e map[string]any) { crossingObject(e)["distributions"] = []any{"upstream", "gke"} },
		"distributions duplicate":     func(e map[string]any) { crossingObject(e)["distributions"] = []any{"gke", "gke"} },
		"distributions wrong type":    func(e map[string]any) { crossingObject(e)["distributions"] = "gke" },
		"unknown key inside crossing": func(e map[string]any) { crossingObject(e)["open"] = true },
		"unknown key inside horizon":  func(e map[string]any) { sub(e, "horizon")["gte"] = "1.0.0" },
	}
	// Findings the gate itself must produce; the others are structural and
	// are refused by the closed rule schema before the gate runs.
	structural := map[string]bool{"distributions wrong type": true, "unknown key inside crossing": true, "unknown key inside horizon": true}
	for name, mutate := range cases {
		entry := crossingCandidate(t)
		mutate(entry)
		result, err := Validate(candidateFile(t, entry), Options{})
		if err != nil || result.Valid {
			t.Errorf("%s: err=%v valid=%v", name, err, result.Valid)
			continue
		}
		if !structural[name] && !strings.Contains(checks(result), "crossing") {
			t.Errorf("%s: rejected, but not by the crossing gate: %s", name, checks(result))
		}
	}
	accepted := map[string]func(map[string]any){
		"restored": func(e map[string]any) {
			crossingObject(e)["restored"] = map[string]any{"version": sub(e, "horizon")["lt"], "basis": "RESTORED_IN_RELEASE", "sourceId": sub(e, "change")["sourceId"]}
		},
		"distributions": func(e map[string]any) { crossingObject(e)["distributions"] = []any{"gke", "upstream"} },
	}
	for name, mutate := range accepted {
		entry := crossingCandidate(t)
		mutate(entry)
		if result, err := Validate(candidateFile(t, entry), Options{}); err != nil || !result.Valid {
			t.Errorf("%s: rejected: err=%v findings=%+v", name, err, result.Findings)
		}
	}
}

// TestRulecheckCrossingGateMutation: the gate does the rejecting. With the
// gate's findings removed from the picture (AllowRange maintainer self-check
// still applies it), a gate-only unsafe shape would pass the engine parse
// only if the engine were the sole guard; this pins the gate by asserting
// the finding set of each gate-only shape contains "crossing".
func TestRulecheckCrossingGateMutation(t *testing.T) {
	entry := crossingCandidate(t)
	crossingObject(entry)["horizon"].(map[string]any)["sourceId"] = ""
	for _, opts := range []Options{{}, {AllowRange: true}} {
		result, err := Validate(candidateFile(t, entry), opts)
		if err != nil || result.Valid || !strings.Contains(checks(result), "crossing") {
			t.Fatalf("opts=%+v: err=%v valid=%v checks=%s", opts, err, result.Valid, checks(result))
		}
	}
}
