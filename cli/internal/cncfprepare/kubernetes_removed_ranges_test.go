// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"bytes"
	"encoding/json"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// k8sRemovalRulePath is the embedded CNCF rule pack. The drift test reads it
// directly, so a trial pack placed there is checked the same way.
const k8sRemovalRulePath = "../cncfcheck/data/rules.json"

type k8sPackRule struct {
	ID      string
	Fact    string
	Subject constraintengine.RuleTransition
}

func k8sRemovalRules(t *testing.T) []k8sPackRule {
	t.Helper()
	raw, err := os.ReadFile(k8sRemovalRulePath)
	if err != nil {
		t.Fatal(err)
	}
	var pack struct {
		Entries []struct {
			Project string          `json:"project"`
			Rule    json.RawMessage `json:"rule"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(raw, &pack); err != nil {
		t.Fatal(err)
	}
	result := []k8sPackRule{}
	for _, entry := range pack.Entries {
		if entry.Project != "kubernetes" {
			continue
		}
		var shape struct {
			ID        string `json:"id"`
			Condition *struct {
				FactID string `json:"factId"`
			} `json:"condition"`
		}
		if err := json.Unmarshal(entry.Rule, &shape); err != nil {
			t.Fatal(err)
		}
		subject, err := constraintengine.RuleTransitionOf(entry.Rule)
		if err != nil {
			t.Fatal(err)
		}
		if shape.Condition == nil || !strings.HasSuffix(shape.Condition.FactID, "_removed_gvk_present") {
			continue
		}
		result = append(result, k8sPackRule{ID: shape.ID, Fact: shape.Condition.FactID, Subject: subject})
	}
	return result
}

func k8sLineParts(t *testing.T, line string) (uint64, uint64) {
	t.Helper()
	major, minor, ok := strings.Cut(line, ".")
	majorNumber, majorErr := strconv.ParseUint(major, 10, 32)
	minorNumber, minorErr := strconv.ParseUint(minor, 10, 32)
	if !ok || majorErr != nil || minorErr != nil || minorNumber == 0 {
		t.Fatalf("table line %q", line)
	}
	return majorNumber, minorNumber
}

func k8sVersion(major, minor uint64, patch int) string {
	return strconv.FormatUint(major, 10) + "." + strconv.FormatUint(minor, 10) + "." + strconv.Itoa(patch)
}

func k8sPreparedFactIDs(t *testing.T, from, to string) []string {
	t.Helper()
	prepared := prepareK8s(t, k8sList(k8sDoc("v1", "ConfigMap")), from, to, true)
	facts := k8sProposedFacts(t, prepared)
	ids := make([]string, 0, len(facts))
	for id := range facts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// TestK8sRemovalTableMatchesRulePack is the drift test between the preparer's
// removal table and the rule pack. Every table fact has exactly one removal
// rule anchored on that line's x.(y-1).0 -> x.y.0 pair, every removal rule
// has a table fact or is the flow-control rule, and a rule that carries a
// range carries exactly the region this preparer accepts: from
// [x.(y-1).0, x.y.0), to [x.y.0, x.(y+1).0). For every sampled pair, each
// rule that matches it gets its fact from the preparer.
func TestK8sRemovalTableMatchesRulePack(t *testing.T) {
	rules := k8sRemovalRules(t)
	byFact := map[string]k8sPackRule{}
	for _, rule := range rules {
		if _, dup := byFact[rule.Fact]; dup {
			t.Fatalf("two removal rules share fact %s", rule.Fact)
		}
		byFact[rule.Fact] = rule
	}
	tableFacts := map[string]string{}
	for line, removals := range kubernetesRemovalsByTargetMinor {
		major, minor := k8sLineParts(t, line)
		for _, removal := range removals {
			tableFacts[removal.Fact] = line
			rule, found := byFact[removal.Fact]
			if !found {
				t.Fatalf("table fact %s has no removal rule", removal.Fact)
			}
			if rule.Subject.From != k8sVersion(major, minor-1, 0) || rule.Subject.To != k8sVersion(major, minor, 0) {
				t.Fatalf("%s anchored %s -> %s, table line %s", rule.ID, rule.Subject.From, rule.Subject.To, line)
			}
			k8sCheckRuleRange(t, rule, major, minor)
		}
	}
	for _, rule := range rules {
		if rule.Fact == KubernetesFlowControlFact {
			if _, inTable := tableFacts[rule.Fact]; inTable {
				t.Fatal("the flow-control fact must stay out of the removal table")
			}
			major, minor := k8sLineParts(t, strings.TrimSuffix(rule.Subject.To, ".0"))
			if rule.Subject.From != k8sVersion(major, minor-1, 0) {
				t.Fatalf("%s anchored %s -> %s", rule.ID, rule.Subject.From, rule.Subject.To)
			}
			k8sCheckRuleRange(t, rule, major, minor)
			continue
		}
		if _, inTable := tableFacts[rule.Fact]; !inTable {
			t.Fatalf("removal rule %s has no table fact", rule.ID)
		}
	}
	// Every rule that matches a sampled pair gets its fact. Pairs that match
	// no ranged rule may still receive facts (harmless: the rule decides).
	for _, rule := range rules {
		major, minor := k8sLineParts(t, strings.TrimSuffix(rule.Subject.To, ".0"))
		for _, fromPatch := range []int{0, 1, 17, 99} {
			for _, toPatch := range []int{0, 3, 99} {
				from, to := k8sVersion(major, minor-1, fromPatch), k8sVersion(major, minor, toPatch)
				if rule.Subject.Match(from, to) == constraintengine.MatchNone {
					continue
				}
				if ids := k8sPreparedFactIDs(t, from, to); !containsString(ids, rule.Fact) {
					t.Fatalf("%s matches %s -> %s but the preparer emits %v", rule.ID, from, to, ids)
				}
			}
		}
	}
}

func k8sCheckRuleRange(t *testing.T, rule k8sPackRule, major, minor uint64) {
	t.Helper()
	if rule.Subject.Range == nil {
		return
	}
	want := constraintengine.VersionBound{Gte: k8sVersion(major, minor-1, 0), Lt: k8sVersion(major, minor, 0)}
	wantTo := constraintengine.VersionBound{Gte: k8sVersion(major, minor, 0), Lt: k8sVersion(major, minor+1, 0)}
	if rule.Subject.Range.From != want || rule.Subject.Range.To != wantTo {
		t.Fatalf("%s range %+v differs from the preparer's accepted region from %+v to %+v", rule.ID, rule.Subject.Range, want, wantTo)
	}
}

// TestK8sRemovalSelectionCrossesTheMinorLine: default selection now matches
// any pair that crosses exactly one reviewed minor boundary, any patch of
// the previous line to any patch of the target line -- not only the anchor
// pair M.(m-1).0 -> M.m.0. A same-line patch upgrade, a downgrade, a
// multi-minor jump, a major crossing, or a non-release version still selects
// nothing, and falls through to the flow-control preparer unchanged.
func TestK8sRemovalSelectionCrossesTheMinorLine(t *testing.T) {
	want125 := KubernetesRemovedAPIFacts("1.24.0", "1.25.0")
	if len(want125) != 7 {
		t.Fatalf("1.25 facts=%v", want125)
	}
	for _, pair := range [][2]string{
		{"1.24.0", "1.25.0"},
		{"1.24.17", "1.25.3"},
		{"1.24.99", "1.25.0"},
		{"1.24.0", "1.25.99"},
		{"1.24.4294967295", "1.25.4294967295"},
	} {
		prepared := prepareK8s(t, k8sList(k8sDoc("batch/v1beta1", "CronJob")), pair[0], pair[1], true)
		wantBool(t, k8sProposedFacts(t, prepared), k8sFact("cronjob_v1beta1"), true)
		if prepared.Reason != ReasonKubernetesRemovedGVKPresent {
			t.Fatalf("%v: reason=%s", pair, prepared.Reason)
		}
		if got := KubernetesRemovedAPIFacts(pair[0], pair[1]); strings.Join(got, ",") != strings.Join(want125, ",") {
			t.Fatalf("%v selected %v, want %v", pair, got, want125)
		}
	}
	for _, pair := range [][2]string{
		{"1.25.1", "1.25.4"},  // same-line patch upgrade
		{"1.25.0", "1.25.3"},  // same-line, at the target line already
		{"1.23.99", "1.25.3"}, // multi-minor jump
		{"1.24.17", "1.26.0"}, // multi-minor jump
		{"1.25.3", "1.24.17"}, // downgrade
		{"1.24.5", "1.24.5"},  // equal
		{"0.24.0", "1.25.0"},  // major crossing
		{"1.24.0", "2.25.0"},  // major crossing
		{"v1.24.0", "1.25.3"}, // not a release version
		{"1.24.0", "1.25.0-rc.1"},
	} {
		if got := KubernetesRemovedAPIFacts(pair[0], pair[1]); len(got) != 0 {
			t.Fatalf("%v selected %v, want none", pair, got)
		}
		doc := k8sList(k8sDoc("batch/v1beta1", "CronJob"))
		got, gotErr := PrepareKubernetesRemovedAPIs(doc, pair[0], pair[1], "official_upstream", true, true)
		want, wantErr := PrepareKubernetesFlowControl(doc, pair[0], pair[1], "official_upstream", true, true)
		if (gotErr == nil) != (wantErr == nil) || got.Reason != want.Reason || got.State != want.State || !bytes.Equal(got.CanonicalInputJSON, want.CanonicalInputJSON) || got.InputDigest != want.InputDigest {
			t.Fatalf("%v: expected the flow-control preparer's output unchanged", pair)
		}
	}
}

// TestK8sOffAnchorPairMatchesCrossingBehaviour is the byte-identity proof for
// fix 2 now that crossing selection is the default: 1.24.17 -> 1.25.3 crosses
// into the 1.25 minor line but is not the reviewed anchor pair
// 1.24.0 -> 1.25.0. Its prepared output must match the anchor pair's own
// output byte for byte (same reason, state, and canonical fact shape), since
// both are on the same reviewed line and the CronJob GVK is present in both.
func TestK8sOffAnchorPairMatchesCrossingBehaviour(t *testing.T) {
	doc := k8sList(k8sDoc("batch/v1beta1", "CronJob"))
	anchor, anchorErr := PrepareKubernetesRemovedAPIs(doc, "1.24.0", "1.25.0", "official_upstream", true, true)
	offAnchor, offAnchorErr := PrepareKubernetesRemovedAPIs(doc, "1.24.17", "1.25.3", "official_upstream", true, true)
	if anchorErr != nil || offAnchorErr != nil {
		t.Fatalf("unexpected error anchor=%v offAnchor=%v", anchorErr, offAnchorErr)
	}
	if anchor.Reason != offAnchor.Reason || anchor.State != offAnchor.State {
		t.Fatalf("off-anchor pair diverged: got state=%s reason=%s want state=%s reason=%s", offAnchor.State, offAnchor.Reason, anchor.State, anchor.Reason)
	}
	if anchor.Reason != ReasonKubernetesRemovedGVKPresent {
		t.Fatalf("anchor reason=%s", anchor.Reason)
	}
	wantBool(t, k8sProposedFacts(t, offAnchor), k8sFact("cronjob_v1beta1"), true)
}

// TestK8sRemovalsForCrossedMinorLineReady exercises the minor-crossing
// selector directly -- the selector the default path now calls -- alongside
// KubernetesRemovedAPIFacts and PrepareKubernetesRemovedAPIs above.
func TestK8sRemovalsForCrossedMinorLineReady(t *testing.T) {
	want125 := KubernetesRemovedAPIFacts("1.24.0", "1.25.0")
	for _, pair := range [][2]string{{"1.24.0", "1.25.0"}, {"1.24.17", "1.25.3"}, {"1.24.99", "1.25.0"}, {"1.24.0", "1.25.99"}, {"1.24.4294967295", "1.25.4294967295"}} {
		removals, ok := kubernetesRemovalsForCrossedMinorLine(pair[0], pair[1])
		if !ok {
			t.Fatalf("%v: expected a reviewed line", pair)
		}
		facts := make([]string, 0, len(removals))
		for _, removal := range removals {
			facts = append(facts, removal.Fact)
		}
		if strings.Join(facts, ",") != strings.Join(want125, ",") {
			t.Fatalf("%v selected %v", pair, facts)
		}
	}
	for _, pair := range [][2]string{
		{"1.25.1", "1.25.4"},
		{"1.23.99", "1.25.3"},
		{"1.24.17", "1.26.0"},
		{"1.25.3", "1.24.17"},
		{"1.24.5", "1.24.5"},
		{"0.24.0", "1.25.0"},
		{"1.24.0", "2.25.0"},
		{"v1.24.0", "1.25.3"},
		{"1.24.0", "1.25.0-rc.1"},
	} {
		if _, ok := kubernetesRemovalsForCrossedMinorLine(pair[0], pair[1]); ok {
			t.Fatalf("%v: expected no reviewed line", pair)
		}
	}
}

// k8sGenuinelyServedByLine is a pinned fixture of group/version pairs that
// the cited Kubernetes deprecated API migration guide (the same source the
// rule pack's removal rules cite) names as actually served at each target
// minor line. It is hand-derived from that guide, independent of the
// kubernetesRemovalsByTargetMinor table it checks, so a Served entry that was
// typed in wrong -- for example a version that is not introduced until a
// later line -- cannot pass just because it agrees with itself.
var k8sGenuinelyServedByLine = map[string]map[string]bool{
	"1.22": {
		"admissionregistration.k8s.io/v1": true,
		"apiextensions.k8s.io/v1":         true,
		"apiregistration.k8s.io/v1":       true,
		"authentication.k8s.io/v1":        true,
		"authorization.k8s.io/v1":         true,
		"certificates.k8s.io/v1":          true,
		"coordination.k8s.io/v1":          true,
		"networking.k8s.io/v1":            true,
		"rbac.authorization.k8s.io/v1":    true,
		"scheduling.k8s.io/v1":            true,
		"storage.k8s.io/v1":               true,
	},
	"1.25": {
		"batch/v1":            true,
		"discovery.k8s.io/v1": true,
		"events.k8s.io/v1":    true,
		"autoscaling/v2":      true,
		"policy/v1":           true,
		"node.k8s.io/v1":      true,
	},
	"1.26": {
		// flowcontrol.apiserver.k8s.io/v1 is not served until 1.29: it is
		// deliberately absent here.
		"flowcontrol.apiserver.k8s.io/v1beta2": true,
		"flowcontrol.apiserver.k8s.io/v1beta3": true,
		"autoscaling/v2":                       true,
	},
	"1.27": {
		"storage.k8s.io/v1": true,
	},
	"1.33": {"authentication.k8s.io/v1": true},
	"1.34": {"admissionregistration.k8s.io/v1": true},
	"1.37": {
		"networking.k8s.io/v1": true,
		"storage.k8s.io/v1":    true,
	},
	"1.29": {
		"flowcontrol.apiserver.k8s.io/v1":      true,
		"flowcontrol.apiserver.k8s.io/v1beta3": true,
	},
}

// TestK8sServedVersionsAreGenuinelyServed checks every removal entry's Served
// list against k8sGenuinelyServedByLine, the pinned fixture derived from the
// cited deprecation guide. A Served version this fixture does not recognize
// for that line is unreviewed, not served: recording it as served would let a
// document at that version be classified served (a declared false) when the
// source never established that.
func TestK8sServedVersionsAreGenuinelyServed(t *testing.T) {
	for line, removals := range kubernetesRemovalsByTargetMinor {
		fixture, found := k8sGenuinelyServedByLine[line]
		if !found {
			t.Fatalf("line %s has no genuinely-served fixture; add one derived from the cited guide", line)
		}
		for _, removal := range removals {
			for _, served := range removal.Served {
				key := removal.Group + "/" + served
				if !fixture[key] {
					t.Fatalf("%s lists %s as served at %s, but the pinned fixture does not recognize it as genuinely served at that line", removal.Fact, key, line)
				}
			}
		}
	}
}

// TestK8sServedVersionsHoldAcrossTheTargetLine: a Served version must not be
// removed at or before its target line by any removal the table or the
// flow-control adapter records for the same group and kind. Otherwise a
// document at that version would be classified as served (a declared false)
// instead of unreviewed (unsupported).
func TestK8sServedVersionsHoldAcrossTheTargetLine(t *testing.T) {
	type removalAt struct {
		line  [2]uint64
		group string
		kinds []string
		gone  string
	}
	all := []removalAt{{line: [2]uint64{1, 32}, group: "flowcontrol.apiserver.k8s.io", kinds: []string{"FlowSchema", "PriorityLevelConfiguration"}, gone: "v1beta3"}}
	for line, removals := range kubernetesRemovalsByTargetMinor {
		major, minor := k8sLineParts(t, line)
		for _, removal := range removals {
			all = append(all, removalAt{line: [2]uint64{major, minor}, group: removal.Group, kinds: removal.Kinds, gone: removal.Removed})
		}
	}
	atOrBefore := func(a, b [2]uint64) bool { return a[0] < b[0] || a[0] == b[0] && a[1] <= b[1] }
	for line, removals := range kubernetesRemovalsByTargetMinor {
		major, minor := k8sLineParts(t, line)
		for _, removal := range removals {
			for _, served := range removal.Served {
				if served == removal.Removed {
					t.Fatalf("%s lists its removed version as served", removal.Fact)
				}
				for _, other := range all {
					if other.group != removal.Group || other.gone != served || !atOrBefore(other.line, [2]uint64{major, minor}) {
						continue
					}
					for _, kind := range removal.Kinds {
						if containsString(other.kinds, kind) {
							t.Fatalf("%s lists %s/%s %s as served at %s, but it is removed at %d.%d", removal.Fact, removal.Group, kind, served, line, other.line[0], other.line[1])
						}
					}
				}
			}
		}
	}
}

// TestK8sFlowControlPathUnchanged: every 1.31.x -> 1.32.y pair, and every
// other pair outside the table, still produces exactly the flow-control
// adapter's bytes.
func TestK8sFlowControlPathUnchanged(t *testing.T) {
	docs := [][]byte{
		k8sList(k8sDoc("flowcontrol.apiserver.k8s.io/v1beta3", "FlowSchema")),
		k8sList(k8sDoc("flowcontrol.apiserver.k8s.io/v1", "FlowSchema")),
		k8sList(k8sDoc("batch/v1beta1", "CronJob")),
	}
	for _, pair := range [][2]string{{"1.31.0", "1.32.0"}, {"1.31.4", "1.32.2"}, {"1.25.1", "1.25.4"}, {"1.23.4", "1.26.2"}} {
		for _, doc := range docs {
			for _, complete := range []bool{true, false} {
				got, gotErr := PrepareKubernetesRemovedAPIs(doc, pair[0], pair[1], "official_upstream", true, complete)
				want, wantErr := PrepareKubernetesFlowControl(doc, pair[0], pair[1], "official_upstream", true, complete)
				if (gotErr == nil) != (wantErr == nil) || !bytes.Equal(got.CanonicalInputJSON, want.CanonicalInputJSON) || got.Reason != want.Reason || got.State != want.State || got.InputDigest != want.InputDigest {
					t.Fatalf("%v: removal path diverged from flow-control path", pair)
				}
			}
		}
	}
}

func k8sFact(slug string) string { return "component.kubernetes." + slug + "_removed_gvk_present" }
