// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"slices"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract/crdbatchids"
	"github.com/prufyx/prufyx/cli/internal/testclock"
)

// The custom-resource version-removal rules of the batch crdbatchids states
// read the custom-resource version set, which the native routes of the
// project checks below do not supply. Once the shipped pack holds the batch,
// a report of such a route over a hop one of them matches therefore also
// holds their claims, each UNKNOWN; a scoped PASS of the reviewed rule then
// no longer exits 0 but 11. Before the batch ships the report holds no such
// claim. The helpers state both cases exactly.

// batchRuleIDs are the ids of the batch's rules of project that the shipped
// pack holds: all of them once the batch ships, none before.
func batchRuleIDs(project string) []string {
	if !crdbatchids.Shipped() {
		return nil
	}
	var ids []string
	for _, r := range crdbatchids.ProjectRules(project) {
		ids = append(ids, r.ID)
	}
	return ids
}

// passExit is the exit of a JSON report whose reviewed claims pass and
// whose batch claims are batchIDs: 0 without batch claims, 11 with them.
func passExit(batchIDs []string) int {
	if len(batchIDs) == 0 {
		return ExitOK
	}
	return ExitUnknown
}

// batchBeforeReview is the reason of a batch claim at an evaluation time
// before the batch rule's review; batchAfterReview are its reasons at or
// after the review: the native routes do not supply the custom-resource
// version set the rule reads. The tests' clocks follow the newest review of
// the project's rules (testclock), which a renewal moves past the batch's own
// review, so which of the two a claim holds is derived from the claim's own
// review time and the report's evaluation time, never from a pinned date.
const (
	batchBeforeReview = "RULE_EVIDENCE_CLOCK_BEFORE_REVIEW"
)

// batchAfterReview are the reasons of a batch claim at or after its review: the
// rule is in force and still UNKNOWN, because the native route does not
// supply the version set it reads (RULE_FACT_UNAVAILABLE) or the hop lies
// outside the range the rule reviewed. Anything else fails.
var batchAfterReview = []string{
	"RULE_FACT_UNAVAILABLE",
	"RULE_RELEASE_BOUNDARY_NOT_REVIEWED",
	"RULE_TRANSITION_NOT_REVIEWED",
}

// batchReasonOK reports whether reason is the reason a batch claim reviewed at
// reviewedAt holds in a report evaluated at evaluatedAt (both RFC 3339): exactly
// batchBeforeReview before the review, one of batchAfterReview from it on.
func batchReasonOK(t *testing.T, evaluatedAt, reviewedAt, reason string) bool {
	t.Helper()
	now, err := time.Parse(time.RFC3339, evaluatedAt)
	if err != nil {
		t.Fatalf("report evaluatedAt %q: %v", evaluatedAt, err)
	}
	reviewed, err := time.Parse(time.RFC3339, reviewedAt)
	if err != nil {
		t.Fatalf("claim evidenceReviewedAt %q: %v", reviewedAt, err)
	}
	if now.Before(reviewed) {
		return reason == batchBeforeReview
	}
	return slices.Contains(batchAfterReview, reason)
}

// checkBatchClaims fails unless the claims of the JSON CNCF check report
// stdout that name a rule of the batch are exactly want, each UNKNOWN with
// reason batchBeforeReview.
func checkBatchClaims(t *testing.T, stdout string, want []string) {
	t.Helper()
	var report struct {
		Check struct {
			EvaluatedAt string `json:"evaluatedAt"`
			Claims      []struct {
				RuleID             string `json:"ruleId"`
				Status             string `json:"status"`
				ReasonCode         string `json:"reasonCode"`
				EvidenceReviewedAt string `json:"evidenceReviewedAt"`
			} `json:"claims"`
		} `json:"check"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("report: %v", err)
	}
	batch := map[string]bool{}
	for _, id := range crdbatchids.IDs() {
		batch[id] = true
	}
	var got []string
	for _, claim := range report.Check.Claims {
		if !batch[claim.RuleID] {
			continue
		}
		if claim.Status != "UNKNOWN" || !batchReasonOK(t, report.Check.EvaluatedAt, claim.EvidenceReviewedAt, claim.ReasonCode) {
			t.Fatalf("batch claim %s is %s %s", claim.RuleID, claim.Status, claim.ReasonCode)
		}
		got = append(got, claim.RuleID)
	}
	sort.Strings(got)
	wanted := append([]string(nil), want...)
	sort.Strings(wanted)
	if !slices.Equal(got, wanted) {
		t.Fatalf("batch claims %v, want %v", got, wanted)
	}
}

// checkOffPairReport fails unless a JSON report over a hop next to the
// reviewed pair of exact (an exact-pair rule) holds what that hop gets: the
// exact rule's UNKNOWN claim for an unreviewed transition, and, once a batch
// rule's range covers the hop, also the claims of the rules that match it
// (every batch rule of project, UNKNOWN). The exit is 11 either way.
func checkOffPairReport(t *testing.T, code int, stdout, project, exact string) {
	t.Helper()
	if code != ExitUnknown {
		t.Fatalf("off-pair code=%d stdout=%q", code, stdout)
	}
	ids := batchRuleIDs(project)
	checkBatchClaims(t, stdout, ids)
	var report struct {
		Check struct {
			Claims []struct {
				RuleID     string `json:"ruleId"`
				Status     string `json:"status"`
				ReasonCode string `json:"reasonCode"`
			} `json:"claims"`
		} `json:"check"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatal(err)
	}
	exactClaims := 0
	for _, claim := range report.Check.Claims {
		if claim.RuleID == exact {
			exactClaims++
			if claim.Status != "UNKNOWN" || claim.ReasonCode != "RULE_TRANSITION_NOT_REVIEWED" {
				t.Fatalf("exact rule claim %+v", claim)
			}
		}
	}
	if exactClaims != 1 || len(report.Check.Claims) != 1+len(ids) {
		t.Fatalf("off-pair claims %+v, want one of %s and %d of the batch", report.Check.Claims, exact, len(ids))
	}
}

// kyvernoLatestBatchRuleIDs are the custom-resource batch rules a Kyverno
// report from origin to target holds, each UNKNOWN. On the reviewed target
// 1.19.1 they are the rules whose boundary the hop crosses without being
// their reviewed pair: the UpdateRequest v1beta1 removal at 1.16 lies on the
// hops from 1.14.5 and 1.15.3, not on the later ones. On another target no
// rule matches the hop, so the report holds every rule of the project, the
// batch's included.
func kyvernoLatestBatchRuleIDs(origin, target string) []string {
	if target != "1.19.1" || origin == "1.14.5" || origin == "1.15.3" {
		return batchRuleIDs("kyverno")
	}
	return nil
}

// batchClaimStatuses maps every claim of the JSON CNCF check report stdout
// to its status; a claim of a rule outside the batch fails the test, and so
// does an UNKNOWN claim for any reason but an incomplete set (the reason a
// set rule gives when the set is not declared complete).
func batchClaimStatuses(t *testing.T, stdout string) map[string]string {
	t.Helper()
	var report struct {
		Check struct {
			Claims []struct {
				RuleID     string `json:"ruleId"`
				Status     string `json:"status"`
				ReasonCode string `json:"reasonCode"`
			} `json:"claims"`
		} `json:"check"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("report: %v", err)
	}
	batch := map[string]bool{}
	for _, id := range crdbatchids.IDs() {
		batch[id] = true
	}
	out := map[string]string{}
	for _, claim := range report.Check.Claims {
		if !batch[claim.RuleID] {
			t.Fatalf("claim of %s, which is not a batch rule", claim.RuleID)
		}
		if claim.Status == "UNKNOWN" && claim.ReasonCode != "RULE_SET_FACT_INCOMPLETE" {
			t.Fatalf("claim of %s UNKNOWN for %s", claim.RuleID, claim.ReasonCode)
		}
		out[claim.RuleID] = claim.Status
	}
	return out
}

// exactClocks are evaluation clocks a test derived itself and that
// floorNowArgs must keep as they are.
var exactClocks sync.Map

// exactClock registers at as a clock that is never floored and returns its text.
func exactClock(at time.Time) string {
	text := at.UTC().Format(time.RFC3339)
	exactClocks.Store(text, true)
	return text
}

// batchPreReviewClock is the clock of a test whose premise is that the
// project's custom-resource batch rules are not yet reviewed: one hour before
// the earliest review of the project's batch rules in the shipped pack,
// computed from the rule data. A project without batch rules, or a pack that
// does not hold the batch, keeps fallback.
func batchPreReviewClock(project, fallback string) string {
	if !crdbatchids.Shipped() {
		return fallback
	}
	var oldest time.Time
	for _, r := range crdbatchids.ProjectRules(project) {
		reviewed, _ := testclock.RuleEvidence(r.ID)
		at, err := time.Parse(time.RFC3339, reviewed)
		if err != nil {
			panic(err)
		}
		if oldest.IsZero() || at.Before(oldest) {
			oldest = at
		}
	}
	if oldest.IsZero() {
		return fallback
	}
	return exactClock(oldest.Add(-time.Hour))
}
