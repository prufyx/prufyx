// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"slices"
	"sort"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract/crdbatchids"
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

// checkBatchClaims fails unless the claims of the JSON CNCF check report
// stdout that name a rule of the batch are exactly want, each UNKNOWN.
func checkBatchClaims(t *testing.T, stdout string, want []string) {
	t.Helper()
	var report struct {
		Check struct {
			Claims []struct {
				RuleID string `json:"ruleId"`
				Status string `json:"status"`
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
		if claim.Status != "UNKNOWN" {
			t.Fatalf("batch claim %s is %s", claim.RuleID, claim.Status)
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
// reviewed pair of exact (an exact-pair rule) holds what that hop gets:
// before the batch ships, the exact rule's UNKNOWN claim for an unreviewed
// transition; once a batch rule's range covers the hop, the claims of the
// rules that match it (every batch rule of project, UNKNOWN) and none of
// the exact rule. The exit is 11 either way.
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
	if want := map[bool]int{true: 0, false: 1}[len(ids) > 0]; exactClaims != want || len(report.Check.Claims) != want+len(ids) {
		t.Fatalf("off-pair claims %+v, want %d of %s and %d of the batch", report.Check.Claims, want, exact, len(ids))
	}
}

// kyvernoLatestBatchRuleIDs are the custom-resource batch rules a Kyverno hop
// from origin to 1.19.1 (or 1.19.2) crosses without being their reviewed
// pair: the UpdateRequest v1beta1 removal at 1.16 lies on the hops from
// 1.14.5 and 1.15.3, not on the later ones. Their claims are UNKNOWN.
func kyvernoLatestBatchRuleIDs(origin string) []string {
	if origin == "1.14.5" || origin == "1.15.3" {
		return batchRuleIDs("kyverno")
	}
	return nil
}

// batchClaimStatuses maps every claim of the JSON CNCF check report stdout
// to its status; a claim of a rule outside the batch fails the test.
func batchClaimStatuses(t *testing.T, stdout string) map[string]string {
	t.Helper()
	var report struct {
		Check struct {
			Claims []struct {
				RuleID string `json:"ruleId"`
				Status string `json:"status"`
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
		out[claim.RuleID] = claim.Status
	}
	return out
}
