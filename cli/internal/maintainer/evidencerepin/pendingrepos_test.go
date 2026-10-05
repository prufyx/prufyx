// SPDX-License-Identifier: AGPL-3.0-only

package evidencerepin

import "testing"

func TestPendingRepositoriesCountsRulesPerRepository(t *testing.T) {
	results := []ClassResult{
		{RulePack: "p1", RuleID: "r1", SourceID: "a", Owner: "o", Repo: "x", Class: ClassPending},
		{RulePack: "p1", RuleID: "r1", SourceID: "b", Owner: "o", Repo: "x", Class: ClassPending},
		{RulePack: "p1", RuleID: "r2", SourceID: "a", Owner: "o", Repo: "x", Class: ClassPending},
		{RulePack: "p2", RuleID: "r1", SourceID: "a", Owner: "o", Repo: "x", Class: ClassPending},
		{RulePack: "p1", RuleID: "r3", SourceID: "a", Owner: "o", Repo: "y", Class: ClassFileIdentical},
		{RulePack: "p1", RuleID: "r4", SourceID: "a", Owner: "o", Repo: "a", Class: ClassPending},
	}
	repos := []RepoResolution{{Owner: "o", Repo: "x", Status: repoPendingAmbiguous}, {Owner: "o", Repo: "a", Status: repoPendingError}}
	got := pendingRepositories(results, repos)
	want := []PendingRepository{
		{Repo: "o/a", Status: repoPendingError, Rules: 1, Citations: 1},
		{Repo: "o/x", Status: repoPendingAmbiguous, Rules: 3, Citations: 4},
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if len(pendingRepositories(nil, nil)) != 0 {
		t.Fatal("no pending citations must give an empty list")
	}
}
