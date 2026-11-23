// SPDX-License-Identifier: AGPL-3.0-only

package evidencerepin

import (
	"context"
	"strings"
	"testing"
)

type forbiddenResp = struct {
	body   []byte
	status int
}

func forbiddenRun(t *testing.T, first forbiddenResp) (Worklist, *fakeAPIFetcher, *State) {
	t.Helper()
	citations := []Citation{
		{RulePack: "p", RuleID: "r1", Project: "a", SourceID: "s1", Owner: "owner1", Repo: "repoA", Path: "x", OldCommit: commitA, OldDigest: "sha256:x", StartLine: 1, EndLine: 1},
		{RulePack: "p", RuleID: "r2", Project: "b", SourceID: "s2", Owner: "owner2", Repo: "repoB", Path: "x", OldCommit: commitA, OldDigest: "sha256:x", StartLine: 1, EndLine: 1},
	}
	f := &fakeAPIFetcher{responses: map[string]forbiddenResp{
		"/repos/owner1/repoA/releases?per_page=10": first,
		"/repos/owner2/repoB/releases?per_page=10": {[]byte(`[{"id":1,"tag_name":"v1.0.0","draft":false,"prerelease":false}]`), 200},
		"/repos/owner2/repoB/git/ref/tags/v1.0.0":  {[]byte(`{"object":{"sha":"` + commitA + `","type":"commit"}}`), 200},
	}}
	state := newState()
	w, err := BuildWorklist(context.Background(), citations, nil, 0, state, f, fakeBlobFetcher{}, fixedNow(), DefaultMaxAge, nil)
	if err != nil {
		t.Fatalf("BuildWorklist: %v", err)
	}
	return w, f, state
}

func called(f *fakeAPIFetcher, s string) bool {
	for _, c := range f.calls {
		if strings.Contains(c, s) {
			return true
		}
	}
	return false
}

func TestForbiddenNonQuotaRefusesOnlyThatRepo(t *testing.T) {
	w, f, state := forbiddenRun(t, forbiddenResp{[]byte(`{"message":"Resource not accessible by integration","documentation_url":"https://docs.github.com"}`), 403})
	if !called(f, "owner2/repoB") {
		t.Fatalf("next repository was not attempted: %v", f.calls)
	}
	a := state.Repos["owner1/repoA"]
	if a.Status != repoPendingError || !strings.Contains(a.Detail, "REPO_FORBIDDEN") {
		t.Fatalf("repoA not a typed refusal: %+v", a)
	}
	if b := state.Repos["owner2/repoB"]; b.Status != repoResolved {
		t.Fatalf("repoB not resolved: %+v", b)
	}
	if w.Summary.TotalCitations != 2 {
		t.Fatalf("summary %+v", w.Summary)
	}
	sawA := false
	for _, c := range w.Citations {
		if c.Owner == "owner1" {
			sawA = true
			if c.Class != ClassPending {
				t.Fatalf("forbidden repo citation not pending: %+v", c)
			}
		}
	}
	if !sawA {
		t.Fatalf("forbidden repo citation missing from worklist")
	}
	for _, r := range w.Rules {
		if r.RuleID == "r1" && r.BatchEligible {
			t.Fatalf("forbidden repo rule eligible: %+v", r)
		}
	}
	reported := false
	for _, r := range w.Repos {
		if r.Owner == "owner1" && strings.Contains(r.Detail, "REPO_FORBIDDEN") {
			reported = true
		}
	}
	if !reported {
		t.Fatalf("refusal not reported with the repo: %+v", w.Repos)
	}
}

func TestForbiddenRateLimitShapesStopGlobally(t *testing.T) {
	for name, r := range map[string]forbiddenResp{
		"429":         {[]byte(`{"message":"slow down"}`), 429},
		"quota-403":   {[]byte(`{"message":"API rate limit exceeded for user"}`), 403},
		"secondary":   {[]byte(`{"message":"You have exceeded a secondary rate limit."}`), 403},
		"abuse":       {[]byte(`{"message":"You have triggered an abuse detection mechanism"}`), 403},
		"not-json":    {[]byte(`forbidden`), 403},
		"empty":       {nil, 403},
		"extra-field": {[]byte(`{"message":"nope","other":1}`), 403},
		"no-message":  {[]byte(`{"documentation_url":"x"}`), 403},
		"json-array":  {[]byte(`[]`), 403},
		"json-null":   {[]byte(`null`), 403},
	} {
		t.Run(name, func(t *testing.T) {
			_, f, state := forbiddenRun(t, r)
			if called(f, "owner2") {
				t.Fatalf("global stop expected, later repo attempted: %v", f.calls)
			}
			if got := state.Repos["owner1/repoA"].Status; got != repoPendingRateLimited {
				t.Fatalf("status %q, want rate limited", got)
			}
		})
	}
}
