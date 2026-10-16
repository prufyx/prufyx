// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"errors"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

type budgetStub struct {
	Source
	api int64
}

func (s *budgetStub) Stats() GitHubStats { return GitHubStats{APIRequests: s.api} }
func (s *budgetStub) Read(extract.RepoRef, string, string) ([]byte, error) {
	return nil, nil
}

// The per-project dry-run budget is a decision of the owner; moving it is a
// reviewed change of this test too. The run budget (--rest-budget) is separate.
func TestOnboardingProjectBudgetValues(t *testing.T) {
	if OnboardingRESTBudget != 250 || OnboardingReadBudget != 3000 {
		t.Fatalf("per-project budget is %d REST / %d reads, want 250 / 3000", OnboardingRESTBudget, OnboardingReadBudget)
	}
}

// A project that reaches either limit is refused from then on: no read after
// the limit succeeds and the source stays over.
func TestBudgetSourceStopsAtEitherLimit(t *testing.T) {
	st := &budgetStub{}
	b := &budgetSource{src: st, stats: st}
	for i := 0; i < OnboardingReadBudget; i++ {
		if _, err := b.Read(extract.RepoRef{}, "", ""); err != nil {
			t.Fatalf("read %d refused early: %v", i, err)
		}
	}
	if _, err := b.Read(extract.RepoRef{}, "", ""); !errors.Is(err, errOnboardingBudget) || !b.over {
		t.Fatalf("read past the read budget: err=%v over=%v", err, b.over)
	}

	st2 := &budgetStub{}
	b2 := &budgetSource{src: st2, stats: st2}
	st2.api = OnboardingRESTBudget
	if _, err := b2.Read(extract.RepoRef{}, "", ""); !errors.Is(err, errOnboardingBudget) {
		t.Fatalf("read at the REST budget: %v", err)
	}
	st2.api = 0
	if _, err := b2.Read(extract.RepoRef{}, "", ""); !errors.Is(err, errOnboardingBudget) {
		t.Fatalf("a project that went over stays refused: %v", err)
	}
}
