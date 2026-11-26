// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"errors"
	"strings"
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
func (s *budgetStub) List(extract.RepoRef, string, string) ([]extract.TreeEntry, error) {
	return nil, nil
}

// The per-project dry-run budget is a decision of the owner; moving it is a
// reviewed change of this test too. The run budget (--rest-budget) is separate.
func TestOnboardingProjectBudgetValues(t *testing.T) {
	t.Parallel()
	if OnboardingRESTBudget != 250 || OnboardingReadBudget != 3000 || OnboardingListBudget != 10000 {
		t.Fatalf("per-project budget is %d REST / %d reads / %d listings, want 250 / 3000 / 10000", OnboardingRESTBudget, OnboardingReadBudget, OnboardingListBudget)
	}
}

// A project that reaches either limit is refused from then on: no read after
// the limit succeeds and the source stays over.
func TestBudgetSourceStopsAtEitherLimit(t *testing.T) {
	t.Parallel()
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

// A scan lists every directory of a tag (a vendored tree holds hundreds),
// and a listing answered from a cached subtree costs no REST request: such
// listings must not use up the file-read budget, yet stay bounded on their
// own, and stay refused once the project is over.
func TestBudgetSourceListingsAreBoundedApartFromReads(t *testing.T) {
	t.Parallel()
	st := &budgetStub{}
	b := &budgetSource{src: st, stats: st}
	for i := 0; i < OnboardingReadBudget; i++ {
		if _, err := b.List(extract.RepoRef{}, "", ""); err != nil {
			t.Fatalf("listing %d refused early: %v", i, err)
		}
	}
	if _, err := b.Read(extract.RepoRef{}, "", ""); err != nil {
		t.Fatalf("a read refused after %d listings: %v", OnboardingReadBudget, err)
	}
	for i := OnboardingReadBudget; i < OnboardingListBudget; i++ {
		if _, err := b.List(extract.RepoRef{}, "", ""); err != nil {
			t.Fatalf("listing %d refused early: %v", i, err)
		}
	}
	if _, err := b.List(extract.RepoRef{}, "", ""); !errors.Is(err, errOnboardingBudget) || !b.over {
		t.Fatalf("listing past the listing budget: err=%v over=%v", err, b.over)
	}
	if _, err := b.Read(extract.RepoRef{}, "", ""); !errors.Is(err, errOnboardingBudget) {
		t.Fatalf("a project that went over stays refused: %v", err)
	}
}

// Reads cannot be traded against listings: the read budget still holds when
// no listing was made, and the REST limit still stops a listing.
func TestBudgetSourceReadLimitAndRESTLimitStillHold(t *testing.T) {
	t.Parallel()
	st := &budgetStub{}
	b := &budgetSource{src: st, stats: st, reads: OnboardingReadBudget}
	if _, err := b.Read(extract.RepoRef{}, "", ""); !errors.Is(err, errOnboardingBudget) {
		t.Fatalf("read past the read budget: %v", err)
	}
	st2 := &budgetStub{api: OnboardingRESTBudget}
	b2 := &budgetSource{src: st2, stats: st2}
	if _, err := b2.List(extract.RepoRef{}, "", ""); !errors.Is(err, errOnboardingBudget) {
		t.Fatalf("listing at the REST budget: %v", err)
	}
}

// A budget stop names the counter that was used up and the values of all
// three; each of the three trips alone, and the first reason is kept.
func TestBudgetRefusalNamesTheCounter(t *testing.T) {
	t.Parallel()
	read := func(b *budgetSource) error { _, err := b.Read(extract.RepoRef{}, "", ""); return err }
	list := func(b *budgetSource) error { _, err := b.List(extract.RepoRef{}, "", ""); return err }
	for name, tc := range map[string]struct {
		api          int64
		reads, lists int
		call         func(*budgetSource) error
		want         string
	}{
		"REST on a read":    {api: 250, call: read, want: "used up: GitHub REST requests (used 250 of 250 GitHub REST requests, 0 of 3000 reads, 0 of 10000 listings)"},
		"REST on a listing": {api: 251, lists: 7, call: list, want: "used up: GitHub REST requests (used 251 of 250 GitHub REST requests, 0 of 3000 reads, 7 of 10000 listings)"},
		"reads":             {api: 249, reads: 3000, call: read, want: "used up: reads (used 249 of 250 GitHub REST requests, 3000 of 3000 reads, 0 of 10000 listings)"},
		"listings":          {api: 12, lists: 10000, call: list, want: "used up: listings (used 12 of 250 GitHub REST requests, 0 of 3000 reads, 10000 of 10000 listings)"},
		"REST and listings": {api: 250, lists: 10000, call: list, want: "used up: GitHub REST requests and listings (used 250 of 250"},
	} {
		st := &budgetStub{api: tc.api}
		b := &budgetSource{src: st, stats: st, reads: tc.reads, lists: tc.lists}
		err := tc.call(b)
		if !errors.Is(err, errOnboardingBudget) || !b.over || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: over=%v err=%v", name, b.over, err)
		}
		st.api = 0
		for _, again := range []func(*budgetSource) error{read, list} {
			if next := again(b); !errors.Is(next, errOnboardingBudget) || next.Error() != err.Error() {
				t.Fatalf("%s: a later call says %v, want %v", name, next, err)
			}
		}
		if b.reads != tc.reads || b.lists != tc.lists {
			t.Fatalf("%s: refused calls were counted", name)
		}
	}
}

// One REST request below the limit is admitted; at the limit nothing is.
func TestBudgetRESTBoundary(t *testing.T) {
	t.Parallel()
	st := &budgetStub{api: OnboardingRESTBudget - 1}
	b := &budgetSource{src: st, stats: st}
	if _, err := b.List(extract.RepoRef{}, "", ""); err != nil || b.over || b.reason() != "" {
		t.Fatalf("at 249: err=%v over=%v reason=%q", err, b.over, b.reason())
	}
	st.api = OnboardingRESTBudget
	if _, err := b.List(extract.RepoRef{}, "", ""); !errors.Is(err, errOnboardingBudget) || !b.over {
		t.Fatalf("at 250: err=%v over=%v", err, b.over)
	}
}
