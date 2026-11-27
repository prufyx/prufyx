// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
)

const floorSlug = "cyclops" // a shipped target; its floor is edited in the head only

func floorTargetPath(tr Tree) string {
	return filepath.Join(tr.Root, filepath.FromSlash(DefaultLayout().Onboarding.TargetsDir), crdversions.TargetFileName(floorSlug))
}

func floorApprovalFile(tr Tree) string {
	return filepath.Join(tr.Root, filepath.FromSlash(DefaultLayout().ApprovalDir), TargetFloorApprovalPack, floorSlug+".json")
}

func editFloorTarget(t *testing.T, tr Tree, edit func(string) string) {
	t.Helper()
	raw, err := os.ReadFile(floorTargetPath(tr))
	if err != nil {
		t.Fatal(err)
	}
	out := edit(string(raw))
	if out == string(raw) {
		t.Fatal("the edit changed nothing")
	}
	writeFile(t, floorTargetPath(tr), []byte(out))
}

var minFromRE = regexp.MustCompile(`"minFrom": "[^"]*"`)

func withMinFrom(to string) func(string) string {
	return func(s string) string { return minFromRE.ReplaceAllString(s, `"minFrom": "`+to+`"`) }
}

func withDerivedFrom(v string) func(string) string {
	return func(s string) string {
		return strings.Replace(s, `"minFrom": "0.19",`, `"minFrom": "0.19",`+"\n"+`    "derivedFrom": "`+v+`",`, 1)
	}
}

func floorApprovalFor(t *testing.T, base, head Tree, key testApprovalKey, decided time.Time) []byte {
	t.Helper()
	hraw, err := os.ReadFile(floorTargetPath(head))
	must(t, err)
	braw, err := os.ReadFile(floorTargetPath(base))
	must(t, err)
	s, err := TargetFloorApprovalSubject(braw, hraw, floorSlug)
	must(t, err)
	rec := ApprovalRecord{
		BaseDigest: s.BaseDigest(), CandidateDigest: CandidateDigest(s.Candidate), CandidateID: "pr-1",
		DecidedAt: decided.UTC().Format("2006-01-02T15:04:05Z"), Decision: ApprovalDecisionApprove, Identity: "airstand",
		Pack: s.Pack, RuleID: s.RuleID, Scope: s.Scope, Subject: s.Kind,
	}
	return key.sign(t, rec)
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func floorFixture(t *testing.T) (Tree, Tree, testApprovalKey) {
	t.Helper()
	base, head := trees(t)
	key := newApprovalKey(t)
	key.pinBoth(t, base, head, "airstand")
	return base, head, key
}

func floorCheckOf(t *testing.T, r *Report) Check {
	t.Helper()
	c, ok := check(r, CheckTargetFloor)
	if !ok {
		t.Fatal("no target-floor check in the report")
	}
	return c
}

// A hand-lowered floor with no owner approval is refused, whoever authors it:
// minFrom, derivedFrom, a human and the automation account alike.
func TestTargetFloorLoweringNeedsOwnerApproval(t *testing.T) {
	t.Parallel()
	for name, edit := range map[string]func(string) string{
		"minFrom":     withMinFrom("0.18"),
		"derivedFrom": withDerivedFrom("0.17"),
	} {
		for _, author := range []string{"airstand", DefaultBotLogin} {
			base, head, _ := floorFixture(t)
			editFloorTarget(t, head, edit)
			r := runGate(t, Options{Base: base, Head: head, Author: author})
			c := floorCheckOf(t, r)
			if c.OK || !strings.Contains(c.Detail, "without an owner approval") {
				t.Fatalf("%s by %s: %+v", name, author, c)
			}
			if r.Passed() {
				t.Fatalf("%s by %s: the gate passed", name, author)
			}
		}
	}
}

func TestTargetFloorLoweringWithApprovalIsAdmitted(t *testing.T) {
	t.Parallel()
	for name, edit := range map[string]func(string) string{"minFrom": withMinFrom("0.18"), "derivedFrom": withDerivedFrom("0.17")} {
		for _, author := range []string{"airstand", DefaultBotLogin} {
			base, head, key := floorFixture(t)
			editFloorTarget(t, head, edit)
			writeFile(t, floorApprovalFile(head), floorApprovalFor(t, base, head, key, gateNow.Add(-time.Hour)))
			regenerate(t, head)
			c := floorCheckOf(t, runGate(t, Options{Base: base, Head: head, Author: author}))
			if !c.OK || !strings.Contains(c.Detail, "1 target floors lowered") {
				t.Fatalf("%s by %s: %+v", name, author, c)
			}
			if r := runGate(t, Options{Base: base, Head: head, Author: author}); strings.Contains(strings.Join(failedChecks(r), "\n"), "knowledge-records") {
				t.Fatalf("approval file refused as a stray record: %v", failedChecks(r))
			}
		}
	}
}

func TestTargetFloorApprovalRefusals(t *testing.T) {
	t.Parallel()
	type tc struct {
		name string
		run  func(t *testing.T) *Report
		want string
	}
	cases := []tc{
		{"approval for another floor", func(t *testing.T) *Report {
			base, head, key := floorFixture(t)
			editFloorTarget(t, head, withMinFrom("0.18"))
			ap := floorApprovalFor(t, base, head, key, gateNow.Add(-time.Hour))
			editFloorTarget(t, head, withMinFrom("0.17")) // lowered further than approved
			writeFile(t, floorApprovalFile(head), ap)
			return runGate(t, Options{Base: base, Head: head, Author: "airstand"})
		}, "candidate digest"},
		{"approval from a key that is not pinned", func(t *testing.T) *Report {
			base, head, _ := floorFixture(t)
			editFloorTarget(t, head, withMinFrom("0.18"))
			writeFile(t, floorApprovalFile(head), floorApprovalFor(t, base, head, newApprovalKey(t), gateNow.Add(-time.Hour)))
			return runGate(t, Options{Base: base, Head: head, Author: "airstand"})
		}, "not pinned"},
		{"approval older than 14 days", func(t *testing.T) *Report {
			base, head, key := floorFixture(t)
			editFloorTarget(t, head, withMinFrom("0.18"))
			writeFile(t, floorApprovalFile(head), floorApprovalFor(t, base, head, key, gateNow.Add(-15*24*time.Hour)))
			return runGate(t, Options{Base: base, Head: head, Author: "airstand"})
		}, "older than 14 days"},
		{"approval already in the base", func(t *testing.T) *Report {
			base, head, key := floorFixture(t)
			editFloorTarget(t, head, withMinFrom("0.18"))
			ap := floorApprovalFor(t, base, head, key, gateNow.Add(-time.Hour))
			writeFile(t, floorApprovalFile(head), ap)
			writeFile(t, floorApprovalFile(base), ap)
			return runGate(t, Options{Base: base, Head: head, Author: "airstand"})
		}, "already in the base"},
		{"pause switch holds the lowering", func(t *testing.T) *Report {
			base, head, key := floorFixture(t)
			editFloorTarget(t, head, withMinFrom("0.18"))
			writeFile(t, floorApprovalFile(head), floorApprovalFor(t, base, head, key, gateNow.Add(-time.Hour)))
			writeFile(t, filepath.Join(head.Root, filepath.FromSlash(DefaultLayout().PausePath)), []byte("paused\n"))
			return runGate(t, Options{Base: base, Head: head, Author: "airstand"})
		}, "pause switch"},
	}
	for _, c := range cases {
		r := c.run(t)
		fc := floorCheckOf(t, r)
		if fc.OK || !strings.Contains(fc.Detail, c.want) {
			t.Fatalf("%s: %+v", c.name, fc)
		}
	}
}

// A raised floor and an unchanged target need no approval; an approval file
// that no lowered floor uses is a stray record.
func TestTargetFloorRaiseAndStrayApproval(t *testing.T) {
	t.Parallel()
	base, head, key := floorFixture(t)
	editFloorTarget(t, head, withMinFrom("0.20"))
	c := floorCheckOf(t, runGate(t, Options{Base: base, Head: head, Author: "airstand"}))
	if !c.OK || !strings.Contains(c.Detail, "0 target floors lowered") {
		t.Fatalf("raise: %+v", c)
	}
	// A stray approval beside a raise.
	other, lowered, _ := floorFixture(t)
	editFloorTarget(t, lowered, withMinFrom("0.18"))
	ap := floorApprovalFor(t, other, lowered, key, gateNow.Add(-time.Hour))
	writeFile(t, floorApprovalFile(head), ap)
	r := runGate(t, Options{Base: base, Head: head, Author: "airstand"})
	requireFail(t, r, "knowledge-records")
}

// A new target whose derivedFrom is below its minFrom lowers from an absent
// base and needs the approval too.
func TestTargetFloorNewTargetWithLowerDerivedFrom(t *testing.T) {
	t.Parallel()
	base, head, _ := floorFixture(t)
	raw, err := os.ReadFile(floorTargetPath(head))
	must(t, err)
	fresh := strings.NewReplacer(`"project": "cyclops"`, `"project": "synthetic-new"`, `"minFrom": "0.19",`, `"minFrom": "0.19",`+"\n"+`    "derivedFrom": "0.10",`).Replace(string(raw))
	newPath := filepath.Join(filepath.Dir(floorTargetPath(head)), crdversions.TargetFileName("synthetic-new"))
	writeFile(t, newPath, []byte(fresh))
	r := runGate(t, Options{Base: base, Head: head, Author: "airstand"})
	if c := floorCheckOf(t, r); c.OK || !strings.Contains(c.Detail, "synthetic-new") {
		t.Fatalf("%+v", c)
	}
}

func TestTargetFloorApprovalSubjectRefusals(t *testing.T) {
	t.Parallel()
	_, head, _ := floorFixture(t)
	hraw, err := os.ReadFile(floorTargetPath(head))
	must(t, err)
	if _, err := TargetFloorApprovalSubject(hraw, hraw, floorSlug); err == nil || !strings.Contains(err.Error(), "not lowered") {
		t.Fatalf("unchanged floor: %v", err)
	}
	if _, err := TargetFloorApprovalSubject(nil, hraw, floorSlug); err == nil {
		t.Fatal("a new target without a lower derivedFrom needs no approval, so none is built")
	}
	if _, err := TargetFloorApprovalSubject(nil, []byte("{}"), floorSlug); err == nil {
		t.Fatal("unreadable target")
	}
}
