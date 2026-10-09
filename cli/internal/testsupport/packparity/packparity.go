// SPDX-License-Identifier: AGPL-3.0-only

// Package packparity holds the table both rule packs (the CNCF pack and the
// community-project pack) are tested against: the same abstract rule sets
// must give the same claim statuses and the same exit code under either
// pack. It is imported only by tests; no command links it. It lives under
// internal/testsupport because a table shared by two packages' tests cannot
// sit in a _test.go file (Go does not export those); the guard test in this
// package fails if any non-test file imports it.
//
// A case names the kinds of rule a check holds for one reviewed transition.
// Each pack's test turns every kind into a concrete rule of its own and
// compares what the check reports with the case.
package packparity

import "sort"

// Kind is one abstract rule.
type Kind string

const (
	// Pass is a verdict rule that the declared input satisfies.
	Pass Kind = "pass"
	// Blocked is a verdict rule that the declared input violates.
	Blocked Kind = "blocked"
	// Unsupported is a support-range rule (severity "unsupported") whose
	// dependency is outside the documented range.
	Unsupported Kind = "unsupported"
	// Supported is a support-range rule whose dependency is inside it.
	Supported Kind = "supported"
	// Notice is an applicable one-way notice.
	Notice Kind = "notice"
)

// Case is one row of the table.
type Case struct {
	Name  string
	Rules []Kind
	// Exit is the exit code of the check: 0 only when every verdict claim
	// passed, 10 when one is BLOCKED, 11 otherwise (including a check with
	// no verdict claim at all).
	Exit int
	// Verdicts are the statuses of the verdict claims, sorted. Notice
	// claims are never among them.
	Verdicts []string
	// Notices is the number of NOTICE claims.
	Notices int
}

// Cases is the parity table. UNSUPPORTED is never PASS and never BLOCKED; a
// notice never takes part in the exit code.
var Cases = []Case{
	{"pass", []Kind{Pass}, 0, []string{"PASS"}, 0},
	{"pass and a supported combination", []Kind{Pass, Supported}, 0, []string{"PASS", "PASS"}, 0},
	{"only a supported combination", []Kind{Supported}, 0, []string{"PASS"}, 0},
	{"pass and UNSUPPORTED", []Kind{Pass, Unsupported}, 11, []string{"PASS", "UNSUPPORTED"}, 0},
	{"only UNSUPPORTED", []Kind{Unsupported}, 11, []string{"UNSUPPORTED"}, 0},
	{"UNSUPPORTED and a notice", []Kind{Unsupported, Notice}, 11, []string{"UNSUPPORTED"}, 1},
	{"blocker and UNSUPPORTED", []Kind{Blocked, Unsupported}, 10, []string{"BLOCKED", "UNSUPPORTED"}, 0},
	{"pass, blocker and UNSUPPORTED", []Kind{Pass, Blocked, Unsupported}, 10, []string{"BLOCKED", "PASS", "UNSUPPORTED"}, 0},
	{"pass and a notice", []Kind{Pass, Notice}, 0, []string{"PASS"}, 1},
	{"blocker and a notice", []Kind{Blocked, Notice}, 10, []string{"BLOCKED"}, 1},
	{"only a notice", []Kind{Notice}, 11, []string{}, 1},
}

// Statuses returns the sorted verdict statuses and the notice count of a
// report's claims, given each claim's status and whether it is a notice.
func Statuses(claims []Claim) (verdicts []string, notices int) {
	verdicts = []string{}
	for _, claim := range claims {
		if claim.Notice {
			if claim.Status == "NOTICE" {
				notices++
			}
			continue
		}
		verdicts = append(verdicts, claim.Status)
	}
	sort.Strings(verdicts)
	return verdicts, notices
}

// Claim is the part of a claim the table compares.
type Claim struct {
	Status string
	Notice bool
}
