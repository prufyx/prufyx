// SPDX-License-Identifier: AGPL-3.0-only

// Package humanreport renders the human (text) report of a check route: the
// verdict first, the problems grouped, the citations one flag away. It is a
// pure view over claims the engine already decided. It decides nothing:
//
//   - the headline word is derived from the exit code the route reports, never
//     from the claims, and any exit other than 10 (BLOCKED) or 0 (scoped PASS)
//     reads UNKNOWN, so an undecided result can never read as a pass;
//   - the renderer never edits knowledge text. It groups identical next actions
//     and may print one byte-identical trailing sentence once; the JSON report
//     is produced elsewhere and is not touched;
//   - every claim and every source stays reachable: the default report counts
//     them, -v lists every rule id and every cited source.
//
// A route may display a next action that differs from the JSON one (the
// Kubernetes declaration hint); the caller substitutes it before rendering.
package humanreport

import (
	"fmt"
	"io"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// Exit codes the headline is derived from (mirrors communityapp).
const (
	exitOK      = 0
	exitBlocked = 10
)

// ReasonTransitionNotReviewed marks a claim of a rule for another transition.
const ReasonTransitionNotReviewed = "RULE_TRANSITION_NOT_REVIEWED"

// maxTitlesShown bounds the rule titles listed for one group of identical
// actions in the default report; -v lists every rule.
const maxTitlesShown = 6

// Input is everything the renderer needs.
type Input struct {
	// Exit is the exit code of the checked rules as the route reports it
	// (before --strict-exit). It is passed in, never recomputed.
	Exit   int
	Claims []constraintengine.Claim
	// Project, From and To name the subject in the headline; From and To may
	// be empty.
	Project, From, To string
	ShowPasses        bool
	Verbose           bool
	// Title returns the human title of a rule, or "" to fall back to the id.
	Title func(ruleID string) string
	// Preamble lines print verbatim right after the headline (trust policy
	// disclosures, input qualifications).
	Preamble []string
	// UndecidedNotes print inside the UNDECIDED section: the unreviewed
	// transition message and the collapsed counts of rules for other
	// transitions.
	UndecidedNotes []string
	// Scope lines are accuracy caveats; they always print.
	Scope []string
	// Trailer lines always print after the whole-upgrade line.
	Trailer []string
	// NotEvaluated lines list rules the route left out; they always print.
	NotEvaluated []string
	// Provenance lines print only with Verbose.
	Provenance []string
	// Knowledge describes the knowledge used, for the footer.
	Knowledge string
	// NoticeScopeLine is printed once after an established one-way notice.
	NoticeScopeLine string
	// Locations are, per rule id, the ready-made object lines (for example
	// "applyset.yaml:1  CronJob default/nightly-report") printed under the
	// rule's title. Only a listed title shows them.
	Locations map[string][]string
}

type item struct {
	claim constraintengine.Claim
	title string
}

type group struct {
	action string
	items  []item
}

// Render writes the report.
func Render(out io.Writer, in Input) error {
	w := &writer{out: out, locations: in.Locations}
	var mustFix, undecided, passed []item
	counts := struct{ blocked, undecided, passed, verdicts, notCovered int }{}
	var notices []constraintengine.Claim
	seen := map[constraintengine.SourceEvidence]bool{}
	var sources []constraintengine.SourceEvidence
	addSources := func(claim constraintengine.Claim) {
		for _, source := range claim.Sources {
			if !seen[source] {
				seen[source] = true
				sources = append(sources, source)
			}
		}
	}
	for _, claim := range in.Claims {
		if claim.IsVerdictNeutral() {
			notices = append(notices, claim)
			addSources(claim)
			continue
		}
		counts.verdicts++
		collapsed := claim.Status == "UNKNOWN" &&
			(claim.ReasonCode == ReasonTransitionNotReviewed || claim.ReasonCode == constraintengine.ReasonReleaseBoundaryNotReviewed)
		if collapsed {
			counts.notCovered++
		}
		switch {
		case claim.Status == "BLOCKED":
			counts.blocked++
			mustFix = append(mustFix, in.newItem(claim))
		case claim.Status == "PASS":
			counts.passed++
			if in.ShowPasses {
				passed = append(passed, in.newItem(claim))
			}
		default:
			counts.undecided++
			if !collapsed {
				undecided = append(undecided, in.newItem(claim))
			}
		}
		if !collapsed && (claim.Status != "PASS" || in.ShowPasses) {
			addSources(claim)
		}
	}

	w.printf("%s  %d must fix · %d undecided · %d passed     %s\n", HeadlineWord(in.Exit), counts.blocked, counts.undecided, counts.passed, in.subject(counts.verdicts))
	for _, line := range in.Preamble {
		w.println(line)
	}

	trailing := commonTrailingSentence(in.Verbose, mustFix, undecided)
	if len(mustFix) > 0 {
		w.println("")
		w.printf("MUST FIX (%d)\n", len(mustFix))
		for _, g := range groupByAction(mustFix) {
			w.writeGroup(g, "fix", trailing, in.Verbose, true)
		}
	}
	if counts.undecided > 0 {
		w.println("")
		w.printf("UNDECIDED (%s)\n", plural(counts.undecided, "rule", "rules"))
		for _, line := range in.UndecidedNotes {
			w.printf("  %s\n", line)
		}
		for _, g := range groupByAction(undecided) {
			w.writeGroup(g, "to decide", trailing, in.Verbose, false)
		}
	}
	if len(passed) > 0 {
		w.println("")
		w.printf("PASSED (%d)\n", len(passed))
		for _, g := range groupByAction(passed) {
			w.writeGroup(g, "if this changes", "", in.Verbose, true)
		}
	}
	if err := writeNotices(w, notices, in); err != nil {
		return err
	}
	for _, line := range in.NotEvaluated {
		w.printf("not evaluated: %s\n", line)
	}

	w.println("")
	for _, line := range in.Scope {
		w.println(line)
	}
	whole := "Whole upgrade: not proven."
	if evaluated := counts.verdicts - counts.notCovered; evaluated > 0 {
		whole += fmt.Sprintf(" This report evaluated only %s.", plural(evaluated, "reviewed rule", "reviewed rules"))
	} else {
		whole += " No reviewed rule decided this transition."
	}
	if trailing != "" {
		whole += " " + trailing
	}
	w.println(whole)
	for _, line := range in.Trailer {
		w.println(line)
	}

	if in.Verbose {
		if len(sources) > 0 {
			w.println("")
			w.printf("SOURCES (%d)\n", len(sources))
			for _, source := range sources {
				w.printf("  %s lines %d-%d; revision %s; digest %s\n", source.URL, source.StartLine, source.EndLine, source.Revision, source.ContentDigest)
			}
		}
		w.println("")
		w.println("Evidence and provenance")
		for _, line := range in.Provenance {
			w.printf("  %s\n", line)
		}
		w.printf("  %s\n", ExitMeaning(in.Exit))
	} else {
		footer := fmt.Sprintf("%s (show with -v).", plural(len(sources), "cited upstream source", "cited upstream sources"))
		if counts.passed > 0 && !in.ShowPasses {
			footer += fmt.Sprintf(" %s (--show-passes).", plural(counts.passed, "passed rule", "passed rules"))
		}
		if in.Knowledge != "" {
			footer += " " + in.Knowledge
		}
		w.println(footer)
	}
	return w.err
}

// HeadlineWord is the verdict word for an exit code. Only 10 and 0 are named;
// every other value, including a failure the route did not expect, reads
// UNKNOWN (fail closed).
func HeadlineWord(exit int) string {
	switch exit {
	case exitBlocked:
		return "BLOCKED"
	case exitOK:
		return "PASS (scoped)"
	}
	return "UNKNOWN"
}

// ExitMeaning states the meaning of the checked-rules exit code.
func ExitMeaning(exit int) string {
	switch exit {
	case exitBlocked:
		return "exit 10: a reviewed rule blocks this upgrade"
	case exitOK:
		return "exit 0: scoped PASS; whole-upgrade compatibility is not proven (--strict-exit exits 14 instead)"
	}
	return "exit 11: UNKNOWN; at least one rule could not be decided, which is not a pass"
}

func (in Input) subject(verdicts int) string {
	subject := in.Project
	if in.From != "" && in.To != "" {
		subject += " " + in.From + " -> " + in.To
	}
	return subject + ", " + plural(verdicts, "reviewed rule", "reviewed rules")
}

func (in Input) newItem(claim constraintengine.Claim) item {
	title := ""
	if in.Title != nil {
		title = in.Title(claim.RuleID)
	}
	if title == "" {
		title = claim.RuleID
	}
	return item{claim: claim, title: title}
}

func actionOf(claim constraintengine.Claim) string { return claim.NextAction }

func groupByAction(items []item) []group {
	var groups []group
	index := map[string]int{}
	for _, it := range items {
		key := actionOf(it.claim)
		position, ok := index[key]
		if !ok {
			position = len(groups)
			index[key] = position
			groups = append(groups, group{action: key})
		}
		groups[position].items = append(groups[position].items, it)
	}
	return groups
}

// commonTrailingSentence returns the final sentence shared, byte for byte, by
// every listed action when there are at least two distinct actions and each
// splits at its last ". " into a non-empty head and that sentence. Otherwise
// it returns "" and no action is split. In verbose mode it never splits.
func commonTrailingSentence(verbose bool, lists ...[]item) string {
	if verbose {
		return ""
	}
	var common string
	distinct := map[string]bool{}
	for _, list := range lists {
		for _, it := range list {
			action := actionOf(it.claim)
			distinct[action] = true
			head, tail, ok := splitLastSentence(action)
			if !ok || head == "" {
				return ""
			}
			if common == "" {
				common = tail
			} else if tail != common {
				return ""
			}
		}
	}
	if len(distinct) < 2 {
		return ""
	}
	return common
}

func splitLastSentence(text string) (head, tail string, ok bool) {
	index := strings.LastIndex(text, ". ")
	if index < 0 {
		return "", "", false
	}
	return text[:index+1], text[index+2:], true
}

func (w *writer) writeGroup(g group, label, trailing string, verbose, listTitles bool) {
	action := g.action
	if trailing != "" {
		if head, _, ok := splitLastSentence(action); ok {
			action = head
		}
	}
	switch {
	case listTitles || len(g.items) == 1:
		shown := g.items
		if !verbose && len(shown) > maxTitlesShown {
			shown = shown[:maxTitlesShown]
		}
		for _, it := range shown {
			w.printf("  %s\n", it.title)
			if line, ok := it.claim.MatchedMembersLine(); ok {
				w.printf("    %s\n", line)
			}
			w.writeLocations(it.claim.RuleID, verbose)
			if verbose {
				w.writeRule(it.claim)
			}
		}
		if len(shown) < len(g.items) {
			w.printf("  and %d more rules with the same %s (-v lists them)\n", len(g.items)-len(shown), label)
		}
	default:
		hint := " (-v lists them)"
		if verbose {
			hint = ""
		}
		w.printf("  %s with the same action%s\n", plural(len(g.items), "rule", "rules"), hint)
		if verbose {
			for _, it := range g.items {
				w.printf("    %s\n", it.title)
				w.writeLocations(it.claim.RuleID, verbose)
				w.writeRule(it.claim)
			}
		}
	}
	w.printf("    %s: %s\n", label, action)
}

func (w *writer) writeRule(claim constraintengine.Claim) {
	w.printf("    rule: %s (%s, %s)\n", claim.RuleID, claim.Status, claim.ReasonCode)
	w.printf("    %s\n", claim.EvidenceBasisLine())
}

// writeNotices prints one-way notices and leads: informational, never a
// verdict, never counted. The scope line follows an established one-way notice.
func writeNotices(w *writer, notices []constraintengine.Claim, in Input) error {
	established := false
	headed := false
	for _, claim := range notices {
		lines, notice := claim.NoticeLines()
		if !notice || len(lines) == 0 {
			if !notice {
				// A lead is not a notice: it prints as an informational line.
				if !headed {
					w.println("")
					w.println("NOTICES (not verdicts)")
					headed = true
				}
				w.printf("  %s: %s (%s)\n    next action: %s\n    %s\n", claim.RuleID, claim.Status, claim.ReasonCode, claim.NextAction, claim.EvidenceBasisLine())
			}
			continue
		}
		if !headed {
			w.println("")
			w.println("NOTICES (not verdicts)")
			headed = true
		}
		for _, line := range lines {
			w.printf("  %s\n", line)
		}
		w.printf("  %s\n", claim.EvidenceBasisLine())
		if claim.Operator == constraintengine.OperatorNoticeOneWay && claim.Status == constraintengine.StatusNotice {
			established = true
		}
	}
	if established && in.NoticeScopeLine != "" {
		w.printf("  %s\n", in.NoticeScopeLine)
	}
	return w.err
}

func plural(count int, one, many string) string {
	if count == 1 {
		return fmt.Sprintf("%d %s", count, one)
	}
	return fmt.Sprintf("%d %s", count, many)
}

type writer struct {
	out       io.Writer
	err       error
	locations map[string][]string
}

// maxLocationsShown bounds the object lines listed under one rule title.
const maxLocationsShown = 5

func (w *writer) writeLocations(ruleID string, verbose bool) {
	lines := w.locations[ruleID]
	shown := lines
	if !verbose && len(shown) > maxLocationsShown {
		shown = shown[:maxLocationsShown]
	}
	for _, line := range shown {
		w.printf("    %s\n", line)
	}
	if len(shown) < len(lines) {
		w.printf("    and %d more objects (-v lists them)\n", len(lines)-len(shown))
	}
}

func (w *writer) printf(format string, args ...any) {
	if w.err == nil {
		_, w.err = fmt.Fprintf(w.out, format, args...)
	}
}

func (w *writer) println(text string) {
	if w.err == nil {
		_, w.err = fmt.Fprintln(w.out, text)
	}
}
