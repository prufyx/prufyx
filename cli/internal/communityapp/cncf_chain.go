// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"fmt"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
)

// cncfChain runs check cncf --via: the input's transition checked hop by hop
// through the versions the operator declared, plus the end-to-end pair. Exit
// codes follow the verdict: 0 PASS, 10 BLOCKED, 11 otherwise.
func (r runtime) cncfChain(project string, input []byte, via []string, now time.Time, format string, showPasses bool) int {
	chain, err := r.cncfChecker().CheckChain(project, input, via, now)
	if err != nil {
		return r.cncfError("CNCF chained check failed (--via must list exact versions in ascending order strictly between the input's versions, and the input must hold one component per side)", err)
	}
	encoded, err := cncfcheck.MarshalChain(chain)
	if err != nil {
		return r.fail("CNCF report integrity failure", ExitIntegrity)
	}
	if format == "json" {
		if _, err := fmt.Fprintln(r.stdout, string(encoded)); err != nil {
			return ExitIntegrity
		}
		return cncfcheck.ChainExit(chain)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s %s (%d hops, path declared with --via)\n", chain.Verdict, project, strings.Join(chain.Path, " -> "), len(chain.Hops))
	for _, hop := range chain.Hops {
		writeChainHop(&b, fmt.Sprintf("hop %d", hop.Index), hop, showPasses)
	}
	writeChainHop(&b, "end-to-end", chain.Whole, showPasses)
	fmt.Fprintf(&b, "next action: %s\n", chain.NextAction)
	b.WriteString("scope: the same facts are used on every hop; only the hops you declared are checked; runtime behavior is not verified\n")
	if _, err := fmt.Fprint(r.stdout, b.String()); err != nil {
		return ExitIntegrity
	}
	return cncfcheck.ChainExit(chain)
}

func writeChainHop(b *strings.Builder, label string, hop cncfcheck.ChainHop, showPasses bool) {
	fmt.Fprintf(b, "  %-10s %s -> %s  %s\n", label, hop.From, hop.To, hop.Verdict)
	undecided := 0
	for _, claim := range hop.Report.Check.Claims {
		if claim.IsVerdictNeutral() {
			continue
		}
		switch {
		case claim.Status == "BLOCKED":
			fmt.Fprintf(b, "             %s: BLOCKED (%s)\n             %s\n", claim.RuleID, claim.ReasonCode, claim.NextAction)
		case claim.Status == "PASS" && showPasses:
			fmt.Fprintf(b, "             %s: PASS\n", claim.RuleID)
		case claim.Status != "PASS":
			undecided++
		}
	}
	if hop.Verdict == cncfcheck.ChainUnknown && hop.Decided == 0 {
		b.WriteString("             no reviewed rule matches this transition\n")
	} else if undecided > 0 {
		fmt.Fprintf(b, "             %d rule(s) not decided; check this pair alone for the reasons\n", undecided)
	}
}
