// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"fmt"
	"io"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfknowledge"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// trustPolicyFlag reads --require-basis. Without the flag the default
// policy applies; a provided value must be a comma-separated list of known
// evidence bases, each at most once.
func trustPolicyFlag(args []string, value string) (cncfcheck.TrustPolicy, bool) {
	if !flagProvided(args, "require-basis") {
		return cncfcheck.TrustPolicy{}, true
	}
	policy, err := cncfcheck.ParseTrustPolicy(value)
	return policy, err == nil
}

// cncfChecker is the embedded CNCF checker under the command's trust policy.
// Every check cncf route evaluates embedded knowledge through it.
func (r runtime) cncfChecker() cncfcheck.Checker {
	return cncfcheck.WithTrustPolicy(r.trust)
}

// withTrustPolicy binds the command's trust policy to an external request.
// Every check cncf route evaluates external knowledge through it.
func (r runtime) withTrustPolicy(req cncfknowledge.Request) cncfknowledge.Request {
	req.TrustPolicy = r.trust
	return req
}

// trustPolicyLines is the human statement of a report's trust policy: one
// line when it left out verdict rules, one when it left out leads, none
// otherwise.
func trustPolicyLines(disclosure *cncfcheck.TrustPolicyDisclosure) []string {
	if disclosure == nil {
		return nil
	}
	var lines []string
	if disclosure.ExcludedRules > 0 {
		lines = append(lines, fmt.Sprintf("trust policy: evidence basis %s only; %d %s left out, so the result cannot pass", strings.Join(disclosure.RequiredBasis, ", "), disclosure.ExcludedRules, plural(disclosure.ExcludedRules, "rule", "rules")))
	}
	if disclosure.ExcludedLeadRules > 0 {
		lines = append(lines, fmt.Sprintf("trust policy: %d unverified %s not shown; add lead to --require-basis to list %s", disclosure.ExcludedLeadRules, plural(disclosure.ExcludedLeadRules, "lead", "leads"), plural(disclosure.ExcludedLeadRules, "it", "them")))
	}
	return lines
}

func plural(count int, one, many string) string {
	if count == 1 {
		return one
	}
	return many
}

// writeBasisHeadline prints the headline notes about evidence bases: the
// trust policy's exclusions, and how many findings rely on model consensus.
// It prints nothing for a report that has neither.
func writeBasisHeadline(out io.Writer, claims []constraintengine.Claim, disclosure *cncfcheck.TrustPolicyDisclosure) error {
	lines := trustPolicyLines(disclosure)
	if note, ok := constraintengine.ConsensusNote(claims); ok {
		lines = append(lines, note)
	}
	for _, line := range lines {
		if _, err := fmt.Fprintln(out, line); err != nil {
			return err
		}
	}
	return nil
}

// policyLeftOutEverything reports whether the trust policy left out every
// verdict rule of a report, so a route that prints exactly one claim has
// none to print.
func policyLeftOutEverything(claims []constraintengine.Claim, disclosure *cncfcheck.TrustPolicyDisclosure) bool {
	return disclosure != nil && disclosure.ExcludedRules > 0 && verdictClaims(claims) == 0
}

const policyLeftOutLine = "UNKNOWN: the trust policy left out every rule this check uses; nothing was evaluated"

// writeTrustPolicyOutcome prints the basis headline of a single-claim route.
// done is true when the policy left out every verdict rule: the route then
// prints the UNKNOWN line instead of its claim and returns.
func writeTrustPolicyOutcome(out io.Writer, claims []constraintengine.Claim, disclosure *cncfcheck.TrustPolicyDisclosure) (done bool, err error) {
	if err := writeBasisHeadline(out, claims, disclosure); err != nil {
		return false, err
	}
	if !policyLeftOutEverything(claims, disclosure) {
		return false, nil
	}
	_, err = fmt.Fprintln(out, policyLeftOutLine)
	return true, err
}
