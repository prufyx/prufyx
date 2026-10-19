// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/humanreport"
	"github.com/prufyx/prufyx/cli/internal/projectcheck"
	"github.com/prufyx/prufyx/cli/internal/scanrun"
)

// humanRoute is what a check route tells the shared human report. Exit is the
// route's own exit code of the checked rules (before --strict-exit).
type humanRoute struct {
	exit                 int
	claims               []constraintengine.Claim
	project, from, to    string
	showPasses, verbose  bool
	trust                *cncfcheck.TrustPolicyDisclosure
	preamble             []string
	scope                []string
	trailer              []string
	notEvaluated         []string
	provenance           []string
	knowledge            string
	customResourceCaveat bool
}

var (
	ruleDescriptionsOnce sync.Once
	ruleDescriptions     map[string]string
)

// ruleTitle names a rule the way prufyx scan does (first sentence of the
// embedded rule description); a rule the embedded pack does not know (an
// external bundle) falls back to its id in the renderer.
func ruleTitle(ruleID string) string {
	ruleDescriptionsOnce.Do(func() {
		ruleDescriptions = map[string]string{}
		if descriptions, err := cncfcheck.EmbeddedRuleDescriptions(); err == nil {
			for id, text := range descriptions {
				ruleDescriptions[id] = text
			}
		}
		if descriptions, err := projectcheck.EmbeddedRuleDescriptions(); err == nil {
			for id, text := range descriptions {
				ruleDescriptions[id] = text
			}
		}
	})
	description := ruleDescriptions[ruleID]
	if description == "" {
		return ""
	}
	return scanrun.RuleTitle(description)
}

// verboseRequested reports -v, --verbose or --details (not set to false).
func verboseRequested(args []string) bool {
	verbose := false
	for _, arg := range args {
		if arg == "--" {
			break
		}
		name, ok := optionName(arg)
		if !ok || (name != "v" && name != "verbose" && name != "details") {
			continue
		}
		switch {
		case strings.HasSuffix(arg, "=false"):
			verbose = false
		default:
			verbose = true
		}
	}
	return verbose
}

func splitLines(text string) []string {
	text = strings.TrimRight(text, "\n")
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

// writeHumanReport renders the shared human report for a route.
func writeHumanReport(out io.Writer, route humanRoute) error {
	var basis bytes.Buffer
	if err := writeBasisHeadline(&basis, route.claims, route.trust); err != nil {
		return err
	}
	summary := summarizeClaims(route.claims, route.showPasses)
	var notes bytes.Buffer
	if summary.allUnreviewed {
		if err := writeUnreviewedTransition(&notes, summary, route.project, route.from, route.to); err != nil {
			return err
		}
	} else if err := writeCollapsedNotesUnreviewedOnly(&notes, summary); err != nil {
		return err
	}
	scope := append([]string(nil), route.scope...)
	var caveats bytes.Buffer
	if err := writeNoVerdictLine(&caveats, route.claims); err != nil {
		return err
	}
	if route.customResourceCaveat {
		if err := writeCustomResourceScope(&caveats, route.claims); err != nil {
			return err
		}
	}
	if policyLeftOutEverything(route.claims, route.trust) {
		fmt.Fprintln(&caveats, policyLeftOutLine)
	}
	scope = append(splitLines(caveats.String()), scope...)
	preamble := append(splitLines(basis.String()), route.preamble...)
	return humanreport.Render(out, humanreport.Input{
		Exit: route.exit, Claims: route.claims,
		Project: route.project, From: route.from, To: route.to,
		ShowPasses: route.showPasses, Verbose: route.verbose,
		Title:           ruleTitle,
		Preamble:        preamble,
		UndecidedNotes:  splitLines(notes.String()),
		Scope:           scope,
		Trailer:         route.trailer,
		NotEvaluated:    route.notEvaluated,
		Provenance:      route.provenance,
		Knowledge:       route.knowledge,
		NoticeScopeLine: noticeScopeLine,
	})
}

// writeCollapsedNotesUnreviewedOnly prints the counts of claims the report
// does not list as items: rules for other transitions and release-boundary
// rules. Passes are counted in the headline and footer instead.
func writeCollapsedNotesUnreviewedOnly(out io.Writer, summary claimSummary) error {
	summary.passes = 0
	return writeCollapsedNotes(out, summary)
}

// nativeProvenance lists the -v provenance lines of a native-resource report.
func nativeProvenance(rawDigests []string, preparedDigest string, report cncfcheck.Report) []string {
	return append([]string{
		"raw input digests " + joinNativeDigests(rawDigests) + "  prepared input digest " + preparedDigest,
	}, reportProvenance(report)...)
}

func reportProvenance(report cncfcheck.Report) []string {
	return []string{
		"evaluated at " + report.Check.EvaluatedAt + " · aggregate UNKNOWN (whole-upgrade compatibility: UNKNOWN)",
		"knowledge " + report.KnowledgeOrigin + " " + report.KnowledgeRevision + " pack digest " + report.KnowledgePackDigest,
		"network used: false",
	}
}

// knowledgeFooter is the one-line knowledge statement of the default footer.
func knowledgeFooter(report cncfcheck.Report) string {
	return fmt.Sprintf("Knowledge: %s %s. No network used.", report.KnowledgeOrigin, report.KnowledgeRevision)
}
