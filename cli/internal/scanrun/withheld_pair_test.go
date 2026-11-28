// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// A release pair the extractor withholds leaves no rule and no line review for
// the line it enters. These tests hold that scan never infers a pass over such
// a pair, neither on the hop into the line nor on a jump across it, while the
// pairs around it were derived. The release lines 7.5 to 7.10 and their
// reviews are synthetic, test only and never published: 7.5 -> 7.6 is the
// withheld pair, 7.6 -> 7.7 up to 7.9 -> 7.10 are derived.

const (
	withheldLine = "7.6"
	derivedRule  = "strimzi.synthetic-removal.kafkas.7-6-0-to-7-7-0"
)

// derivedPairRule is the removal rule of the derived pair 7.6.0 -> 7.7.0, over
// its line-wide range.
func derivedPairRule() string {
	return strings.NewReplacer(crdLineRuleID, derivedRule, "0.52.0", "7.8.0", "0.51.0", "7.7.0", "0.50.0", "7.6.0").Replace(crdLineRule)
}

// withheldKnowledge holds the reviews of the derived lines 7.7 to 7.10 and the
// rule of 7.6 -> 7.7. injected adds a review of the withheld line: the control
// that shows the fixtures would pass the pair if it were reviewed.
func withheldKnowledge(t *testing.T, injected bool) attestedCRD {
	t.Helper()
	reviews := []lineattest.LineAttestation{
		jumpAtt("7.7", jumpReleases("7.6.0"), jumpReleases("7.7.0"), "", derivedRule),
		jumpAtt("7.8", jumpReleases("7.7.0"), jumpReleases("7.8.0"), ""),
		jumpAtt("7.9", jumpReleases("7.8.0"), jumpReleases("7.9.0"), ""),
		jumpAtt("7.10", jumpReleases("7.9.0"), jumpReleases("7.10.0"), ""),
	}
	if injected {
		reviews = append(reviews, jumpAtt(withheldLine, jumpReleases("7.5.0"), jumpReleases("7.6.0"), ""))
	}
	k := attestedCRD{crdKnowledge: newCRDKnowledge(t, derivedPairRule())}
	k.attestations = lineattest.NewIndex(reviews)
	return k
}

// withheldPolicies are the path policies a scan can meet: none, a reviewed
// sequential_minor one and a reviewed direct one.
var withheldPolicies = []string{"", "sequential_minor", "direct"}

func withheldScan(t *testing.T, k Knowledge, policy, doc, from, to string) (Result, scanreport.Path) {
	t.Helper()
	if policy != "" {
		k = jumpPolicyKnowledge{Knowledge: k, status: crdPolicy(t, policy)}
	}
	result := crdScan(t, k, []string{settingsDoc, doc}, "--from", "strimzi="+from, "--to", "strimzi="+to, "--resource-scope-complete")
	path, _ := strimziJump(t, result.Report)
	if path.Policy != policy || len(path.Hops) == 0 {
		t.Fatalf("policy %q hops %d gaps %v", path.Policy, len(path.Hops), gapReasons(result.Report))
	}
	return result, path
}

// endpointLineName is the release line of a hop end: a line itself, or the line
// of an exact release.
func endpointLineName(t *testing.T, version, line string) string {
	t.Helper()
	if version == "" {
		return line
	}
	l, ok := lineattest.LineOf(version)
	if !ok {
		t.Fatalf("no line of %q", version)
	}
	return l
}

// requireNoCover is requireNeverCovered for a path of any number of hops.
func requireNoCover(t *testing.T, result Result, path scanreport.Path) {
	t.Helper()
	if result.Report.Verdict == scanreport.VerdictPass || result.Exit == 0 {
		t.Fatalf("exit %d verdict %s", result.Exit, result.Report.Verdict)
	}
	for _, c := range result.Report.Inventory {
		if c.Name == "strimzi" && c.Covered {
			t.Fatal("strimzi reported as covered")
		}
	}
	if !hasComponentGap(result.Report, "strimzi", scanreport.ReasonComponentNotCovered, "only for custom-resource versions") {
		t.Fatalf("gaps %v", gapReasons(result.Report))
	}
	for _, hop := range path.Hops {
		if hop.Status == scanreport.HopCovered {
			t.Fatalf("hop covered %+v", hop)
		}
	}
}

func TestScanWithheldPairNeverPasses(t *testing.T) {
	t.Parallel()
	for _, target := range []string{"7.6.0", "7.7.0", "7.8.0", "7.10.0"} {
		for _, policy := range withheldPolicies {
			for name, doc := range map[string]string{"served objects": kafkaV1Doc, "removed objects": kafkaV1beta2Doc} {
				t.Run(target+"/"+policy+"/"+name, func(t *testing.T) {
					result, path := withheldScan(t, withheldKnowledge(t, false), policy, doc, "7.5.0", target)
					requireNoCover(t, result, path)
					// one hop into the withheld line, or one under a direct
					// policy; else one hop per minor line
					first := path.Hops[0]
					if first.From.Version != "7.5.0" {
						t.Fatalf("first hop %+v", first)
					}
					// a direct hop over several lines may record the review of
					// its target line as consulted; it decides nothing
					if len(first.Families) != 0 || (first.Attestation != nil && (policy != "direct" || first.Attestation.Line == withheldLine)) {
						t.Fatalf("the hop over the withheld pair was decided: %+v", first)
					}
					for _, hop := range path.Hops {
						to := endpointLineName(t, hop.To.Version, hop.To.Line)
						for _, family := range hop.Families {
							// a derived hop may pass only itself: between two
							// exact releases of adjacent derived lines
							if family.Status == scanreport.FamilyPass && (hop.Index == 1 || to == withheldLine || family.Line != to || hop.From.Version == "" || hop.To.Version == "") {
								t.Fatalf("family pass on hop %+v: %+v", hop, family)
							}
						}
					}
					// no rule passes the withheld pair, the whole upgrade or
					// any span that starts before the withheld line
					for _, pass := range result.Report.Passes {
						from, okFrom := lineattest.LineOf(pass.Hop.From)
						if !okFrom {
							from = pass.Hop.From
						}
						if pass.Hop.WholeUpgrade || pass.Hop.Index == 1 || from == "7.5" || strings.HasPrefix(pass.Hop.To, withheldLine) {
							t.Fatalf("rule pass over the withheld pair: %+v", pass)
						}
					}
					jump := path.Jump
					if jump == nil {
						if len(path.Hops) != 1 {
							t.Fatalf("no jump for %d hops", len(path.Hops))
						}
						return
					}
					if jump.Status == scanreport.JumpStepwisePass || jump.Status == scanreport.JumpAttention || len(jump.Hops) != len(path.Hops) {
						t.Fatalf("jump %+v", jump)
					}
					if jump.Hops[0].Status == scanreport.JumpHopPass || jump.Hops[0].Status == scanreport.JumpHopAttention || len(jump.Hops[0].Reasons) == 0 {
						t.Fatalf("jump hop over the withheld pair %+v", jump.Hops[0])
					}
					if len(jump.Missing) == 0 || jump.Missing[0].Hop != 1 && name == "served objects" {
						t.Fatalf("the withheld hop is not named as missing: %+v", jump.Missing)
					}
					for i, hop := range jump.Hops {
						if hop.Status == scanreport.JumpHopPass && (len(path.Hops[i].Families) != 1 || path.Hops[i].Families[0].Status != scanreport.FamilyPass) {
							t.Fatalf("jump hop passes without its own family pass: %+v", hop)
						}
					}
				})
			}
		}
	}
}

// The derived pair after the withheld one passes itself and nothing else.
func TestScanDerivedPairAfterWithheldPassesOnlyItself(t *testing.T) {
	t.Parallel()
	for _, policy := range withheldPolicies {
		result, path := withheldScan(t, withheldKnowledge(t, false), policy, kafkaV1Doc, "7.6.0", "7.7.0")
		requireNoCover(t, result, path)
		if len(path.Hops) != 1 || path.Jump != nil || len(path.Hops[0].Families) != 1 || path.Hops[0].Families[0].Status != scanreport.FamilyPass || path.Hops[0].Families[0].Line != "7.7" {
			t.Fatalf("policy %q: %+v", policy, path)
		}
		for _, pass := range result.Report.Passes {
			if pass.Hop.From != "7.6.0" || pass.Hop.To != "7.7.0" {
				t.Fatalf("policy %q: pass of another hop %+v", policy, pass)
			}
		}
	}
}

// Control: the same fixtures with a review of the withheld line injected do
// pass, so the tests above fail for want of that review and of nothing else.
func TestScanWithheldPairControlWithInjectedReview(t *testing.T) {
	t.Parallel()
	for _, policy := range withheldPolicies {
		result, path := withheldScan(t, withheldKnowledge(t, true), policy, kafkaV1Doc, "7.5.0", "7.6.0")
		requireNoCover(t, result, path)
		if len(path.Hops) != 1 || len(path.Hops[0].Families) != 1 || path.Hops[0].Families[0].Status != scanreport.FamilyPass || path.Hops[0].Families[0].Line != withheldLine {
			t.Fatalf("policy %q: the control did not flip: %+v", policy, path)
		}
	}
	// Across the line only a stepwise path can pass (a direct hop over several
	// lines is never decided by a line review).
	for _, policy := range []string{"", "sequential_minor"} {
		for _, target := range []string{"7.7.0", "7.8.0", "7.10.0"} {
			result, path := withheldScan(t, withheldKnowledge(t, true), policy, kafkaV1Doc, "7.5.0", target)
			requireNoCover(t, result, path)
			if path.Jump == nil || path.Jump.Status != scanreport.JumpStepwisePass || path.Jump.Hops[0].Status != scanreport.JumpHopPass {
				t.Fatalf("policy %q to %s: the control did not flip: %+v", policy, target, path.Jump)
			}
		}
	}
}
