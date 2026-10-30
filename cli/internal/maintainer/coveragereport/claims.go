// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// The README sentences that make claims about the rules themselves, each
// between its own marker pair and generated from the rule packs: how the
// active rules were established, and when they stop being valid.
const (
	READMEBasisBegin    = "<!-- basis-counts:begin -->"
	READMEBasisEnd      = "<!-- basis-counts:end -->"
	READMEValidityBegin = "<!-- validity-window:begin -->"
	READMEValidityEnd   = "<!-- validity-window:end -->"
)

type claimEvidence struct {
	Basis      string `json:"basis"`
	State      string `json:"state"`
	ValidUntil string `json:"validUntil"`
}

type claimPack struct {
	Entries []struct {
		Rule struct {
			Evidence claimEvidence `json:"evidence"`
		} `json:"rule"`
	} `json:"entries"`
	LineAttestations []struct {
		Evidence claimEvidence `json:"evidence"`
	} `json:"lineAttestations"`
	ServedAPIs []struct {
		Evidence claimEvidence `json:"evidence"`
	} `json:"servedAPIs"`
}

func parseClaimPacks(packs ...[]byte) ([]claimPack, error) {
	out := make([]claimPack, 0, len(packs))
	for i, raw := range packs {
		var p claimPack
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, fmt.Errorf("rule pack %d: %w", i+1, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// basisCounts renders "N basis `a`, M basis `b`" in the order of the closed
// vocabulary. An unknown basis is an error, never silently dropped.
func basisCounts(counts map[string]int) (string, error) {
	var parts []string
	seen := 0
	for _, b := range constraintengine.Bases() {
		if n := counts[b]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d with basis `%s`", n, b))
			seen += n
		}
	}
	total := 0
	for _, n := range counts {
		total += n
	}
	if seen != total {
		return "", fmt.Errorf("a rule pack holds a basis outside the closed vocabulary")
	}
	return strings.Join(parts, ", "), nil
}

// RenderBasisSentence renders the text between the basis-counts markers from
// the rule packs. An absent basis is a reviewed rule. It ends with one
// newline.
func RenderBasisSentence(packs ...[]byte) (string, error) {
	ps, err := parseClaimPacks(packs...)
	if err != nil {
		return "", err
	}
	rules := map[string]int{}
	atts := map[string]int{}
	nRules, nAtts := 0, 0
	for _, p := range ps {
		for _, e := range p.Entries {
			if ev := e.Rule.Evidence; ev.State == "active" {
				rules[constraintengine.EffectiveBasis(ev.Basis)]++
				nRules++
			}
		}
		for _, a := range p.LineAttestations {
			atts[constraintengine.EffectiveBasis(a.Evidence.Basis)]++
			nAtts++
		}
		for _, a := range p.ServedAPIs {
			atts[constraintengine.EffectiveBasis(a.Evidence.Basis)]++
			nAtts++
		}
	}
	rc, err := basisCounts(rules)
	if err != nil {
		return "", err
	}
	ac, err := basisCounts(atts)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Of the %d active rules shipped today, %s. A `reviewed` rule was established by a person who read the cited upstream evidence. A `mechanical` rule was derived from upstream source by an extractor program that is re-run and checked before the rule is accepted; no person reviewed it rule by rule.", nRules, rc)
	if nAtts > 0 {
		fmt.Fprintf(&b, " The %d release-line attestations and served-API lists are separate records: %s.", nAtts, ac)
	}
	b.WriteString("\n")
	return b.String(), nil
}

// RenderValiditySentence renders the text between the validity-window
// markers from the rule packs: the number of active rules and the earliest
// and latest day on which one stops being valid. It ends with one newline.
func RenderValiditySentence(packs ...[]byte) (string, error) {
	ps, err := parseClaimPacks(packs...)
	if err != nil {
		return "", err
	}
	n := 0
	var first, last string
	for _, p := range ps {
		for _, e := range p.Entries {
			ev := e.Rule.Evidence
			if ev.State != "active" {
				continue
			}
			until, err := constraintengine.ParseUTC(ev.ValidUntil)
			if err != nil {
				return "", fmt.Errorf("a rule has no readable validUntil: %w", err)
			}
			day := until.UTC().Format("2006-01-02")
			if n == 0 || day < first {
				first = day
			}
			if n == 0 || day > last {
				last = day
			}
			n++
		}
	}
	if n == 0 {
		return "", fmt.Errorf("the rule packs hold no active rule")
	}
	return fmt.Sprintf("The %d active rules shipped today stop being valid, rule by rule, between %s and %s unless their review is renewed; after its date a build without newer knowledge answers `UNKNOWN` for that rule.\n", n, first, last), nil
}
