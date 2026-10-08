// SPDX-License-Identifier: AGPL-3.0-only

package rulecheck

import (
	"encoding/json"
	"fmt"

	"github.com/prufyx/prufyx/cli/internal/distribution"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

// AttestationCitationItem is the citation item of one line attestation.
func AttestationCitationItem(a lineattest.LineAttestation) CitationItem {
	return CitationItem{Record: true, ID: "lineAttestation " + a.Key().String(), Sources: a.Evidence.Sources}
}

// PolicyCitationItem is the citation item of one path policy.
func PolicyCitationItem(r upgradepath.Record) CitationItem {
	return CitationItem{Record: true, ID: "pathPolicy " + r.Component, Sources: r.Evidence.Sources}
}

// PackCitationItems lists every source-bearing item of a whole pack: its
// rules, line attestations, path policies and distribution records and
// applicability statements. The pack sections are located exactly as the
// pack loader locates them (lineattest.PackMemberSection), so a malformed
// pack is an error, never a pack "without" the section.
func PackCitationItems(pack []byte) ([]CitationItem, error) {
	var doc struct {
		Entries []struct {
			Rule json.RawMessage `json:"rule"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(pack, &doc); err != nil || len(doc.Entries) == 0 {
		return nil, fmt.Errorf("not a rule pack with entries")
	}
	rules := make([]json.RawMessage, 0, len(doc.Entries))
	for _, entry := range doc.Entries {
		rules = append(rules, entry.Rule)
	}
	items, err := RuleCitationItems(rules)
	if err != nil {
		return nil, err
	}
	section, present, err := lineattest.PackMemberSection(pack, lineattest.PackMember)
	if err != nil {
		return nil, err
	}
	if present {
		atts, err := lineattest.Parse(section)
		if err != nil {
			return nil, err
		}
		for _, a := range atts {
			items = append(items, AttestationCitationItem(a))
		}
	}
	if section, present, err = lineattest.PackMemberSection(pack, upgradepath.PackMember); err != nil {
		return nil, err
	}
	if present {
		policies, err := upgradepath.Parse(section)
		if err != nil {
			return nil, err
		}
		for _, p := range policies {
			items = append(items, PolicyCitationItem(p))
		}
	}
	if section, present, err = lineattest.PackMemberSection(pack, distribution.PackMember); err != nil {
		return nil, err
	}
	if present {
		parsed, err := distribution.Parse(section)
		if err != nil {
			return nil, err
		}
		for _, r := range parsed.Records {
			items = append(items, CitationItem{Record: true, ID: "distribution " + r.Distribution, Sources: r.Evidence.Sources})
		}
		for _, a := range parsed.Applicability {
			items = append(items, CitationItem{Record: true, ID: "applicability " + a.Distribution + " " + a.Family, Sources: a.Evidence.Sources})
		}
	}
	return items, nil
}
