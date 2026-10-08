// SPDX-License-Identifier: AGPL-3.0-only

//go:build prufyx_synthetic_knowledge

package communityapp

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract/supersedeids"
)

// Run with: go test -tags prufyx_synthetic_knowledge -run Synthetic ./internal/communityapp/
//
// The generic check route runs end to end against synthetic, never published
// mechanical, consensus and lead rules for one Kubernetes transition.

func syntheticBasisEntry(id, operator, basis, extra string) cncfcheck.Entry {
	entry := syntheticKubernetesEntry(id, operator, "REVIEWED_SOURCE_CONSTRAINT", "plan the reviewed route", extra)
	provenance := `"basis":"` + basis + `","derivedAt":"2026-09-20T00:00:00Z",`
	if basis == constraintengine.BasisMechanical {
		provenance = `"basis":"mechanical","extractor":{"id":"synthetic-extractor","version":"1.0.0","codeDigest":"sha256:` + strings.Repeat("1", 64) + `"},"derivedAt":"2026-09-20T00:00:00Z",`
	}
	entry.Rule = []byte(strings.Replace(string(entry.Rule), `"evidence":{`, `"evidence":{`+provenance, 1))
	return entry
}

func TestSyntheticRequireBasisThroughTheCommandRoute(t *testing.T) {
	satisfied := `,"dependency":{"side":"proposed","component":"pkg:github/kubernetes/kubernetes","comparison":"gte","version":"1.36.0"}`
	reviewed := syntheticKubernetesEntry("kubernetes.synthetic-a-reviewed.1-35-0-to-1-36-0", "require_component_version", "REVIEWED_SOURCE_CONSTRAINT", "keep the reviewed version", satisfied)
	mechanical := syntheticBasisEntry("kubernetes.synthetic-b-mechanical.1-35-0-to-1-36-0", "require_component_version", constraintengine.BasisMechanical, satisfied)
	consensus := syntheticBasisEntry("kubernetes.synthetic-c-consensus.1-35-0-to-1-36-0", "require_component_version", constraintengine.BasisConsensus, satisfied)
	lead := syntheticBasisEntry("kubernetes.synthetic-d-lead.1-35-0-to-1-36-0", "forbid_target_version", constraintengine.BasisLead, "")
	input := []byte(`{"schema":"` + constraintengine.InputSchema + `","authority":"` + constraintengine.InputAuthority + `","current":{"components":[{"component":"pkg:github/kubernetes/kubernetes","version":"1.35.0","facts":[]}]},"proposed":{"components":[{"component":"pkg:github/kubernetes/kubernetes","version":"1.36.0","facts":[]}]}}`)
	for _, tc := range []struct {
		name     string
		entries  []cncfcheck.Entry
		policy   string
		exit     int
		json     []string
		human    []string
		notHuman []string
	}{
		{"default: consensus never passes, lead left out", []cncfcheck.Entry{reviewed, mechanical, consensus, lead}, "", ExitUnknown,
			[]string{`"status":"NO_KNOWN_ISSUE"`, `"trustPolicy":{"requiredBasis":["reviewed","mechanical","empirical","consensus"],"excludedRules":0,"excludedLeadRules":1}`, `"engineContractDigest":"` + constraintengine.EngineContractDigestBasis() + `"`},
			[]string{"1 finding relies on model consensus\n", "kubernetes.synthetic-c-consensus.1-35-0-to-1-36-0: NO_KNOWN_ISSUE (CONSENSUS_NO_KNOWN_ISSUE)\n", "evidence basis: two independent model readings, citations verified; may block, never passes\n", "trust policy: 1 unverified lead not shown; add lead to --require-basis to list it\n", "2 rules PASS (not listed; use --show-passes)\n"},
			[]string{"synthetic-d-lead", "result cannot pass"}},
		{"reviewed only: mechanical rules left out, the check cannot pass", []cncfcheck.Entry{reviewed, mechanical, consensus, lead}, "reviewed", ExitUnknown,
			[]string{`"trustPolicy":{"requiredBasis":["reviewed"],"excludedRules":2,"excludedLeadRules":1}`, `"status":"PASS"`},
			[]string{"trust policy: evidence basis reviewed only; 2 rules left out, so the result cannot pass\n", "1 rule PASS (not listed; use --show-passes)\n"},
			[]string{"synthetic-b-mechanical", "synthetic-c-consensus", "model consensus"}},
		{"lead listed: an unverified lead never blocks", []cncfcheck.Entry{reviewed, mechanical, lead}, "reviewed,mechanical,lead", ExitOK,
			[]string{`"status":"NOTICE"`, `"reasonCode":"LEAD_NOT_VERIFIED"`},
			[]string{"unverified lead (does not block): kubernetes.synthetic-d-lead.1-35-0-to-1-36-0\nworth checking: plan the reviewed route\nevidence basis: one unverified model reading; never blocks or passes\n"},
			[]string{"BLOCKED", "trust policy"}},
		{"no consensus finding, no note", []cncfcheck.Entry{reviewed, mechanical}, "", ExitOK, nil, nil, []string{"model consensus", "trust policy"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restore, err := cncfcheck.UseSyntheticKnowledge(nil, tc.entries)
			if err != nil {
				t.Fatal(err)
			}
			defer restore()
			path := writeCNCFFile(t, "input.json", input, 0o600)
			args := []string{"check", "cncf", "--project", "kubernetes", "--input", path, "--now", supersedeids.ClockString()}
			if tc.policy != "" {
				args = append(args, "--require-basis", tc.policy)
			}
			code, stdout, stderr := runCNCFCLI(t, args...)
			if code != tc.exit || stderr != "" {
				t.Fatalf("code=%d stderr=%s stdout=%s", code, stderr, stdout)
			}
			for _, want := range tc.human {
				if !strings.Contains(stdout, want) {
					t.Fatalf("human lacks %q:\n%s", want, stdout)
				}
			}
			for _, unwanted := range tc.notHuman {
				if strings.Contains(stdout, unwanted) {
					t.Fatalf("human holds %q:\n%s", unwanted, stdout)
				}
			}
			code, report, _ := runCNCFCLI(t, append(args, "--format", "json")...)
			if code != tc.exit {
				t.Fatalf("json code=%d", code)
			}
			for _, want := range tc.json {
				if !strings.Contains(report, want) {
					t.Fatalf("json lacks %s:\n%s", want, report)
				}
			}
		})
	}
}
