// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract/extractpack"
)

// publishedRule is what the advice consistency checks read of a rule in the
// CNCF pack.
type publishedRule struct {
	ID, Next, To string
	Members      []string
}

func publishedCRDRules(t *testing.T) []publishedRule {
	t.Helper()
	raw, err := os.ReadFile("../../cncfcheck/data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	var pack struct {
		Entries []struct {
			Rule struct {
				ID         string `json:"id"`
				NextAction string `json:"nextAction"`
				Subject    struct {
					To string `json:"to"`
				} `json:"subject"`
				SetCondition struct {
					Members []string `json:"members"`
				} `json:"setCondition"`
			} `json:"rule"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(raw, &pack); err != nil {
		t.Fatal(err)
	}
	var out []publishedRule
	for _, e := range pack.Entries {
		if strings.Contains(e.Rule.ID, ".crd-version-removal.") {
			out = append(out, publishedRule{e.Rule.ID, e.Rule.NextAction, e.Rule.Subject.To, e.Rule.SetCondition.Members})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// adviceInputs are the values nextAction reads.
type adviceInputs struct {
	Kind, Group, Repl, To string
	Stored                []string
}

func (in adviceInputs) current() string {
	return nextAction(&CRD{Kind: in.Kind, Group: in.Group}, in.Repl, in.Stored, in.To)
}

var (
	reNewAdvice = regexp.MustCompile(`^(verify completed storage migration before removing old status\.storedVersions; )?(?:migrate (\S+) manifests/clients to (\S+)/(\S+)|identify a supported migration for (\S+) manifests/clients); for managed objects, follow supported controller migration or investigate before upgrade to (\S+)$`)
	// The wording of extractor 2.7.0 and earlier (the two shapes the
	// published rules carry).
	reOldPlain  = regexp.MustCompile(`^change apiVersion of (\S+) to (\S+)/(\S+) before upgrading to (\S+)$`)
	reOldStored = regexp.MustCompile(`^migrate stored (\S+) objects to (\S+) and remove (.+) from status\.storedVersions, then change apiVersion to (\S+)/(\S+) before upgrading to (\S+)$`)
)

// parseAdvice recovers the inputs of a published advice text, in the current
// wording or in the earlier one.
func parseAdvice(s string) (adviceInputs, bool) {
	if m := reNewAdvice.FindStringSubmatch(s); m != nil {
		in := adviceInputs{To: m[6]}
		if m[1] != "" {
			in.Stored = []string{"stored"}
		}
		if m[5] != "" {
			in.Kind = m[5]
		} else {
			in.Kind, in.Group, in.Repl = m[2], m[3], m[4]
		}
		return in, true
	}
	if m := reOldPlain.FindStringSubmatch(s); m != nil {
		return adviceInputs{Kind: m[1], Group: m[2], Repl: m[3], To: m[4]}, true
	}
	if m := reOldStored.FindStringSubmatch(s); m != nil && m[2] == m[5] {
		return adviceInputs{Kind: m[1], Repl: m[2], Stored: strings.Split(m[3], ", "), Group: m[4], To: m[6]}, true
	}
	return adviceInputs{}, false
}

func sum(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// Every published rule's advice is what the current extractor derives from the
// rule's own inputs, except the rules on the explicit pending-migration list
// (extractpack.RemediationAllowList). A wording change in nextAction therefore
// fails here until the rules are renewed or listed; the list shrinks as
// renewals land.
func TestPublishedRemediationAdviceMatchesExtractor(t *testing.T) {
	pending := map[string]extractpack.RemediationPair{}
	for _, p := range extractpack.RemediationAllowList() {
		if _, dup := pending[p.RuleID]; dup {
			t.Errorf("pending list holds %s twice", p.RuleID)
		}
		pending[p.RuleID] = p
	}
	seen := map[string]bool{}
	var derived []string
	for _, r := range publishedCRDRules(t) {
		in, ok := parseAdvice(r.Next)
		if !ok {
			t.Errorf("%s: advice %q has a shape this test does not know: the extractor change that introduced it must update parseAdvice and renew or list the published rules", r.ID, r.Next)
			continue
		}
		for _, m := range r.Members {
			parts := strings.Split(m, "/")
			if len(parts) != 3 || (in.Group != "" && parts[0] != in.Group) || parts[2] != in.Kind {
				t.Errorf("%s: member %q does not match the advice inputs %+v", r.ID, m, in)
			}
		}
		if in.To != r.To {
			t.Errorf("%s: advice target %q differs from subject.to %q", r.ID, in.To, r.To)
		}
		cur := in.current()
		p, listed := pending[r.ID]
		seen[r.ID] = true
		if cur != r.Next {
			derived = append(derived, fmt.Sprintf("\t{RuleID: %q, OldSHA256: %q, NewSHA256: %q},", r.ID, sum(r.Next), sum(cur)))
		}
		switch {
		case cur == r.Next && listed:
			t.Errorf("%s: advice is current but the rule is still on the pending list: remove its entry from remediationAllowList and raise RemediationAllowListVersion", r.ID)
		case cur != r.Next && !listed:
			t.Errorf("%s: published advice %q differs from the current extractor output %q. The extractor change that altered nextAction must be followed by renewing this rule; until then add it to the pending list (remediationAllowList in extractpack/remediation.go, regenerate with PRUFYX_PRINT_REMEDIATION_ALLOWLIST=1)", r.ID, r.Next, cur)
		case cur != r.Next && (p.OldSHA256 != sum(r.Next) || p.NewSHA256 != sum(cur)):
			t.Errorf("%s: pending entry does not match the published advice and the current output (old %s new %s)", r.ID, sum(r.Next), sum(cur))
		}
	}
	for id := range pending {
		if !seen[id] {
			t.Errorf("pending entry %s names no published crd-version-removal rule: remove it", id)
		}
	}
	if os.Getenv("PRUFYX_PRINT_REMEDIATION_ALLOWLIST") != "" {
		t.Logf("allow-list (%d):\n%s", len(derived), strings.Join(derived, "\n"))
	}
}
