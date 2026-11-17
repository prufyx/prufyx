// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
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
	Sources      []citedSource
}

type citedSource struct{ ID, Revision, ContentDigest string }

// adviceRow holds the advice inputs the rule's own members and subject do
// not carry: the replacement version and the stored-version flag. Rows were
// first filled in by hand from the published advice; they are verified, not
// derived, by testdata/crd-advice-verification.json, which records what the
// cited CRD files themselves say (see TestAdviceRowsMatchCRDVerification).
type adviceRow struct {
	RuleID                string `json:"ruleId"`
	Replacement           string `json:"replacement"`
	StoredVersionsPresent bool   `json:"storedVersionsPresent"`
	SourcesDigest         string `json:"sourcesDigest"`
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
				Evidence struct {
					Sources []struct {
						ID            string `json:"id"`
						Revision      string `json:"revision"`
						ContentDigest string `json:"contentDigest"`
					} `json:"sources"`
				} `json:"evidence"`
			} `json:"rule"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(raw, &pack); err != nil {
		t.Fatal(err)
	}
	var out []publishedRule
	for _, e := range pack.Entries {
		if !strings.Contains(e.Rule.ID, ".crd-version-removal.") {
			continue
		}
		r := publishedRule{ID: e.Rule.ID, Next: e.Rule.NextAction, To: e.Rule.Subject.To, Members: e.Rule.SetCondition.Members}
		for _, s := range e.Rule.Evidence.Sources {
			r.Sources = append(r.Sources, citedSource{s.ID, s.Revision, s.ContentDigest})
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func adviceRows(t *testing.T) map[string]adviceRow {
	t.Helper()
	raw, err := os.ReadFile("testdata/crd-advice-inputs.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Version int         `json:"version"`
		Rules   []adviceRow `json:"rules"`
	}
	if err := json.Unmarshal(raw, &f); err != nil || f.Version != 1 {
		t.Fatalf("advice inputs: version %d, %v", f.Version, err)
	}
	out := map[string]adviceRow{}
	for _, r := range f.Rules {
		if _, dup := out[r.RuleID]; dup {
			t.Fatalf("advice inputs hold %s twice", r.RuleID)
		}
		out[r.RuleID] = r
	}
	return out
}

func sum(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// sourcesDigest binds an advice row to the sources a rule cites.
func sourcesDigest(srcs []citedSource) string {
	s := append([]citedSource(nil), srcs...)
	sort.Slice(s, func(i, j int) bool { return s[i].ID < s[j].ID })
	var b strings.Builder
	for _, x := range s {
		fmt.Fprintf(&b, "%s|%s|%s\n", x.ID, x.Revision, x.ContentDigest)
	}
	return sum(b.String())
}

// currentAdvice derives what the current extractor says for the rule. The
// kind, group and target come from the rule's structured members and subject;
// the replacement version and the stored-version state come from the advice
// row, never from the rule's own advice text. It fails when the row is not
// bound to the rule's cited sources.
func currentAdvice(r publishedRule, row adviceRow) (string, error) {
	if row.SourcesDigest != sourcesDigest(r.Sources) {
		return "", fmt.Errorf("the advice row of %s is not bound to the sources the rule cites now: re-read the cited CRDs and update testdata/crd-advice-inputs.json", r.ID)
	}
	var kind, group string
	for _, m := range r.Members {
		parts := strings.Split(m, "/")
		if len(parts) != 3 {
			return "", fmt.Errorf("%s: member %q is not group/version/Kind", r.ID, m)
		}
		if kind != "" && (kind != parts[2] || group != parts[0]) {
			return "", fmt.Errorf("%s: members name more than one kind", r.ID)
		}
		group, kind = parts[0], parts[2]
	}
	if kind == "" {
		return "", fmt.Errorf("%s: no members", r.ID)
	}
	var stored []string
	if row.StoredVersionsPresent {
		stored = []string{"stored"}
	}
	return nextAction(&CRD{Kind: kind, Group: group}, row.Replacement, stored, r.To), nil
}

// checkPublished is the consistency rule for one published rule: its advice
// is the current extractor output for inputs read from structured fields and
// the pinned CRD row, unless the rule is on the pending list (then the list
// entry must describe exactly this published text and the current output).
func checkPublished(r publishedRule, row adviceRow, hasRow bool, pending map[string]extractpack.RemediationPair) error {
	if !hasRow {
		return fmt.Errorf("%s: no row in testdata/crd-advice-inputs.json: add one by reading the CRDs the rule cites", r.ID)
	}
	cur, err := currentAdvice(r, row)
	if err != nil {
		return err
	}
	p, listed := pending[r.ID]
	switch {
	case cur == r.Next && listed:
		return fmt.Errorf("%s: advice is current but the rule is still on the pending list: remove its entry from remediationAllowList and raise RemediationAllowListVersion", r.ID)
	case cur != r.Next && !listed:
		return fmt.Errorf("%s: published advice %q differs from the current extractor output %q. The extractor change that altered nextAction must be followed by renewing this rule; until then add it to the pending list (remediationAllowList in extractpack/remediation.go, regenerate with PRUFYX_PRINT_REMEDIATION_ALLOWLIST=1). If instead this rule's advice or sources were edited by hand, revert that", r.ID, r.Next, cur)
	case cur != r.Next && (p.OldSHA256 != sum(r.Next) || p.NewSHA256 != sum(cur)):
		return fmt.Errorf("%s: pending entry does not match the published advice and the current output (old %s new %s)", r.ID, sum(r.Next), sum(cur))
	}
	return nil
}

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
	rows := adviceRows(t)
	seen := map[string]bool{}
	var derived []string
	for _, r := range publishedCRDRules(t) {
		seen[r.ID] = true
		row, ok := rows[r.ID]
		if err := checkPublished(r, row, ok, pending); err != nil {
			t.Error(err)
		}
		if cur, err := currentAdvice(r, row); err == nil && cur != r.Next {
			derived = append(derived, fmt.Sprintf("\t{RuleID: %q, OldSHA256: %q, NewSHA256: %q},", r.ID, sum(r.Next), sum(cur)))
		}
	}
	for id := range pending {
		if !seen[id] {
			t.Errorf("pending entry %s names no published crd-version-removal rule: remove it", id)
		}
	}
	for id := range rows {
		if !seen[id] {
			t.Errorf("advice row %s names no published crd-version-removal rule: remove it", id)
		}
	}
	if os.Getenv("PRUFYX_PRINT_REMEDIATION_ALLOWLIST") != "" {
		t.Logf("allow-list (%d):\n%s", len(derived), strings.Join(derived, "\n"))
	}
}

// Mutating the advice inputs of a rule that is current (not pending) fails:
// the replacement version and the storage prefix are not taken from the text
// being checked.
func TestRemediationConsistencyDetectsMutatedInputs(t *testing.T) {
	pending := map[string]extractpack.RemediationPair{}
	for _, p := range extractpack.RemediationAllowList() {
		pending[p.RuleID] = p
	}
	rows := adviceRows(t)
	var current []publishedRule
	for _, r := range publishedCRDRules(t) {
		if _, listed := pending[r.ID]; !listed {
			current = append(current, r)
		}
	}
	if len(current) == 0 {
		t.Skip("every published rule is pending")
	}
	for _, r := range current {
		row := rows[r.ID]
		if err := checkPublished(r, row, true, pending); err != nil {
			t.Fatalf("baseline: %v", err)
		}
		mut := map[string]func(publishedRule) publishedRule{
			"replacement version in the advice text": func(x publishedRule) publishedRule {
				x.Next = strings.Replace(x.Next, "/"+row.Replacement+";", "/"+row.Replacement+"x;", 1)
				return x
			},
			"storage prefix removed from the advice text": func(x publishedRule) publishedRule {
				x.Next = strings.TrimPrefix(x.Next, "verify completed storage migration before removing old status.storedVersions; ")
				return x
			},
			"storage prefix added to the advice text": func(x publishedRule) publishedRule {
				x.Next = "verify completed storage migration before removing old status.storedVersions; " + x.Next
				return x
			},
			"target version in the advice text": func(x publishedRule) publishedRule {
				x.Next = strings.Replace(x.Next, "upgrade to "+x.To, "upgrade to 9.9.9", 1)
				return x
			},
			"cited source re-pinned": func(x publishedRule) publishedRule {
				x.Sources = append([]citedSource(nil), x.Sources...)
				x.Sources[0].ContentDigest = "sha256:" + strings.Repeat("0", 64)
				return x
			},
		}
		for name, f := range mut {
			m := f(r)
			if m.Next == r.Next && len(m.Sources) > 0 && m.Sources[0] == r.Sources[0] {
				continue // the mutation does not apply to this rule's shape
			}
			if err := checkPublished(m, row, true, pending); err == nil {
				t.Errorf("%s: %s passed", r.ID, name)
			}
		}
		// Editing the row alone (without the text) also fails.
		bad := row
		bad.Replacement += "x"
		if err := checkPublished(r, bad, true, pending); err == nil {
			t.Errorf("%s: a changed replacement in the row passed", r.ID)
		}
		bad = row
		bad.StoredVersionsPresent = !bad.StoredVersionsPresent
		if err := checkPublished(r, bad, true, pending); err == nil {
			t.Errorf("%s: a flipped storage flag in the row passed", r.ID)
		}
	}
}

// verifiedSource is one cited CRD file as read from its upstream repository
// at the cited revision by testdata/verify-crd-advice.py.
type verifiedSource struct {
	ID       string `json:"id"`
	Repo     string `json:"repo"`
	Revision string `json:"revision"`
	Path     string `json:"path"`
	Digest   string `json:"digest"`
	Versions []struct {
		Name    string `json:"name"`
		Served  bool   `json:"served"`
		Storage bool   `json:"storage"`
	} `json:"versions"`
}

type verifiedRule struct {
	RuleID                string           `json:"ruleId"`
	Sources               []verifiedSource `json:"sources"`
	RemovedVersions       []string         `json:"removedVersions"`
	Replacement           string           `json:"replacement"`
	StoredVersionsPresent bool             `json:"storedVersionsPresent"`
}

func verifiedRules(t *testing.T) map[string]verifiedRule {
	t.Helper()
	raw, err := os.ReadFile("testdata/crd-advice-verification.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Version int            `json:"version"`
		Rules   []verifiedRule `json:"rules"`
	}
	if err := json.Unmarshal(raw, &f); err != nil || f.Version != 1 {
		t.Fatalf("advice verification: version %d, %v", f.Version, err)
	}
	out := map[string]verifiedRule{}
	for _, r := range f.Rules {
		if _, dup := out[r.RuleID]; dup {
			t.Fatalf("advice verification holds %s twice", r.RuleID)
		}
		out[r.RuleID] = r
	}
	return out
}

// derive recomputes the advice inputs from the recorded spec.versions flags:
// the replacement is the extractor's replacement() over the later CRD (the
// source whose id does not start with "crd-versions-"), and a stored version
// is present when a version the later CRD no longer serves has storage: true
// in the earlier or the later file.
func (v verifiedRule) derive() (string, bool, error) {
	var later, earlier *verifiedSource
	for i := range v.Sources {
		if strings.HasPrefix(v.Sources[i].ID, "crd-versions-") {
			if earlier != nil {
				return "", false, fmt.Errorf("%s: more than one earlier source", v.RuleID)
			}
			earlier = &v.Sources[i]
		} else {
			if later != nil {
				return "", false, fmt.Errorf("%s: more than one later source", v.RuleID)
			}
			later = &v.Sources[i]
		}
	}
	if earlier == nil || later == nil {
		return "", false, fmt.Errorf("%s: needs one earlier and one later source", v.RuleID)
	}
	crd := &CRD{}
	servedLater := map[string]bool{}
	for _, x := range later.Versions {
		crd.Versions = append(crd.Versions, CRDVersion{Name: x.Name, Served: x.Served, Storage: x.Storage})
		if x.Served {
			servedLater[x.Name] = true
		}
	}
	removed := map[string]bool{}
	for _, x := range earlier.Versions {
		if x.Served && !servedLater[x.Name] {
			removed[x.Name] = true
		}
	}
	stored := false
	for _, s := range []*verifiedSource{earlier, later} {
		for _, x := range s.Versions {
			if x.Storage && removed[x.Name] {
				stored = true
			}
		}
	}
	return replacement(crd), stored, nil
}

// checkVerified requires a row to equal what the verification record derives
// from the cited CRD files, and the record to name exactly the sources the
// rule cites (id, revision, path in the url, content digest).
func checkVerified(r publishedRule, row adviceRow, v verifiedRule, hasRecord bool) error {
	if !hasRecord {
		return fmt.Errorf("%s: no entry in testdata/crd-advice-verification.json: run testdata/verify-crd-advice.py", r.ID)
	}
	cited := map[string]citedSource{}
	for _, s := range r.Sources {
		cited[s.ID] = s
	}
	if len(v.Sources) != len(cited) {
		return fmt.Errorf("%s: verification records %d sources, rule cites %d", r.ID, len(v.Sources), len(cited))
	}
	for _, s := range v.Sources {
		c, ok := cited[s.ID]
		if !ok || c.Revision != s.Revision || c.ContentDigest != s.Digest || len(s.Digest) != len("sha256:")+64 {
			return fmt.Errorf("%s: verification of source %s does not match the cited revision/digest: re-run testdata/verify-crd-advice.py", r.ID, s.ID)
		}
	}
	repl, stored, err := v.derive()
	if err != nil {
		return err
	}
	if v.Replacement != repl || v.StoredVersionsPresent != stored {
		return fmt.Errorf("%s: recorded inputs (%s, %v) differ from what the recorded versions derive (%s, %v)", r.ID, v.Replacement, v.StoredVersionsPresent, repl, stored)
	}
	if row.Replacement != repl || row.StoredVersionsPresent != stored {
		return fmt.Errorf("%s: advice row (%s, %v) differs from the CRD-derived inputs (%s, %v)", r.ID, row.Replacement, row.StoredVersionsPresent, repl, stored)
	}
	return nil
}

// Every advice row equals the inputs derived from the cited CRD files'
// spec.versions, as recorded with their revision and sha256 by
// testdata/verify-crd-advice.py (which fetched the files and checked the
// digests against the rule's cited contentDigest).
func TestAdviceRowsMatchCRDVerification(t *testing.T) {
	rows, rec := adviceRows(t), verifiedRules(t)
	seen := map[string]bool{}
	for _, r := range publishedCRDRules(t) {
		seen[r.ID] = true
		row, okRow := rows[r.ID]
		if !okRow {
			t.Errorf("%s: no advice row", r.ID)
			continue
		}
		v, ok := rec[r.ID]
		if err := checkVerified(r, row, v, ok); err != nil {
			t.Error(err)
		}
	}
	for id := range rec {
		if !seen[id] {
			t.Errorf("verification entry %s names no published crd-version-removal rule: remove it", id)
		}
	}
}

// A changed row, record, flag or cited digest fails the verification.
func TestAdviceVerificationDetectsMutations(t *testing.T) {
	rows, rec := adviceRows(t), verifiedRules(t)
	rules := publishedCRDRules(t)
	if len(rules) == 0 {
		t.Fatal("no published crd-version-removal rules")
	}
	for _, r := range rules {
		row, v := rows[r.ID], rec[r.ID]
		if err := checkVerified(r, row, v, true); err != nil {
			t.Fatalf("baseline: %v", err)
		}
		if err := checkVerified(r, row, verifiedRule{}, false); err == nil {
			t.Errorf("%s: a missing record passed", r.ID)
		}
		bad := row
		bad.Replacement += "x"
		if checkVerified(r, bad, v, true) == nil {
			t.Errorf("%s: a changed row replacement passed", r.ID)
		}
		bad = row
		bad.StoredVersionsPresent = !bad.StoredVersionsPresent
		if checkVerified(r, bad, v, true) == nil {
			t.Errorf("%s: a flipped row storage flag passed", r.ID)
		}
		// The record's own derived fields must follow its recorded flags.
		bv := v
		bv.Replacement += "x"
		if checkVerified(r, row, bv, true) == nil {
			t.Errorf("%s: a record replacement not derived from its versions passed", r.ID)
		}
		bv = v
		bv.StoredVersionsPresent = !bv.StoredVersionsPresent
		if checkVerified(r, row, bv, true) == nil {
			t.Errorf("%s: a record storage flag not derived from its versions passed", r.ID)
		}
		// Changing the recorded version flags changes the derived inputs: the
		// served flags of the later file move the replacement, and the storage
		// flags of the earlier file move the stored-version state.
		for si, src := range v.Sources {
			later := !strings.HasPrefix(src.ID, "crd-versions-")
			if !later && !v.StoredVersionsPresent {
				continue
			}
			bv = v
			bv.Sources = append([]verifiedSource(nil), v.Sources...)
			bs := src
			bs.Versions = append(bs.Versions[:0:0], bs.Versions...)
			for vi := range bs.Versions {
				if later {
					bs.Versions[vi].Served = !bs.Versions[vi].Served
				} else {
					bs.Versions[vi].Storage = false
				}
			}
			bv.Sources[si] = bs
			if checkVerified(r, row, bv, true) == nil {
				t.Errorf("%s: changed recorded version flags in %s passed", r.ID, bs.ID)
			}
		}
		// A record for another revision or digest than the rule cites.
		bv = v
		bv.Sources = append([]verifiedSource(nil), v.Sources...)
		bv.Sources[0].Digest = "sha256:" + strings.Repeat("0", 64)
		if checkVerified(r, row, bv, true) == nil {
			t.Errorf("%s: a record digest that is not the cited one passed", r.ID)
		}
		bv.Sources[0] = v.Sources[0]
		bv.Sources[0].Revision = strings.Repeat("0", 40)
		if checkVerified(r, row, bv, true) == nil {
			t.Errorf("%s: a record revision that is not the cited one passed", r.ID)
		}
		bv.Sources = v.Sources[:1]
		if checkVerified(r, row, bv, true) == nil {
			t.Errorf("%s: a record with a missing source passed", r.ID)
		}
	}
}
