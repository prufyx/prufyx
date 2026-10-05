// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
)

func cloneWorklist(t *testing.T, wl evidencerepin.Worklist) evidencerepin.Worklist {
	t.Helper()
	var out evidencerepin.Worklist
	raw, err := json.Marshal(wl)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func requireV9(t *testing.T, name string, err error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "V9:") {
		t.Errorf("%s: expected a V9 failure, got %v", name, err)
	}
}

// A latest-baseline statement whose signer worklist dropped
// "resolution: tag_fallback" must be refused against an independent
// worklist that still carries it.
func TestV9RefusesForgedWorklistDroppingTagFallback(t *testing.T) {
	packPath := "/p/rules.json"
	wl, pack := buildWorklistAndPack(t, packPath, baseNow, []ruleSpec{freshSpec("rule-a", "proj-a", baseNow)})
	statement := prepareSingle(t, wl, pack, packPath).Statement
	if len(statement.Rules) != 1 || statement.Rules[0].Citations[0].Baseline != "" {
		t.Fatalf("setup: expected one renewed latest-baseline rule: %+v", statement.NotExtended)
	}
	signerRaw := marshalWorklist(t, wl)
	if err := checkIndependentWorklist(statement, packPath, signerRaw); err != nil {
		t.Fatalf("normal case: %v", err)
	}
	if err := checkSignerWorklistAgrees(statement, packPath, signerRaw, signerRaw); err != nil {
		t.Fatalf("normal case: %v", err)
	}
	independent := cloneWorklist(t, wl)
	independent.Citations[0].Resolution = resolutionTagFallback
	indRaw := marshalWorklist(t, independent)
	requireV9(t, "independent tag_fallback, signer dropped it", checkSignerWorklistAgrees(statement, packPath, signerRaw, indRaw))
	requireV9(t, "independent tag_fallback on a renewed citation", checkIndependentWorklist(statement, packPath, indRaw))
}

// Every baseline-selecting field must agree, whichever side differs.
func TestV9SignerAndIndependentWorklistsMustAgreeOnBaselineSelectors(t *testing.T) {
	packPath := "/p/rules.json"
	wl, pack := tagLineWorklist(t, packPath)
	statement := prepareSingle(t, wl, pack, packPath).Statement
	if len(statement.Rules) != 1 {
		t.Fatalf("setup: %+v", statement.NotExtended)
	}
	raw := marshalWorklist(t, wl)
	if err := checkSignerWorklistAgrees(statement, packPath, raw, raw); err != nil {
		t.Fatalf("normal case: %v", err)
	}
	if err := checkSignerWorklistAgrees(statement, packPath, nil, raw); err != nil {
		t.Fatalf("no retained signer worklist compares nothing: %v", err)
	}
	cases := map[string]func(c *evidencerepin.ClassResult){
		"resolution tag_fallback": func(c *evidencerepin.ClassResult) { c.Resolution = resolutionTagFallback },
		"resolution other value":  func(c *evidencerepin.ClassResult) { c.Resolution = "mirror" },
		"stale":                   func(c *evidencerepin.ClassResult) { c.Stale = true },
		"baseline mode":           func(c *evidencerepin.ClassResult) { c.BaselineMode = evidencerepin.BaselineModeLatest },
		"baseline":                func(c *evidencerepin.ClassResult) { c.Baseline = evidencerepin.BaselineReleaseLine },
		"baseline line":           func(c *evidencerepin.ClassResult) { c.BaselineLine = "1.26" },
		"pinned tag":              func(c *evidencerepin.ClassResult) { c.PinnedTag = "go1.21.5" },
		"baseline tag":            func(c *evidencerepin.ClassResult) { c.BaselineTag = "go1.21.12" },
		"owner entry digest":      func(c *evidencerepin.ClassResult) { c.BaselineEntryDigest = "sha256:" + strings.Repeat("0", 64) },
	}
	for name, mutate := range cases {
		other := cloneWorklist(t, wl)
		mutate(&other.Citations[0])
		otherRaw := marshalWorklist(t, other)
		requireV9(t, name+" (independent differs)", checkSignerWorklistAgrees(statement, packPath, raw, otherRaw))
		requireV9(t, name+" (signer differs)", checkSignerWorklistAgrees(statement, packPath, otherRaw, raw))
	}
	missing := cloneWorklist(t, wl)
	missing.Citations = nil
	requireV9(t, "citation missing from signer", checkSignerWorklistAgrees(statement, packPath, marshalWorklist(t, missing), raw))
	requireV9(t, "undecodable signer", checkSignerWorklistAgrees(statement, packPath, []byte("{"), raw))
}

// Verify wires the comparison: a differing resolution on either side is
// refused end to end.
func TestVerifyRefusesDifferingResolutionBetweenWorklists(t *testing.T) {
	f := newRoleFixture(t)
	c := prepareAutomated(t, f.chainFixture, automatedPack(t, baseNow), baseNow, cycleSpecs(12, baseNow), "rev-2", nil)
	f.appendAutomated("0001", c.res.StatementCanonical)
	base := &Chain{TrustRoot: f.root, ExpectedTrustRootDigest: f.digest}
	run := func(signer, independent []byte) error {
		_, err := Verify(VerifyOptions{
			StatementRaw: c.res.StatementCanonical, PriorPackRaw: c.prior, NextPackRaw: c.res.NextPack, WorklistRaw: signer,
			Chain: f.chain(), BaseChain: base, PackName: PackCNCF, PackPath: chainPackPath,
			EngineCapabilityDigest: testEngineCapabilityDigest, AttestedAtNow: c.at.Add(time.Hour), IndependentWorklistRaw: independent,
		})
		return err
	}
	if err := run(c.worklistRaw, c.worklistRaw); err != nil {
		t.Fatalf("normal case: %v", err)
	}
	var wl evidencerepin.Worklist
	if err := json.Unmarshal(c.worklistRaw, &wl); err != nil {
		t.Fatal(err)
	}
	forged := cloneWorklist(t, wl)
	forged.Citations[0].Resolution = resolutionTagFallback
	forgedRaw := marshalWorklist(t, forged)
	requireV9(t, "independent run saw tag_fallback", run(c.worklistRaw, forgedRaw))
	if err := run(forgedRaw, c.worklistRaw); err == nil {
		t.Errorf("a signer worklist carrying tag_fallback must be refused")
	}
}
