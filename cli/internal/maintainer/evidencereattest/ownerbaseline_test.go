// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
	"github.com/prufyx/prufyx/cli/internal/maintainer/repinbaselines"
)

const ownerPackPath = "/p/owner-rules.json"

var ownerCommit = strings.Repeat("c", 40)

func ownerEntry() repinbaselines.Entry {
	return repinbaselines.Entry{
		Approval: "pr-15", Commit: ownerCommit, DecidedAt: "2026-10-05T10:00:00Z",
		Reason: "the project publishes v2.x as its stable line", Repository: "owner/shared", Tag: "v2.0.0",
	}
}

func ownerFile(t *testing.T, entries ...repinbaselines.Entry) []byte {
	t.Helper()
	raw, err := repinbaselines.File{Schema: repinbaselines.Schema, Entries: entries}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// ownerWorklist: rule-b compared with an owner-chosen baseline of the
// ambiguous repository owner/shared; rule-a, rule-c and rule-d are plain.
func ownerWorklist(t *testing.T) (evidencerepin.Worklist, []byte) {
	t.Helper()
	specs := []ruleSpec{freshSpec("rule-a", "proj-a", baseNow), freshSpec("rule-b", "proj-b", baseNow), freshSpec("rule-c", "proj-c", baseNow), freshSpec("rule-d", "proj-d", baseNow)}
	wl, pack := buildWorklistAndPack(t, ownerPackPath, baseNow, specs)
	entry := ownerEntry()
	for i := range wl.Citations {
		if wl.Citations[i].RuleID == "rule-b" {
			c := &wl.Citations[i]
			c.Owner, c.Repo = "owner", "shared"
			c.NewCommit = entry.Commit
			c.Baseline, c.BaselineTag, c.BaselineEntryDigest = evidencerepin.BaselineOwnerChoice, entry.Tag, entry.Digest()
		}
	}
	wl.Repos = append(wl.Repos, evidencerepin.RepoResolution{
		Owner: "owner", Repo: "shared", Status: "PENDING_AMBIGUOUS_LATEST", ResolvedAt: rfc3339(baseNow.Add(-1e9 * 3600)),
		OwnerBaseline: &evidencerepin.OwnerBaseline{Tag: entry.Tag, Commit: entry.Commit, EntryDigest: entry.Digest()},
	})
	return wl, padPackWithSpreadRules(t, pack, 12)
}

func ownerPrepare(t *testing.T, wl evidencerepin.Worklist, pack, baselines []byte) (PrepareResult, VerifyOptions) {
	t.Helper()
	raw := marshalWorklist(t, wl)
	prepare := PrepareOptions{
		WorklistRaw: raw, PackName: PackCNCF, PackPath: ownerPackPath, PackRaw: pack, BaselinesRaw: baselines,
		Wave: 1, AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest, Chain: &Chain{},
	}
	result, records := prepareWithSample(t, prepare)
	opts := defaultVerifyOptions(t, baseNow)
	opts.StatementRaw, opts.PriorPackRaw, opts.NextPackRaw = result.StatementCanonical, pack, result.NextPack
	opts.WorklistRaw, opts.PackName, opts.PackPath = raw, PackCNCF, ownerPackPath
	opts.EngineCapabilityDigest, opts.ReviewRecords = testEngineCapabilityDigest, records
	opts.BaselinesRaw, opts.IndependentWorklistRaw = baselines, raw
	return result, opts
}

func excludedReason(r PrepareResult, id string) string {
	for _, ne := range r.Statement.NotExtended {
		if ne.RuleID == id {
			return ne.WorstClass
		}
	}
	return ""
}

func renews(r PrepareResult, id string) bool {
	for _, ra := range r.Statement.Rules {
		if ra.RuleID == id {
			return true
		}
	}
	return false
}

func TestOwnerBaselineRenewsInAHumanStatement(t *testing.T) {
	wl, pack := ownerWorklist(t)
	result, opts := ownerPrepare(t, wl, pack, ownerFile(t, ownerEntry()))
	if !renews(result, "rule-b") || !renews(result, "rule-a") {
		t.Fatalf("rule-b must renew on the owner baseline: %+v", result.Statement.NotExtended)
	}
	for _, ra := range result.Statement.Rules {
		if ra.RuleID != "rule-b" {
			continue
		}
		c := ra.Citations[0]
		if c.Baseline != evidencerepin.BaselineOwnerChoice || c.ComparedTag != "v2.0.0" || c.ComparedCommit != ownerCommit || c.BaselineEntryDigest != ownerEntry().Digest() || c.BaselineLine != "" || c.PinnedTag != "" {
			t.Fatalf("attestation: %+v", c)
		}
	}
	if _, err := Verify(opts); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestOwnerBaselineWithoutAMatchingEntryIsNotRenewed(t *testing.T) {
	other := ownerEntry()
	other.Tag = "v2.0.1"
	moved := ownerEntry()
	moved.Commit = strings.Repeat("d", 40)
	reason := ownerEntry()
	reason.Reason = "an entry that changed after the worklist"
	elsewhere := ownerEntry()
	elsewhere.Repository = "owner/other"
	cases := map[string][]byte{
		"no file":          nil,
		"empty file":       ownerFile(t),
		"other tag":        ownerFile(t, other),
		"other commit":     ownerFile(t, moved),
		"changed entry":    ownerFile(t, reason),
		"other repository": ownerFile(t, elsewhere),
	}
	for name, file := range cases {
		wl, pack := ownerWorklist(t)
		result, _ := ownerPrepare(t, wl, pack, file)
		if renews(result, "rule-b") || excludedReason(result, "rule-b") != reasonOwnerBaselineUnverified {
			t.Errorf("%s: want %s, got %q", name, reasonOwnerBaselineUnverified, excludedReason(result, "rule-b"))
		}
		if !renews(result, "rule-a") {
			t.Errorf("%s: other rules are unaffected", name)
		}
	}
}

func TestOwnerBaselineNeedsTheVerifiedRepositoryResolution(t *testing.T) {
	file := ownerFile(t, ownerEntry())
	for name, mutate := range map[string]func(*evidencerepin.RepoResolution){
		"repository resolved normally": func(r *evidencerepin.RepoResolution) { r.Status = "RESOLVED"; r.OwnerBaseline = nil },
		"no verified baseline":         func(r *evidencerepin.RepoResolution) { r.OwnerBaseline = nil },
		"resolved with a baseline":     func(r *evidencerepin.RepoResolution) { r.Status = "RESOLVED" },
		"other tag":                    func(r *evidencerepin.RepoResolution) { r.OwnerBaseline.Tag = "v2.0.1" },
		"other commit":                 func(r *evidencerepin.RepoResolution) { r.OwnerBaseline.Commit = strings.Repeat("d", 40) },
		"other digest": func(r *evidencerepin.RepoResolution) {
			r.OwnerBaseline.EntryDigest = "sha256:" + strings.Repeat("0", 64)
		},
	} {
		wl, pack := ownerWorklist(t)
		for i := range wl.Repos {
			if wl.Repos[i].Repo == "shared" {
				mutate(&wl.Repos[i])
			}
		}
		result, _ := ownerPrepare(t, wl, pack, file)
		if renews(result, "rule-b") || excludedReason(result, "rule-b") != reasonOwnerBaselineUnverified {
			t.Errorf("%s: got %q", name, excludedReason(result, "rule-b"))
		}
	}
}

func TestOwnerBaselineCitationFieldsMustMatchTheEntry(t *testing.T) {
	file := ownerFile(t, ownerEntry())
	for name, mutate := range map[string]func(*evidencerepin.ClassResult){
		"no digest":    func(c *evidencerepin.ClassResult) { c.BaselineEntryDigest = "" },
		"no tag":       func(c *evidencerepin.ClassResult) { c.BaselineTag = "" },
		"other tag":    func(c *evidencerepin.ClassResult) { c.BaselineTag = "v2.0.1" },
		"other commit": func(c *evidencerepin.ClassResult) { c.NewCommit = strings.Repeat("d", 40) },
		"no commit":    func(c *evidencerepin.ClassResult) { c.NewCommit = "" },
	} {
		wl, pack := ownerWorklist(t)
		for i := range wl.Citations {
			if wl.Citations[i].RuleID == "rule-b" {
				mutate(&wl.Citations[i])
			}
		}
		result, _ := ownerPrepare(t, wl, pack, file)
		if renews(result, "rule-b") {
			t.Errorf("%s: renewed", name)
		}
	}
}

func TestOwnerBaselineIsNotRenewedByAutomation(t *testing.T) {
	wl, pack := ownerWorklist(t)
	result, err := Prepare(PrepareOptions{
		Mode: ModeAutomated, WorklistRaw: marshalWorklist(t, wl), PackName: PackCNCF, PackPath: ownerPackPath, PackRaw: pack,
		BaselinesRaw: ownerFile(t, ownerEntry()), AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2",
		EngineCapabilityDigest: testEngineCapabilityDigest, Chain: &Chain{},
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if renews(result, "rule-b") || excludedReason(result, "rule-b") != reasonOwnerBaselineNotAutomatable {
		t.Fatalf("automation must not renew on an owner baseline: %q", excludedReason(result, "rule-b"))
	}
}

func TestPrepareRefusesAMalformedBaselineFile(t *testing.T) {
	wl, pack := ownerWorklist(t)
	_, err := Prepare(PrepareOptions{
		WorklistRaw: marshalWorklist(t, wl), PackName: PackCNCF, PackPath: ownerPackPath, PackRaw: pack, BaselinesRaw: []byte(`{"schema":"x"}`),
		Wave: 1, AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest, Chain: &Chain{},
	})
	if err == nil || !strings.Contains(err.Error(), "owner baseline file") {
		t.Fatalf("%v", err)
	}
}

func TestVerifyRequiresTheOwnerBaselineFileAndTheIndependentWorklist(t *testing.T) {
	wl, pack := ownerWorklist(t)
	file := ownerFile(t, ownerEntry())
	_, opts := ownerPrepare(t, wl, pack, file)

	noFile := opts
	noFile.BaselinesRaw = nil
	assertVerifyRejects(t, noFile, "owner baseline file is required")

	noRerun := opts
	noRerun.IndependentWorklistRaw = nil
	assertVerifyRejects(t, noRerun, "an independent worklist is required")

	// A file that holds another entry for the repository (a newer decision)
	// no longer vouches for the statement's.
	newer := ownerEntry()
	newer.Reason, newer.DecidedAt = "a newer decision", "2026-10-06T10:00:00Z"
	other := opts
	other.BaselinesRaw = ownerFile(t, newer)
	assertVerifyRejects(t, other, "V12")

	empty := opts
	empty.BaselinesRaw = ownerFile(t)
	assertVerifyRejects(t, empty, "V12")

	garbage := opts
	garbage.BaselinesRaw = []byte(`{"schema":"x"}`)
	assertVerifyRejects(t, garbage, "")
}

func TestVerifyComparesOwnerBaselinesWithTheIndependentWorklist(t *testing.T) {
	wl, pack := ownerWorklist(t)
	file := ownerFile(t, ownerEntry())
	for name, mutate := range map[string]func(*evidencerepin.ClassResult){
		"independent run saw a line baseline": func(c *evidencerepin.ClassResult) {
			c.Baseline = evidencerepin.BaselineLatest
			c.BaselineEntryDigest = ""
		},
		"independent run saw another tag": func(c *evidencerepin.ClassResult) { c.BaselineTag = "v2.0.1" },
		"independent run saw another entry": func(c *evidencerepin.ClassResult) {
			c.BaselineEntryDigest = "sha256:" + strings.Repeat("0", 64)
		},
		"independent run saw another commit": func(c *evidencerepin.ClassResult) { c.NewCommit = strings.Repeat("d", 40) },
	} {
		_, opts := ownerPrepare(t, wl, pack, file)
		indep := wl
		indep.Citations = append([]evidencerepin.ClassResult(nil), wl.Citations...)
		for i := range indep.Citations {
			if indep.Citations[i].RuleID == "rule-b" {
				mutate(&indep.Citations[i])
			}
		}
		opts.IndependentWorklistRaw = marshalWorklist(t, indep)
		_, err := Verify(opts)
		if err == nil || !strings.Contains(err.Error(), "V9") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The reverse: the signing job claims a plain citation, the independent
	// run used an owner baseline.
	plainWL, plainPack := ownerWorklist(t)
	for i := range plainWL.Citations {
		if plainWL.Citations[i].RuleID == "rule-a" {
			plainWL.Citations[i].Baseline = evidencerepin.BaselineOwnerChoice
			plainWL.Citations[i].BaselineTag, plainWL.Citations[i].BaselineEntryDigest = "v2.0.0", ownerEntry().Digest()
		}
	}
	_, opts := ownerPrepare(t, wl, plainPack, file)
	opts.IndependentWorklistRaw = marshalWorklist(t, plainWL)
	if _, err := Verify(opts); err == nil || !strings.Contains(err.Error(), "V9") {
		t.Errorf("an owner baseline only on the independent side must be refused: %v", err)
	}
}

func TestVerifyRefusesAnOwnerBaselineDigestWithoutTheBaseline(t *testing.T) {
	wl, pack := ownerWorklist(t)
	result, opts := ownerPrepare(t, wl, pack, ownerFile(t, ownerEntry()))
	st := result.Statement
	st.Rules = append([]RuleAttestation(nil), st.Rules...)
	for i := range st.Rules {
		st.Rules[i].Citations = append([]CitationAttestation(nil), st.Rules[i].Citations...)
		if st.Rules[i].RuleID == "rule-a" {
			st.Rules[i].Citations[0].BaselineEntryDigest = ownerEntry().Digest()
		}
	}
	raw, err := CanonicalStatement(st)
	if err != nil {
		t.Fatal(err)
	}
	opts.StatementRaw = raw
	assertVerifyRejects(t, opts, "V12")
}

func TestOwnerBaselineRoleCheck(t *testing.T) {
	wl, pack := ownerWorklist(t)
	result, _ := ownerPrepare(t, wl, pack, ownerFile(t, ownerEntry()))
	doc, err := loadPack(pack)
	if err != nil {
		t.Fatal(err)
	}
	candidates, _, err := packCandidates(doc)
	if err != nil {
		t.Fatal(err)
	}
	st := result.Statement
	st.Wave, st.SampledForFullReview, st.SignerRole = 0, nil, RoleAutomation
	st.Rules = nil
	for _, ra := range result.Statement.Rules {
		if ra.RuleID == "rule-b" {
			ra.ValidUntil = st.ValidUntil
			ra.ConsecutiveBatchCycles = 1
			st.Rules = []RuleAttestation{ra}
		}
	}
	err = checkRolePolicy(st, candidatesByID(candidates))
	if err == nil || !strings.Contains(err.Error(), "owner-chosen baseline") {
		t.Fatalf("only a human statement may renew on an owner baseline: %v", err)
	}
	// A baseline name nobody defined is refused as before.
	st.Rules[0].Citations = append([]CitationAttestation(nil), st.Rules[0].Citations...)
	st.Rules[0].Citations[0].Baseline = "chosen_by_nobody"
	if err := checkRolePolicy(st, candidatesByID(candidates)); err == nil || !strings.Contains(err.Error(), "unknown baseline") {
		t.Fatalf("%v", err)
	}
}

// F3: digest and commit match the file entry but the compared tag does not.
func TestVerifyV12ComparesTheTag(t *testing.T) {
	wl, pack := ownerWorklist(t)
	result, opts := ownerPrepare(t, wl, pack, ownerFile(t, ownerEntry()))
	st := result.Statement
	st.Rules = append([]RuleAttestation(nil), st.Rules...)
	for i := range st.Rules {
		if st.Rules[i].RuleID == "rule-b" {
			st.Rules[i].Citations = append([]CitationAttestation(nil), st.Rules[i].Citations...)
			st.Rules[i].Citations[0].ComparedTag = "v2.0.1"
		}
	}
	raw, err := CanonicalStatement(st)
	if err != nil {
		t.Fatal(err)
	}
	opts.StatementRaw = raw
	assertVerifyRejects(t, opts, "V12: citation")
}
