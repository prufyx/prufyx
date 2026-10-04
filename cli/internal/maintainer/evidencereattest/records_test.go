// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
	"github.com/prufyx/prufyx/cli/internal/maintainer/reviewrecord"
)

// Line attestations and path-policy records renew like rules: these tests
// build packs that carry them and run prepare, sign and verify over them.

const recordComponent = "pkg:github/kubernetes/kubernetes"

var (
	reviewedAttestationID   = evidencerepin.LineAttestationRecordID(recordComponent, lineattest.FamilyKubernetesRemovedServedGVK, "1.30")
	mechanicalAttestationID = evidencerepin.LineAttestationRecordID(recordComponent, lineattest.FamilyKubernetesRemovedServedGVK, "1.31")
	reviewedPolicyID        = evidencerepin.PathPolicyRecordID(recordComponent)
)

// recordDatesSpec is one record's evidence dates.
type recordDatesSpec struct{ reviewedAt, validUntil string }

// dueAt is a record lease that is due for renewal at at: reviewed 30 days
// ago, ending in 7 days (as freshSpec).
func dueAt(at time.Time) recordDatesSpec {
	return recordDatesSpec{rfc3339(at.Add(-30 * 24 * time.Hour)), rfc3339(at.Add(7 * 24 * time.Hour))}
}

type recordPackSpec struct {
	at                    time.Time
	attestation, policy   recordDatesSpec
	mechanical            *recordDatesSpec // a mechanical 1.31 attestation, when set
	noAttestation, noPath bool
	ruleDue               bool // rule-a is due (otherwise its lease runs another 60 days)
	pad                   int  // past rules added (see padPackWithPastRules); they are not cited, so never renewed
}

func recordSourceMap(id, repo, commit string, start, end int) map[string]any {
	return testSource(id, "kubernetes", repo, commit, "api/openapi-spec/swagger.json", "sha256:"+strings.Repeat("cd", 32), start, end)
}

// buildRecordPack renders a pack with rule-a, spec.pad spread rules, and the
// records spec asks for.
func buildRecordPack(t *testing.T, spec recordPackSpec) []byte {
	t.Helper()
	ruleUntil := spec.at.Add(60 * 24 * time.Hour)
	if spec.ruleDue {
		ruleUntil = spec.at.Add(7 * 24 * time.Hour)
	}
	rule := testRule("rule-a", "active", rfc3339(spec.at.Add(-30*24*time.Hour)), rfc3339(ruleUntil), false,
		testSource("rule-a-src", "owner", "repo-rule-a", strings.Repeat("a", 40), "VERSION", "sha256:"+strings.Repeat("cd", 32), 1, 1))
	raw := padPackWithPastRules(t, testPack(t, testEntry("proj-a", rule)), spec.pad)
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var attestations []any
	if !spec.noAttestation {
		attestations = append(attestations, map[string]any{
			"component": recordComponent, "line": "1.30", "factFamily": lineattest.FamilyKubernetesRemovedServedGVK,
			"completeness": lineattest.Completeness, "ruleIds": []string{},
			"evidence": map[string]any{
				"basis": "reviewed", "reviewedAt": spec.attestation.reviewedAt, "validUntil": spec.attestation.validUntil,
				"sources": []any{recordSourceMap("k8s-openapi-1-29", "kubernetes", strings.Repeat("b", 40), 1, 90000), recordSourceMap("k8s-openapi-1-30", "kubernetes", strings.Repeat("c", 40), 1, 91000)},
			},
		})
	}
	if spec.mechanical != nil {
		attestations = append(attestations, map[string]any{
			"component": recordComponent, "line": "1.31", "factFamily": lineattest.FamilyKubernetesRemovedServedGVK,
			"completeness": lineattest.Completeness, "ruleIds": []string{},
			"evidence": map[string]any{
				"basis":     "mechanical",
				"extractor": map[string]any{"id": "k8s.served-api-removal", "version": "1.1.0", "codeDigest": "sha256:" + strings.Repeat("ab", 32)},
				"derivedAt": spec.mechanical.reviewedAt, "reviewedAt": spec.mechanical.reviewedAt, "validUntil": spec.mechanical.validUntil,
				"sources": []any{recordSourceMap("k8s-openapi-1-31", "kubernetes", strings.Repeat("d", 40), 1, 92000)},
			},
		})
	}
	if len(attestations) > 0 {
		doc["lineAttestations"] = attestations
	}
	if !spec.noPath {
		doc["pathPolicies"] = []any{map[string]any{
			"component": recordComponent, "policy": "sequential_minor",
			"evidence": map[string]any{
				"state": "active", "reviewedAt": spec.policy.reviewedAt, "validUntil": spec.policy.validUntil,
				"sources": []any{testSource("skew-policy", "kubernetes", "website", strings.Repeat("e", 40), "content/en/releases/version-skew-policy.md", "sha256:"+strings.Repeat("cd", 32), 189, 193)},
			},
		}}
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// worklistFromPack is a fresh worklist over every citation evidence repin
// finds in packRaw except the padding rules' (rules and records, through evidencerepin.LoadCitations,
// so the record IDs are the ones repin produces), each classified
// FILE_IDENTICAL against its own pinned commit. mutate may edit it.
func worklistFromPack(t *testing.T, packRaw []byte, at time.Time, mutate func(*evidencerepin.Worklist)) []byte {
	t.Helper()
	citations, err := evidencerepin.LoadCitations(chainPackPath, packRaw)
	if err != nil {
		t.Fatal(err)
	}
	wl := evidencerepin.Worklist{
		Schema: evidencerepin.Schema, Authority: evidencerepin.Authority, GeneratedAt: rfc3339(at),
		Scope: evidencerepin.WorklistScope{RulePacks: []string{chainPackPath}},
	}
	repos := map[string]bool{}
	for _, c := range citations {
		if strings.HasPrefix(c.RuleID, "past-") {
			continue
		}
		wl.Citations = append(wl.Citations, evidencerepin.ClassResult{
			RulePack: c.RulePack, RuleID: c.RuleID, Project: c.Project, SourceID: c.SourceID,
			Owner: c.Owner, Repo: c.Repo, Path: c.Path, OldCommit: c.OldCommit, NewCommit: c.OldCommit,
			Class: evidencerepin.ClassFileIdentical,
		})
		if !repos[c.Owner+"/"+c.Repo] {
			repos[c.Owner+"/"+c.Repo] = true
			wl.Repos = append(wl.Repos, evidencerepin.RepoResolution{
				Owner: c.Owner, Repo: c.Repo, Status: "RESOLVED", CurrentTag: "v1.2.3", CurrentCommit: c.OldCommit, ResolvedAt: rfc3339(at.Add(-time.Hour)),
			})
		}
	}
	wl.Summary = evidencerepin.Summary{TotalCitations: len(wl.Citations), Classified: len(wl.Citations)}
	if mutate != nil {
		mutate(&wl)
	}
	return marshalWorklist(t, wl)
}

// itemReviewRecord is testReviewRecord for any renewable item: a rule, or a
// record under its record ID, project and record digest.
func itemReviewRecord(t *testing.T, packRaw []byte, id string, decidedAt time.Time) []byte {
	t.Helper()
	doc, err := loadPack(packRaw)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range doc.records {
		if record.ID != id {
			continue
		}
		digest, _, _, err := ruleDigestAndEvidence(record.Raw)
		if err != nil {
			t.Fatal(err)
		}
		return reviewRecordFor(t, record.Project, id, digest, decidedAt)
	}
	return testReviewRecord(t, packRaw, id, decidedAt, "Sample Reviewer")
}

func reviewRecordFor(t *testing.T, project, id, digest string, decidedAt time.Time) []byte {
	t.Helper()
	other := "sha256:" + strings.Repeat("d", 64)
	raw, err := json.Marshal(map[string]any{
		"schema": reviewrecord.RecordSchema,
		"decision": map[string]any{
			"authority": "DECLARED_MAINTAINER_DECISION_NOT_AUTHENTICATED", "state": "ACCEPTED_FOR_SIGNING_REVIEW",
			"maintainer": "Sample Reviewer", "decidedAt": rfc3339(decidedAt), "scope": "ONE_RULE_CONSISTENCY_ONLY",
		},
		"subject": map[string]any{"project": project, "ruleId": id, "knowledgeRevision": "1", "evaluationAt": rfc3339(decidedAt)},
		"bindings": map[string]any{
			"packetDigest": other, "packetReceiptDigest": other, "sourceReceiptDigest": other, "sourceCorpusManifestDigest": other,
			"sourceCorpusReceiptDigest": other, "vectorFileDigest": other, "selectedVectorGroupDigest": other, "targetDigest": other,
			"engineCapabilityDigest": other, "ruleDigest": digest, "ruleEvidenceDigest": other,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}

// prepareRecordCycle prepares a human batch over prior against f's chain,
// then again with a review record for every sampled item.
func prepareRecordCycle(t *testing.T, f *chainFixture, prior []byte, at time.Time, revision string, extra map[string][]byte) cycle {
	t.Helper()
	worklistRaw := worklistFromPack(t, prior, at, nil)
	reviews := map[string][]byte{}
	for id, raw := range extra {
		reviews[id] = raw
	}
	opts := PrepareOptions{
		WorklistRaw: worklistRaw, PackName: PackCNCF, PackPath: chainPackPath, PackRaw: prior, Chain: f.chain(),
		Wave: 1, AttestedAt: at, Now: at, NextRevision: revision, EngineCapabilityDigest: testEngineCapabilityDigest, ReviewRecords: reviews,
	}
	first, err := Prepare(opts)
	if err != nil {
		t.Fatalf("Prepare %s: %v", revision, err)
	}
	for _, sample := range first.Statement.SampledForFullReview {
		if sample.ReviewRecordDigest == "" {
			reviews[sample.RuleID] = itemReviewRecord(t, prior, sample.RuleID, at.Add(-time.Hour))
		}
	}
	res, err := Prepare(opts)
	if err != nil {
		t.Fatalf("Prepare %s: %v", revision, err)
	}
	return cycle{res: res, worklistRaw: worklistRaw, prior: prior, at: at, reviews: reviews}
}

func statementLists(c cycle, id string) bool {
	for _, ra := range c.res.Statement.Rules {
		if ra.RuleID == id {
			return true
		}
	}
	return false
}

func recordByID(t *testing.T, packRaw []byte, id string) evidencerepin.PackRecord {
	t.Helper()
	doc, err := loadPack(packRaw)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range doc.records {
		if record.ID == id {
			return record
		}
	}
	t.Fatalf("record %s not in pack", id)
	return evidencerepin.PackRecord{}
}

// standardRecordPack: a reviewed 1.30 attestation and a reviewed path policy,
// both due, rule-a due, in a pack large enough that the stagger cap holds
// all three.
func standardRecordPack(t *testing.T, at time.Time) []byte {
	t.Helper()
	return buildRecordPack(t, recordPackSpec{at: at, attestation: dueAt(at), policy: dueAt(at), ruleDue: true, pad: 30})
}

// Acceptance: one reviewed attestation and one reviewed path policy are
// prepared, signed with a test key and verified against the chain, and the
// next pack differs from the prior one only in their validity windows (and
// the renewed rule's and the revision).
func TestRecordsRenewThroughPrepareSignVerify(t *testing.T) {
	f := newChainFixture(t)
	prior := standardRecordPack(t, baseNow)
	c := prepareRecordCycle(t, f, prior, baseNow, "rev-2", nil)
	for _, id := range []string{"rule-a", reviewedAttestationID, reviewedPolicyID} {
		if !statementLists(c, id) {
			t.Fatalf("%s not renewed; notExtended=%+v", id, c.res.Statement.NotExtended)
		}
	}
	for _, ra := range c.res.Statement.Rules {
		switch ra.RuleID {
		case reviewedAttestationID:
			if ra.Project != evidencerepin.RecordProjectLineAttestations || len(ra.Citations) != 2 || ra.ConsecutiveBatchCycles != 1 {
				t.Fatalf("attestation entry: %+v", ra)
			}
		case reviewedPolicyID:
			if ra.Project != evidencerepin.RecordProjectPathPolicies || len(ra.Citations) != 1 {
				t.Fatalf("policy entry: %+v", ra)
			}
		}
	}
	if !strings.Contains(string(c.res.Summary), reviewedAttestationID+": line attestation "+recordComponent) {
		t.Fatalf("summary does not list the records:\n%s", c.res.Summary)
	}

	// Structural check before signing, then sign, append and verify strictly.
	if err := verifyCycle(c, f.chain()); err != nil {
		t.Fatalf("pre-sign verify: %v", err)
	}
	f.append("0001", c.res.StatementCanonical)
	if err := verifyCycle(c, f.chain()); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if _, err := VerifySignature(VerifySignatureOptions{
		Statement: c.res.StatementCanonical, Envelope: f.entries[0].Envelope, TrustRoot: f.root,
		ExpectedTrustRootDigest: f.digest, Now: baseNow.Add(time.Hour),
	}); err != nil {
		t.Fatalf("signature: %v", err)
	}

	// The renewed records carry exactly the statement's dates.
	for _, id := range []string{reviewedAttestationID, reviewedPolicyID} {
		next := recordByID(t, c.res.NextPack, id)
		if next.ReviewedAt != c.res.Statement.AttestedAt || next.ValidUntil != c.res.Statement.ValidUntil {
			t.Fatalf("%s renewed to %s..%s, statement says %s..%s", id, next.ReviewedAt, next.ValidUntil, c.res.Statement.AttestedAt, c.res.Statement.ValidUntil)
		}
	}

	// Line by line, the next pack differs from the prior pack (rendered the
	// same way) only in the revision and in reviewedAt/validUntil values.
	priorDoc, err := loadPack(prior)
	if err != nil {
		t.Fatal(err)
	}
	priorDoc.Revision = "rev-2"
	rendered, err := buildNextPack(priorDoc)
	if err != nil {
		t.Fatal(err)
	}
	before, after := strings.Split(string(rendered), "\n"), strings.Split(string(c.res.NextPack), "\n")
	if len(before) != len(after) {
		t.Fatalf("line count changed: %d -> %d", len(before), len(after))
	}
	changed := 0
	for i := range before {
		if before[i] == after[i] {
			continue
		}
		changed++
		trimmed := strings.TrimSpace(after[i])
		if !strings.HasPrefix(trimmed, `"reviewedAt": "`) && !strings.HasPrefix(trimmed, `"validUntil": "`) {
			t.Fatalf("line %d changed outside a validity field:\n- %s\n+ %s", i+1, before[i], after[i])
		}
	}
	if changed != 6 { // rule-a, the attestation and the policy: two fields each
		t.Fatalf("expected 6 changed lines, got %d", changed)
	}
}

// Acceptance: any change to the record sections other than the renewal the
// statement makes fails verify. Every tamper but the two formatting-only
// ones is also caught by a check independent of the byte-for-byte
// recomputation (V1): the next pack's strict load, V6 or V10.
func TestVerifyRejectsTamperedRecordSections(t *testing.T) {
	f := newChainFixture(t)
	c := prepareRecordCycle(t, f, standardRecordPack(t, baseNow), baseNow, "rev-2", nil)
	f.append("0001", c.res.StatementCanonical)
	if err := verifyCycle(c, f.chain()); err != nil {
		t.Fatalf("untampered: %v", err)
	}
	attestation := func(doc map[string]any) map[string]any {
		return doc["lineAttestations"].([]any)[0].(map[string]any)
	}
	policy := func(doc map[string]any) map[string]any { return doc["pathPolicies"].([]any)[0].(map[string]any) }
	evidence := func(record map[string]any) map[string]any { return record["evidence"].(map[string]any) }
	firstSource := func(record map[string]any) map[string]any {
		return evidence(record)["sources"].([]any)[0].(map[string]any)
	}
	for _, tamper := range []struct {
		name   string
		edit   func(doc map[string]any)
		raw    func(next []byte) []byte
		v1Only bool
	}{
		{name: "attestation lists another rule", edit: func(d map[string]any) { attestation(d)["ruleIds"] = []any{"rule-a"} }},
		{name: "attestation moved to another line", edit: func(d map[string]any) { attestation(d)["line"] = "1.29" }},
		{name: "attestation completeness", edit: func(d map[string]any) { attestation(d)["completeness"] = "PARTIAL" }},
		{name: "attestation basis made mechanical", edit: func(d map[string]any) {
			e := evidence(attestation(d))
			e["basis"] = "mechanical"
			e["extractor"] = map[string]any{"id": "k8s.served-api-removal", "version": "1.1.0", "codeDigest": "sha256:" + strings.Repeat("ab", 32)}
			e["derivedAt"] = e["reviewedAt"]
		}},
		{name: "attestation source digest", edit: func(d map[string]any) {
			firstSource(attestation(d))["contentDigest"] = "sha256:" + strings.Repeat("ef", 32)
		}},
		{name: "attestation source span", edit: func(d map[string]any) { firstSource(attestation(d))["endLine"] = 89999 }},
		{name: "attestation source dropped", edit: func(d map[string]any) {
			e := evidence(attestation(d))
			e["sources"] = e["sources"].([]any)[1:]
		}},
		{name: "attestation lease extended past the statement", edit: func(d map[string]any) {
			until := mustParse(evidence(attestation(d))["validUntil"].(string))
			evidence(attestation(d))["validUntil"] = rfc3339(until.Add(24 * time.Hour))
		}},
		{name: "attestation reviewedAt backdated", edit: func(d map[string]any) {
			evidence(attestation(d))["reviewedAt"] = rfc3339(baseNow.Add(-24 * time.Hour))
		}},
		{name: "policy changed to direct", edit: func(d map[string]any) { policy(d)["policy"] = "direct" }},
		{name: "policy withdrawn", edit: func(d map[string]any) { evidence(policy(d))["state"] = "withdrawn" }},
		{name: "policy for another component", edit: func(d map[string]any) { policy(d)["component"] = "pkg:github/etcd-io/etcd" }},
		{name: "policy gains a basis", edit: func(d map[string]any) { evidence(policy(d))["basis"] = "reviewed" }},
		{name: "policy section removed", edit: func(d map[string]any) { delete(d, "pathPolicies") }},
		{name: "attestation section removed", edit: func(d map[string]any) { delete(d, "lineAttestations") }},
		{name: "second policy added", edit: func(d map[string]any) {
			extra := map[string]any{}
			raw, _ := json.Marshal(policy(d))
			_ = json.Unmarshal(raw, &extra)
			extra["component"] = "pkg:github/kubernetes/a-kubernetes"
			d["pathPolicies"] = []any{extra, policy(d)}
		}},
		{name: "attestation member renamed", raw: func(next []byte) []byte {
			return bytes.Replace(next, []byte(`"lineAttestations":`), []byte(`"LineAttestations":`), 1)
		}},
		{name: "member order inside a record", v1Only: true, raw: func(next []byte) []byte {
			lines := strings.Split(string(next), "\n")
			for i := 0; i+1 < len(lines); i++ {
				if strings.TrimSpace(lines[i]) == `"endLine": 193,` && strings.TrimSpace(lines[i+1]) == `"id": "skew-policy",` {
					lines[i], lines[i+1] = lines[i+1], lines[i]
					break
				}
			}
			return []byte(strings.Join(lines, "\n"))
		}},
		{name: "whitespace inside a section", v1Only: true, raw: func(next []byte) []byte {
			return bytes.Replace(next, []byte(`"completeness": `), []byte(`"completeness":  `), 1)
		}},
	} {
		t.Run(tamper.name, func(t *testing.T) {
			next := c.res.NextPack
			if tamper.edit != nil {
				var doc map[string]any
				if err := json.Unmarshal(next, &doc); err != nil {
					t.Fatal(err)
				}
				tamper.edit(doc)
				raw, err := json.MarshalIndent(doc, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				next = append(raw, '\n')
			} else {
				next = tamper.raw(next)
			}
			if bytes.Equal(next, c.res.NextPack) {
				t.Fatal("tamper did not apply")
			}
			tampered := c
			tampered.res.NextPack = next
			err := verifyCycle(tampered, f.chain())
			if err == nil {
				t.Fatal("verify accepted the tampered next pack")
			}
			independent := independentRecordFinding(t, c, next)
			if tamper.v1Only != (independent == nil) {
				t.Fatalf("independent finding %v (v1Only=%v); verify: %v", independent, tamper.v1Only, err)
			}
		})
	}
}

// independentRecordFinding runs the checks that do not rely on recomputing
// the next pack: its strict load, V6 and V10.
func independentRecordFinding(t *testing.T, c cycle, next []byte) error {
	t.Helper()
	priorDoc, err := loadPack(c.prior)
	if err != nil {
		t.Fatal(err)
	}
	nextDoc, err := loadPack(next)
	if err != nil {
		return err
	}
	if err := checkV10(priorDoc, nextDoc); err != nil {
		return err
	}
	priorByID, err := rulesByID(priorDoc)
	if err != nil {
		t.Fatal(err)
	}
	nextByID, err := rulesByID(nextDoc)
	if err != nil {
		return err
	}
	return checkV6(priorByID, nextByID, c.res.Statement, nil, true)
}

// Acceptance: a mechanical attestation is never renewed: prepare leaves it
// out (MECHANICAL_RECORD_EXCLUDED) with its bytes untouched, and a statement
// or next pack that alters it is refused.
func TestMechanicalAttestationIsNeverRenewed(t *testing.T) {
	f := newChainFixture(t)
	mechanical := dueAt(baseNow)
	prior := buildRecordPack(t, recordPackSpec{at: baseNow, attestation: dueAt(baseNow), policy: dueAt(baseNow), mechanical: &mechanical, ruleDue: true, pad: 30})
	c := prepareRecordCycle(t, f, prior, baseNow, "rev-2", nil)
	if statementLists(c, mechanicalAttestationID) || worstClassOf(c, mechanicalAttestationID) != reasonMechanicalRecord {
		t.Fatalf("mechanical attestation: listed=%v notExtended=%+v", statementLists(c, mechanicalAttestationID), c.res.Statement.NotExtended)
	}
	if !statementLists(c, reviewedAttestationID) {
		t.Fatal("the reviewed attestation beside it was not renewed")
	}
	if compact(t, recordByID(t, prior, mechanicalAttestationID).Raw) != compact(t, recordByID(t, c.res.NextPack, mechanicalAttestationID).Raw) {
		t.Fatal("the mechanical attestation's bytes changed")
	}
	f.append("0001", c.res.StatementCanonical)
	if err := verifyCycle(c, f.chain()); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// A next pack that renews the mechanical attestation alongside: moving
	// only its two validity dates makes it invalid (a mechanical record's
	// reviewedAt is its derivedAt); moving derivedAt too is refused by V6
	// and V10.
	doc, err := loadPack(c.res.NextPack)
	if err != nil {
		t.Fatal(err)
	}
	alter := func(derived bool) []byte {
		var atts []map[string]any
		if err := json.Unmarshal(doc.LineAttestations, &atts); err != nil {
			t.Fatal(err)
		}
		e := atts[1]["evidence"].(map[string]any)
		e["reviewedAt"], e["validUntil"] = c.res.Statement.AttestedAt, c.res.Statement.ValidUntil
		if derived {
			e["derivedAt"] = c.res.Statement.AttestedAt
		}
		altered := doc
		altered.LineAttestations, _ = json.Marshal(atts)
		raw, err := buildNextPack(altered)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if _, err := loadPack(alter(false)); !errors.Is(err, ErrRejected) {
		t.Fatalf("a mechanical attestation with moved dates only loaded: %v", err)
	}
	for _, derived := range []bool{false, true} {
		tampered := c
		tampered.res.NextPack = alter(derived)
		if err := verifyCycle(tampered, f.chain()); err == nil {
			t.Fatalf("verify accepted a next pack renewing a mechanical attestation (derivedAt moved: %v)", derived)
		}
	}
	alteredDoc, err := loadPack(alter(true))
	if err != nil {
		t.Fatal(err)
	}
	if err := checkV10(doc, alteredDoc); err == nil || !strings.Contains(err.Error(), "V10:") {
		t.Fatalf("V10 on a re-derived mechanical attestation: %v", err)
	}
	priorByID, _ := rulesByID(doc)
	nextByID, _ := rulesByID(alteredDoc)
	statement := c.res.Statement
	statement.Rules = append(append([]RuleAttestation(nil), statement.Rules...), RuleAttestation{RuleID: mechanicalAttestationID})
	if err := checkV6(priorByID, nextByID, statement, map[string]string{mechanicalAttestationID: "sha256:" + strings.Repeat("ee", 32)}, true); err == nil || !strings.Contains(err.Error(), "mechanical") {
		t.Fatalf("V6 on a mechanical attestation's dates: %v", err)
	}

	// A statement listing the mechanical attestation is refused by V8.
	candidates, _, err := packCandidates(doc)
	if err != nil {
		t.Fatal(err)
	}
	listed := c.res.Statement
	ra := listed.Rules[0]
	ra.RuleID = mechanicalAttestationID
	listed.Rules = []RuleAttestation{ra}
	if err := checkRolePolicy(listed, candidatesByID(candidates)); err == nil || !strings.Contains(err.Error(), "V8:") {
		t.Fatalf("V8 on a statement renewing a mechanical attestation: %v", err)
	}
}

// A mechanical attestation re-derived after the chain head moves its
// reviewedAt outside any statement; that is not a sign of a truncated chain
// and does not stop the next human batch. A reviewed record whose dates
// moved outside the chain does, exactly as a rule's.
func TestRecordDatesMovedOutsideTheChain(t *testing.T) {
	f := newChainFixture(t)
	mechanical := dueAt(baseNow)
	prior := buildRecordPack(t, recordPackSpec{at: baseNow, attestation: dueAt(baseNow), policy: dueAt(baseNow), mechanical: &mechanical, ruleDue: true, pad: 30})
	c := prepareRecordCycle(t, f, prior, baseNow, "rev-2", nil)
	f.append("0001", c.res.StatementCanonical)

	next := baseNow.Add(cycleSpacing)
	doc, err := loadPack(c.res.NextPack)
	if err != nil {
		t.Fatal(err)
	}
	rederivedAt := next.Add(-24 * time.Hour)
	rederived := setMechanicalDates(t, doc, rederivedAt)
	if _, err := Prepare(PrepareOptions{
		WorklistRaw: worklistFromPack(t, rederived, next, nil), PackName: PackCNCF, PackPath: chainPackPath, PackRaw: rederived, Chain: f.chain(),
		Wave: 1, AttestedAt: next, Now: next, NextRevision: "rev-3", EngineCapabilityDigest: testEngineCapabilityDigest,
	}); err != nil && !strings.Contains(err.Error(), "sample") {
		t.Fatalf("a re-derived mechanical attestation stopped the next batch: %v", err)
	}

	// The reviewed attestation's dates moved outside the chain.
	moved, _, err := renewRecords(doc, map[string]recordDates{reviewedAttestationID: {rfc3339(rederivedAt), rfc3339(rederivedAt.Add(80 * 24 * time.Hour))}})
	if err != nil {
		t.Fatal(err)
	}
	movedRaw, err := buildNextPack(moved)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Prepare(PrepareOptions{
		WorklistRaw: worklistFromPack(t, movedRaw, next, nil), PackName: PackCNCF, PackPath: chainPackPath, PackRaw: movedRaw, Chain: f.chain(),
		Wave: 1, AttestedAt: next, Now: next, NextRevision: "rev-3", EngineCapabilityDigest: testEngineCapabilityDigest,
	})
	if err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("a reviewed attestation renewed outside the chain was accepted: %v", err)
	}
	// With a review record for it, the batch proceeds.
	if _, err := Prepare(PrepareOptions{
		WorklistRaw: worklistFromPack(t, movedRaw, next, nil), PackName: PackCNCF, PackPath: chainPackPath, PackRaw: movedRaw, Chain: f.chain(),
		Wave: 1, AttestedAt: next, Now: next, NextRevision: "rev-3", EngineCapabilityDigest: testEngineCapabilityDigest,
		ReviewRecords: map[string][]byte{reviewedAttestationID: itemReviewRecord(t, movedRaw, reviewedAttestationID, rederivedAt)},
	}); err != nil {
		t.Fatalf("with a review record: %v", err)
	}
}

// setMechanicalDates re-derives the mechanical 1.31 attestation at at.
func setMechanicalDates(t *testing.T, doc packDocument, at time.Time) []byte {
	t.Helper()
	var atts []map[string]any
	if err := json.Unmarshal(doc.LineAttestations, &atts); err != nil {
		t.Fatal(err)
	}
	for _, a := range atts {
		if a["line"] == "1.31" {
			e := a["evidence"].(map[string]any)
			e["derivedAt"], e["reviewedAt"], e["validUntil"] = rfc3339(at), rfc3339(at), rfc3339(at.Add(90*24*time.Hour))
		}
	}
	raw, err := json.Marshal(atts)
	if err != nil {
		t.Fatal(err)
	}
	doc.LineAttestations = raw
	out, err := buildNextPack(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Acceptance: NOT_YET_DUE and NOT_LATER_THAN_CURRENT apply to records.
func TestRecordsThatAreNotDueAreNotRenewed(t *testing.T) {
	f := newChainFixture(t)
	notDue := recordDatesSpec{rfc3339(baseNow.Add(-10 * 24 * time.Hour)), rfc3339(baseNow.Add(30 * 24 * time.Hour))}
	notLater := recordDatesSpec{rfc3339(baseNow.Add(-10 * 24 * time.Hour)), rfc3339(baseNow.Add(60 * 24 * time.Hour))}
	prior := buildRecordPack(t, recordPackSpec{at: baseNow, attestation: notDue, policy: notLater, ruleDue: true, pad: 30})
	c := prepareRecordCycle(t, f, prior, baseNow, "rev-2", nil)
	slot, _ := SlotDate(1, baseNow)
	if !slot.After(baseNow.Add(30*24*time.Hour)) || slot.After(baseNow.Add(60*24*time.Hour)) {
		t.Fatalf("slot %s does not separate the two leases", rfc3339(slot))
	}
	if got := worstClassOf(c, reviewedAttestationID); got != reasonNotYetDue {
		t.Fatalf("attestation: %s", got)
	}
	if got := worstClassOf(c, reviewedPolicyID); got != reasonNotLaterThanCurrent {
		t.Fatalf("policy: %s", got)
	}
}

// Acceptance: the stagger cap counts records and defers them like rules, in
// prepare and in V7.
func TestStaggerCapAppliesToRecords(t *testing.T) {
	f := newChainFixture(t)
	// rule-a (not due), the attestation and the policy: three items, a cap
	// of one per week.
	prior := buildRecordPack(t, recordPackSpec{at: baseNow, attestation: dueAt(baseNow), policy: dueAt(baseNow)})
	c := prepareRecordCycle(t, f, prior, baseNow, "rev-2", nil)
	if len(c.res.Statement.Rules) != 1 {
		t.Fatalf("expected one renewal under a cap of one, got %+v", c.res.Statement.Rules)
	}
	renewed := c.res.Statement.Rules[0].RuleID
	other := reviewedPolicyID
	if renewed == reviewedPolicyID {
		other = reviewedAttestationID
	}
	if worstClassOf(c, other) != reasonStaggerDeferred || statementLists(c, "rule-a") {
		t.Fatalf("notExtended: %+v", c.res.Statement.NotExtended)
	}
	if err := verifyCycle(c, f.chain()); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// V7 counts records: renewing both into the slot week exceeds the cap.
	doc, err := loadPack(prior)
	if err != nil {
		t.Fatal(err)
	}
	both, _, err := renewRecords(doc, map[string]recordDates{
		reviewedAttestationID: {c.res.Statement.AttestedAt, c.res.Statement.ValidUntil},
		reviewedPolicyID:      {c.res.Statement.AttestedAt, c.res.Statement.ValidUntil},
	})
	if err != nil {
		t.Fatal(err)
	}
	nextByID, err := rulesByID(both)
	if err != nil {
		t.Fatal(err)
	}
	statement := c.res.Statement
	statement.Rules = []RuleAttestation{{RuleID: reviewedAttestationID}, {RuleID: reviewedPolicyID}}
	if err := checkV7(statement, nextByID); err == nil || !strings.Contains(err.Error(), "V7:") {
		t.Fatalf("V7 with two records in a week capped at one: %v", err)
	}
}

// Records follow the consecutive-cycle cap, and a review record for the
// record (the seeded sample's) resets it, exactly as for a rule.
func TestRecordsFollowTheConsecutiveCycleCap(t *testing.T) {
	f := newChainFixture(t)
	pack := standardRecordPack(t, baseNow)
	at := baseNow
	cycles := map[string]int{}
	capped := 0
	for round := 1; round <= 5; round++ {
		c := prepareRecordCycle(t, f, pack, at, fmt.Sprintf("rev-%d", round+1), nil)
		for _, id := range []string{"rule-a", reviewedAttestationID, reviewedPolicyID} {
			want := cycles[id] + 1
			if sampledOrReviewed(c, id) {
				want = 1
			}
			switch {
			case statementLists(c, id):
				if got := cyclesOf(c, id); got != want || got > maxConsecutiveBatchCycles {
					t.Fatalf("round %d: %s cycles %d, want %d", round, id, got, want)
				}
				cycles[id] = want
			case want > maxConsecutiveBatchCycles:
				if got := worstClassOf(c, id); got != reasonConsecutiveCycleCap {
					t.Fatalf("round %d: %s over the cap: %s", round, id, got)
				}
				capped++
			default:
				t.Fatalf("round %d: %s not renewed: %s", round, id, worstClassOf(c, id))
			}
		}
		if err := verifyCycle(c, f.chain()); err != nil {
			t.Fatalf("round %d pre-sign: %v", round, err)
		}
		f.append(fmt.Sprintf("%04d", round), c.res.StatementCanonical)
		if err := verifyCycle(c, f.chain()); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		pack = c.res.NextPack
		at = at.Add(cycleSpacing)
	}
	if capped == 0 {
		t.Fatal("no item reached the cap in five rounds; the test does not exercise it")
	}
}

func sampledOrReviewed(c cycle, id string) bool {
	for _, r := range c.res.Statement.IndividualReviews {
		if r.RuleID == id {
			return true
		}
	}
	return false
}

// A review record for a record must name its record ID and project and
// bind its exact bytes.
func TestRecordReviewRecordsAreBoundToTheRecord(t *testing.T) {
	prior := standardRecordPack(t, baseNow)
	record := recordByID(t, prior, reviewedAttestationID)
	digest, _, _, err := ruleDigestAndEvidence(record.Raw)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"wrong project":    reviewRecordFor(t, "kubernetes", reviewedAttestationID, digest, baseNow.Add(-time.Hour)),
		"wrong digest":     reviewRecordFor(t, evidencerepin.RecordProjectLineAttestations, reviewedAttestationID, "sha256:"+strings.Repeat("0", 64), baseNow.Add(-time.Hour)),
		"decided too late": reviewRecordFor(t, evidencerepin.RecordProjectLineAttestations, reviewedAttestationID, digest, baseNow.Add(time.Hour)),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Prepare(PrepareOptions{
				WorklistRaw: worklistFromPack(t, prior, baseNow, nil), PackName: PackCNCF, PackPath: chainPackPath, PackRaw: prior, Chain: &Chain{},
				Wave: 1, AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest,
				ReviewRecords: map[string][]byte{reviewedAttestationID: raw},
			})
			if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "V5:") {
				t.Fatalf("expected a V5 rejection, got %v", err)
			}
		})
	}
}

// Records renew in automated mode too, each into its own scheduled week,
// signed by the automation key; V9 compares their citations with an
// independent worklist.
func TestRecordsRenewInAutomatedMode(t *testing.T) {
	f := newRoleFixture(t)
	prior := standardRecordPack(t, baseNow)
	worklist := func(mutate func(*evidencerepin.Worklist)) []byte {
		return worklistFromPack(t, prior, baseNow, func(wl *evidencerepin.Worklist) {
			lineBaselined(wl)
			if mutate != nil {
				mutate(wl)
			}
		})
	}
	c := prepareAutomatedWith(t, f.chainFixture, prior, baseNow, worklist(nil), "rev-2", nil)
	for _, id := range []string{reviewedAttestationID, reviewedPolicyID} {
		if !statementLists(c, id) {
			t.Fatalf("%s not renewed: %+v", id, c.res.Statement.NotExtended)
		}
		next := recordByID(t, c.res.NextPack, id)
		for _, ra := range c.res.Statement.Rules {
			if ra.RuleID == id && (ra.ValidUntil == "" || next.ValidUntil != ra.ValidUntil || next.ReviewedAt != c.res.Statement.AttestedAt) {
				t.Fatalf("%s: statement %+v, next pack %s..%s", id, ra, next.ReviewedAt, next.ValidUntil)
			}
		}
	}
	f.appendAutomated("0001", c.res.StatementCanonical)
	opts := VerifyOptions{
		StatementRaw: c.res.StatementCanonical, PriorPackRaw: c.prior, NextPackRaw: c.res.NextPack,
		WorklistRaw: c.worklistRaw, Chain: f.chain(), BaseChain: &Chain{TrustRoot: f.root, ExpectedTrustRootDigest: f.digest},
		PackName: PackCNCF, PackPath: chainPackPath, EngineCapabilityDigest: testEngineCapabilityDigest,
		AttestedAtNow: baseNow.Add(time.Hour), IndependentWorklistRaw: c.worklistRaw,
	}
	if _, err := Verify(opts); err != nil {
		t.Fatalf("verify: %v", err)
	}
	opts.IndependentWorklistRaw = worklist(func(wl *evidencerepin.Worklist) {
		for i := range wl.Citations {
			if wl.Citations[i].RuleID == reviewedPolicyID {
				wl.Citations[i].NewCommit = strings.Repeat("9", 40)
			}
		}
	})
	if _, err := Verify(opts); err == nil || !strings.Contains(err.Error(), "V9:") {
		t.Fatalf("V9 with a differing record citation: %v", err)
	}
}

// A record whose citation drifted is not renewed, like a rule.
func TestRecordWithDriftedCitationIsNotRenewed(t *testing.T) {
	prior := standardRecordPack(t, baseNow)
	worklistRaw := worklistFromPack(t, prior, baseNow, func(wl *evidencerepin.Worklist) {
		for i := range wl.Citations {
			if wl.Citations[i].RuleID == reviewedAttestationID && wl.Citations[i].SourceID == "k8s-openapi-1-30" {
				wl.Citations[i].Class = evidencerepin.ClassContentChanged
			}
		}
	})
	res, err := Prepare(PrepareOptions{
		WorklistRaw: worklistRaw, PackName: PackCNCF, PackPath: chainPackPath, PackRaw: prior, Chain: &Chain{},
		Wave: 1, AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, ne := range res.Statement.NotExtended {
		if ne.RuleID == reviewedAttestationID && ne.WorstClass == evidencerepin.ClassContentChanged {
			return
		}
	}
	t.Fatalf("drifted attestation: %+v", res.Statement.NotExtended)
}

// loadPack reads the record sections strictly and re-runs the attestation
// exact-set and line-wide checks.
func TestLoadPackChecksRecordSections(t *testing.T) {
	good := standardRecordPack(t, baseNow)
	if _, err := loadPack(good); err != nil {
		t.Fatal(err)
	}
	edit := func(mutate func(map[string]any)) []byte {
		var doc map[string]any
		if err := json.Unmarshal(good, &doc); err != nil {
			t.Fatal(err)
		}
		mutate(doc)
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	attestation := func(doc map[string]any) map[string]any { return doc["lineAttestations"].([]any)[0].(map[string]any) }
	k8sRule := func(id, from, to string) map[string]any {
		rule := testRule(id, "active", rfc3339(baseNow.Add(-24*time.Hour)), rfc3339(baseNow.Add(30*24*time.Hour)), false,
			testSource("k8s-rule-src", "kubernetes", "kubernetes", strings.Repeat("b", 40), "VERSION", "sha256:"+strings.Repeat("cd", 32), 1, 1))
		rule["subject"] = map[string]any{"component": recordComponent, "from": from, "to": to}
		rule["condition"] = map[string]any{"side": "current", "component": recordComponent, "factId": "component.kubernetes.flowcontrol_v1beta3_removed_gvk_present"}
		return rule
	}
	for name, raw := range map[string][]byte{
		"attestation lists a rule the pack lacks": edit(func(d map[string]any) { attestation(d)["ruleIds"] = []any{"rule-zz"} }),
		"pack holds an unlisted rule of the line": edit(func(d map[string]any) {
			d["entries"] = append(d["entries"].([]any), testEntry("kubernetes", k8sRule("kubernetes.x-removed.1-29-0-to-1-30-0", "1.29.0", "1.30.0")))
		}),
		"listed rule is not line-wide": edit(func(d map[string]any) {
			d["entries"] = append(d["entries"].([]any), testEntry("kubernetes", k8sRule("kubernetes.x-removed.1-29-0-to-1-30-0", "1.29.0", "1.30.0")))
			attestation(d)["ruleIds"] = []any{"kubernetes.x-removed.1-29-0-to-1-30-0"}
		}),
		"case variant of a section": edit(func(d map[string]any) { d["PathPolicies"] = d["pathPolicies"]; delete(d, "pathPolicies") }),
		"unknown member":            edit(func(d map[string]any) { d["notes"] = "x" }),
		"null section":              edit(func(d map[string]any) { d["pathPolicies"] = nil }),
		"attestation window over 90 days": edit(func(d map[string]any) {
			attestation(d)["evidence"].(map[string]any)["validUntil"] = rfc3339(baseNow.Add(80 * 24 * time.Hour))
		}),
		"rule with a record ID": edit(func(d map[string]any) {
			d["entries"].([]any)[0].(map[string]any)["rule"].(map[string]any)["id"] = reviewedPolicyID
		}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadPack(raw); !errors.Is(err, ErrRejected) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
}

// V10 directly: same sections, same records in the same order, nothing but
// the validity window changed.
func TestCheckV10(t *testing.T) {
	prior := standardRecordPack(t, baseNow)
	priorDoc, err := loadPack(prior)
	if err != nil {
		t.Fatal(err)
	}
	renewed, _, err := renewRecords(priorDoc, map[string]recordDates{reviewedPolicyID: {rfc3339(baseNow), rfc3339(baseNow.Add(40 * 24 * time.Hour))}})
	if err != nil {
		t.Fatal(err)
	}
	if err := checkV10(priorDoc, reload(t, renewed)); err != nil {
		t.Fatalf("a date-only renewal: %v", err)
	}
	if err := checkV10(priorDoc, priorDoc); err != nil {
		t.Fatalf("unchanged: %v", err)
	}
	noRecords := buildRecordPack(t, recordPackSpec{at: baseNow, noAttestation: true, noPath: true, pad: 3})
	plain, err := loadPack(noRecords)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkV10(plain, plain); err != nil {
		t.Fatalf("a pack without records: %v", err)
	}
	withPolicy := func(edit func(record map[string]any)) packDocument {
		var records []map[string]any
		if err := json.Unmarshal(priorDoc.PathPolicies, &records); err != nil {
			t.Fatal(err)
		}
		edit(records[0])
		doc := priorDoc
		doc.PathPolicies, _ = json.Marshal(records)
		return reload(t, doc)
	}
	noPolicy := priorDoc
	noPolicy.PathPolicies = nil
	noAttestation := priorDoc
	noAttestation.LineAttestations = nil
	for name, next := range map[string]packDocument{
		"policy changed": withPolicy(func(r map[string]any) { r["policy"] = "direct" }),
		"policy source changed": withPolicy(func(r map[string]any) {
			r["evidence"].(map[string]any)["sources"].([]any)[0].(map[string]any)["startLine"] = 188
		}),
		"policy component":        withPolicy(func(r map[string]any) { r["component"] = "pkg:github/etcd-io/etcd" }),
		"policy section removed":  reload(t, noPolicy),
		"attestations removed":    reload(t, noAttestation),
		"policy withdrawn":        withPolicy(func(r map[string]any) { r["evidence"].(map[string]any)["state"] = "withdrawn" }),
		"policy evidence derived": withPolicy(func(r map[string]any) { r["evidence"].(map[string]any)["basis"] = "reviewed" }),
	} {
		t.Run(name, func(t *testing.T) {
			if err := checkV10(priorDoc, next); err == nil || !strings.Contains(err.Error(), "V10:") {
				t.Fatalf("got %v", err)
			}
		})
	}
	// The same sections, one attestation fewer at the end (so no record
	// differs by position).
	mechanical := dueAt(baseNow)
	twoAttestations, err := loadPack(buildRecordPack(t, recordPackSpec{at: baseNow, attestation: dueAt(baseNow), mechanical: &mechanical, noPath: true, pad: 3}))
	if err != nil {
		t.Fatal(err)
	}
	oneAttestation, err := loadPack(buildRecordPack(t, recordPackSpec{at: baseNow, attestation: dueAt(baseNow), noPath: true, pad: 3}))
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]packDocument{{twoAttestations, oneAttestation}, {oneAttestation, twoAttestations}} {
		if err := checkV10(pair[0], pair[1]); err == nil || !strings.Contains(err.Error(), "V10:") {
			t.Fatalf("a record dropped or added within a section: %v", err)
		}
	}
	// Records reordered across sections cannot happen (sections are
	// canonically ordered); a section added where the prior had none is
	// refused.
	if err := checkV10(reload(t, noPolicy), priorDoc); err == nil {
		t.Fatal("a section added by the next pack was accepted")
	}
}

func reload(t *testing.T, doc packDocument) packDocument {
	t.Helper()
	raw, err := buildNextPack(doc)
	if err != nil {
		t.Fatal(err)
	}
	out, err := loadPack(raw)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// V6 covers records through their views: a date change the statement does
// not cover is refused.
func TestCheckV6CoversRecords(t *testing.T) {
	priorDoc, err := loadPack(standardRecordPack(t, baseNow))
	if err != nil {
		t.Fatal(err)
	}
	renewed, _, err := renewRecords(priorDoc, map[string]recordDates{reviewedAttestationID: {rfc3339(baseNow), rfc3339(baseNow.Add(40 * 24 * time.Hour))}})
	if err != nil {
		t.Fatal(err)
	}
	priorByID, err := rulesByID(priorDoc)
	if err != nil {
		t.Fatal(err)
	}
	nextByID, err := rulesByID(reload(t, renewed))
	if err != nil {
		t.Fatal(err)
	}
	if err := checkV6(priorByID, nextByID, Statement{}, nil, true); err == nil || !strings.Contains(err.Error(), reviewedAttestationID) {
		t.Fatalf("uncovered record date change: %v", err)
	}
	covering := Statement{AttestedAt: rfc3339(baseNow), ValidUntil: rfc3339(baseNow.Add(40 * 24 * time.Hour)), Rules: []RuleAttestation{{RuleID: reviewedAttestationID}}}
	if err := checkV6(priorByID, nextByID, covering, nil, true); err != nil {
		t.Fatalf("covered: %v", err)
	}
	covering.ValidUntil = rfc3339(baseNow.Add(41 * 24 * time.Hour))
	if err := checkV6(priorByID, nextByID, covering, nil, true); err == nil {
		t.Fatal("dates other than the statement's were accepted")
	}
}

// setRecordDates changes the two values in place and nothing else.
func TestSetRecordDatesChangesOnlyTheTwoValues(t *testing.T) {
	raw := json.RawMessage(`{"component":"x","evidence": {"validUntil" :"2026-01-02T00:00:00Z","note":"reviewedAt","reviewedAt":"2026-01-01T00:00:00Z","sources":[{"reviewedAt":"keep"}]},"z":1}`)
	out, err := setRecordDates(raw, "2026-02-01T00:00:00Z", "2026-03-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	want := `{"component":"x","evidence": {"validUntil" :"2026-03-01T00:00:00Z","note":"reviewedAt","reviewedAt":"2026-02-01T00:00:00Z","sources":[{"reviewedAt":"keep"}]},"z":1}`
	if string(out) != want {
		t.Fatalf("got  %s\nwant %s", out, want)
	}
	for name, bad := range map[string]string{
		"repeated member":    `{"evidence":{"reviewedAt":"a","reviewedAt":"b","validUntil":"c"}}`,
		"missing member":     `{"evidence":{"reviewedAt":"a"}}`,
		"no evidence":        `{"other":{}}`,
		"repeated evidence":  `{"evidence":{"reviewedAt":"a","validUntil":"c"},"evidence":{"reviewedAt":"a","validUntil":"c"}}`,
		"not an object":      `[]`,
		"nested only member": `{"evidence":{"inner":{"reviewedAt":"a","validUntil":"c"}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := setRecordDates(json.RawMessage(bad), "2026-02-01T00:00:00Z", "2026-03-01T00:00:00Z"); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// A pack without record sections prepares exactly as before: no section is
// added to the next pack and V10 holds trivially.
func TestPackWithoutRecordsGetsNoSections(t *testing.T) {
	res, _, _, _, _ := singleRuleSetup(t, nil)
	if bytes.Contains(res.NextPack, []byte(lineattest.PackMember)) || bytes.Contains(res.NextPack, []byte("pathPolicies")) {
		t.Fatal("a pack without record sections gained one")
	}
	if bytes.Contains(res.Summary, []byte("records in the pack")) {
		t.Fatal("the summary of a pack without records lists records")
	}
}

// A withdrawn path policy is not renewed (E7), and a statement renewing it
// is refused by V8.
func TestWithdrawnPathPolicyIsNotRenewed(t *testing.T) {
	raw := buildRecordPack(t, recordPackSpec{at: baseNow, attestation: dueAt(baseNow), policy: dueAt(baseNow), ruleDue: true, pad: 30})
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["pathPolicies"].([]any)[0].(map[string]any)["evidence"].(map[string]any)["state"] = "withdrawn"
	prior, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	c := prepareRecordCycle(t, newChainFixture(t), prior, baseNow, "rev-2", nil)
	if statementLists(c, reviewedPolicyID) || worstClassOf(c, reviewedPolicyID) != reasonInactiveOrWithdrawn {
		t.Fatalf("withdrawn policy: %+v", c.res.Statement.NotExtended)
	}
	loaded, err := loadPack(prior)
	if err != nil {
		t.Fatal(err)
	}
	candidates, _, err := packCandidates(loaded)
	if err != nil {
		t.Fatal(err)
	}
	listed := c.res.Statement
	ra := listed.Rules[0]
	ra.RuleID = reviewedPolicyID
	ra.Citations = []CitationAttestation{{SourceID: "skew-policy", Class: evidencerepin.ClassFileIdentical, PinnedCommit: strings.Repeat("e", 40)}}
	listed.Rules = []RuleAttestation{ra}
	if err := checkRolePolicy(listed, candidatesByID(candidates)); err == nil || !strings.Contains(err.Error(), "not renewable") {
		t.Fatalf("V8 on a withdrawn policy: %v", err)
	}
}

func TestRenewRecordsRefusesAnUnknownRecord(t *testing.T) {
	doc, err := loadPack(standardRecordPack(t, baseNow))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := renewRecords(doc, map[string]recordDates{"path-policy.000000000000000000000000": {rfc3339(baseNow), rfc3339(baseNow.Add(time.Hour))}}); !errors.Is(err, ErrRejected) {
		t.Fatalf("got %v", err)
	}
}
