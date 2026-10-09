// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// Line reviews of Strimzi's custom-resource versions (test only, never
// published): line 0.51 read releases 0.50.0, 0.50.1 and 0.51.0.

const crdLineRuleID = "strimzi.crd-version-removal.kafkas-kafka-strimzi-io.0-50-0-to-0-51-0"

// crdLineRule is a line-wide rule of line 0.51: 0.51 no longer serves
// kafka.strimzi.io/v1beta2 Kafka.
var crdLineRule = `{"id":"` + crdLineRuleID + `","operator":"forbid_set_member","subject":{"component":"` + crdComponent + `","from":"0.50.0","to":"0.51.0"},` +
	`"range":{"from":{"gte":"0.50.0","lt":"0.51.0"},"to":{"gte":"0.51.0","lt":"0.52.0"},"bounds":[{"bound":"from.gte","basis":"PREVIOUS_MINOR_LINE","sourceId":"crd-0-51-0"},{"bound":"from.lt","basis":"REMOVED_IN_RELEASE","sourceId":"crd-0-51-0"},{"bound":"to.gte","basis":"REMOVED_IN_RELEASE","sourceId":"crd-0-51-0"},{"bound":"to.lt","basis":"TARGET_SERIES","sourceId":"crd-0-51-0"}]},` +
	`"setCondition":{"side":"proposed","component":"` + crdComponent + `","factId":"` + crdSetFact + `","members":["kafka.strimzi.io/v1beta2/Kafka"]},` +
	`"evidence":{"state":"active","reviewedAt":"2026-09-23T00:00:00Z","validUntil":"2026-12-20T00:00:00Z","sources":[{"id":"crd-0-51-0","url":"https://github.com/strimzi/strimzi-kafka-operator/blob/` + crdRevision + `/install/cluster-operator/040-Crd-kafka.yaml","revision":"` + crdRevision + `","contentDigest":"sha256:` + "0000000000000000000000000000000000000000000000000000000000000000" + `","startLine":1,"endLine":2}]},` +
	`"reasonCode":"CRD_VERSION_NOT_SERVED","nextAction":"change apiVersion of Kafka to kafka.strimzi.io/v1 before upgrading to 0.51.0"}`

// attestedCRD is crdKnowledge with line reviews.
type attestedCRD struct {
	crdKnowledge
	attestations lineattest.Index
}

func (k attestedCRD) AttestationsFor(component, line, family string, now time.Time) []lineattest.Status {
	return k.attestations.AttestationsFor(component, line, family, now)
}

func crdLineAttestation(basis string, ids ...string) lineattest.LineAttestation {
	if ids == nil {
		ids = []string{}
	}
	a := lineattest.LineAttestation{
		Component: crdComponent, Line: "0.51", FactFamily: lineattest.FamilyCustomResourceVersions, Completeness: lineattest.Completeness, RuleIDs: ids,
		Releases: &lineattest.Releases{
			From: []lineattest.Release{{Version: "0.50.0", Commit: strings.Repeat("1", 40)}, {Version: "0.50.1", Commit: strings.Repeat("2", 40)}},
			To:   []lineattest.Release{{Version: "0.51.0", Commit: strings.Repeat("3", 40)}},
		},
		Evidence: lineattest.Evidence{Basis: basis, ReviewedAt: "2026-09-25T00:00:00Z", ValidUntil: "2026-12-20T00:00:00Z", Sources: []constraintengine.SourceEvidence{{
			ID: "crds-0-51-0", URL: "https://github.com/strimzi/strimzi-kafka-operator/blob/" + crdRevision + "/install/cluster-operator/040-Crd-kafka.yaml",
			Revision: crdRevision, ContentDigest: "sha256:" + strings.Repeat("0", 64), StartLine: 1, EndLine: 2,
		}}},
	}
	if basis == constraintengine.BasisMechanical {
		a.Evidence.Extractor = &constraintengine.Extractor{ID: "crd.version-removal.strimzi", Version: "2.1.0", CodeDigest: "sha256:" + strings.Repeat("c", 64)}
		a.Evidence.DerivedAt = a.Evidence.ReviewedAt
	}
	if err := a.Validate(); err != nil {
		panic(err)
	}
	return a
}

func newAttestedCRD(t *testing.T, att *lineattest.LineAttestation, rules ...string) attestedCRD {
	t.Helper()
	k := attestedCRD{crdKnowledge: crdKnowledge{Knowledge: newKnowledge(t, knowledgeOptions{})}}
	if len(rules) > 0 {
		k.crdKnowledge = newCRDKnowledge(t, rules...)
	}
	var atts []lineattest.LineAttestation
	if att != nil {
		atts = append(atts, *att)
	}
	k.attestations = lineattest.NewIndex(atts)
	return k
}

func requireNeverCovered(t *testing.T, result Result) {
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
	hop := strimziHop(t, result.Report)
	if hop.Status == scanreport.HopCovered {
		t.Fatalf("hop covered %+v", hop)
	}
}

// A quiet, reviewed line decides the custom-resource version family on the
// hop: PASS within the family's scope only. The answer stays UNKNOWN (exit
// 11) and the component is not covered; the report names the family and
// what it does not check.
func TestScanCustomResourceAttestedQuietLine(t *testing.T) {
	att := crdLineAttestation(constraintengine.BasisMechanical)
	k := newAttestedCRD(t, &att)
	result := crdScan(t, k, []string{settingsDoc, kafkaV1beta2Doc}, "--from", "strimzi=0.50.1", "--to", "strimzi=0.51.0", "--resource-scope-complete")
	requireNeverCovered(t, result)
	hop := strimziHop(t, result.Report)
	if result.Exit != 11 || len(hop.Families) != 1 || hop.Status != scanreport.HopPartial {
		t.Fatalf("exit %d hop %+v gaps %v", result.Exit, hop, gapReasons(result.Report))
	}
	f := hop.Families[0]
	family, _ := lineattest.LookupFamily(lineattest.FamilyCustomResourceVersions)
	if f.Family != lineattest.FamilyCustomResourceVersions || f.Line != "0.51" || f.Status != scanreport.FamilyPass || f.Scope != family.Scope() {
		t.Fatalf("family %+v", f)
	}
	if a := hop.Attestation; a == nil || a.Family != lineattest.FamilyCustomResourceVersions || a.Basis != "mechanical" || a.Freshness != lineattest.FreshnessCurrent {
		t.Fatalf("attestation %+v", a)
	}
	if len(result.Report.Gaps) != 1 {
		t.Fatalf("gaps %v", gapReasons(result.Report))
	}
	human := string(scanreport.Human(result.Report, scanreport.HumanOptions{}))
	for _, want := range []string{
		"strimzi 0.50.1 -> 0.51.0: PASS within crd.custom_resource_versions only (line 0.51 attested complete, mechanical evidence)",
		"no manifest uses a version that strimzi 0.51.0 stops serving",
		"scope: the custom-resource versions (group/version/Kind) that the project's own CustomResourceDefinitions serve; not schemas",
		"nothing else about strimzi is checked",
	} {
		if !strings.Contains(human, want) {
			t.Fatalf("human output lacks %q:\n%s", want, human)
		}
	}
	for _, banned := range []string{"safe", "compatible", "no issues", "PASS FOR THE DECLARED SCOPE"} {
		if strings.Contains(strings.ToLower(human), strings.ToLower(banned)) {
			t.Fatalf("human output says %q:\n%s", banned, human)
		}
	}
	md := string(scanreport.Markdown(result.Report, scanreport.MarkdownOptions{}))
	if !strings.Contains(md, "## SCOPED RESULTS (1)") || !strings.Contains(md, "PASS within crd.custom\\_resource\\_versions only") && !strings.Contains(md, "PASS within crd.custom_resource_versions only") {
		t.Fatalf("markdown:\n%s", md)
	}
	raw, err := scanreport.MarshalJSON(result.Report)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scanreport.DecodeJSON(raw); err != nil || !strings.Contains(string(raw), `"families":[{"family":"crd.custom_resource_versions","line":"0.51","status":"PASS","basis":"mechanical","scope":"`) {
		t.Fatalf("json %v %s", err, raw)
	}
	// The report conforms to the published schema.
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	schema := readSchema(t)
	conform(t, schema, schema, value, "attested quiet line")
}

// A removal stays BLOCKED, and the family result says so; with the
// replacement version the same reviewed line is PASS within the family.
func TestScanCustomResourceAttestedRemoval(t *testing.T) {
	att := crdLineAttestation(constraintengine.BasisReviewed, crdLineRuleID)
	k := newAttestedCRD(t, &att, crdLineRule)
	result := crdScan(t, k, []string{kafkaV1beta2Doc}, "--from", "strimzi=0.50.0", "--to", "strimzi=0.51.0", "--resource-scope-complete")
	requireNeverCovered(t, result)
	hop := strimziHop(t, result.Report)
	if result.Exit != 10 || len(result.Report.Findings) != 1 || result.Report.Findings[0].RuleID != crdLineRuleID || hop.Status != scanreport.HopBlocked ||
		len(hop.Families) != 1 || hop.Families[0].Status != scanreport.FamilyBlocked {
		t.Fatalf("exit %d hop %+v findings %+v", result.Exit, hop, result.Report.Findings)
	}
	if human := string(scanreport.Human(result.Report, scanreport.HumanOptions{})); !strings.Contains(human, "BLOCKED within crd.custom_resource_versions (line 0.51 attested complete, reviewed evidence): see the problems above") {
		t.Fatalf("human:\n%s", human)
	}
	result = crdScan(t, k, []string{kafkaV1Doc}, "--from", "strimzi=0.50.1", "--to", "strimzi=0.51.0", "--resource-scope-complete")
	requireNeverCovered(t, result)
	hop = strimziHop(t, result.Report)
	if result.Exit != 11 || len(hop.Families) != 1 || hop.Families[0].Status != scanreport.FamilyPass || len(result.Report.Passes) != 1 {
		t.Fatalf("exit %d hop %+v", result.Exit, hop)
	}
}

// Every way a review cannot decide the hop leaves the family undecided,
// with a named gap where the review exists.
func TestScanCustomResourceAttestationNotApplied(t *testing.T) {
	mech := crdLineAttestation(constraintengine.BasisMechanical)
	listed := crdLineAttestation(constraintengine.BasisReviewed, crdLineRuleID)
	unknownListed := crdLineAttestation(constraintengine.BasisReviewed, "strimzi.not-a-rule")
	expired := crdLineAttestation(constraintengine.BasisMechanical)
	expired.Evidence.ValidUntil = "2026-10-01T00:00:00Z"
	cases := map[string]struct {
		k      Knowledge
		docs   []string
		args   []string
		reason string
		detail string
	}{
		"release newer than the review": {newAttestedCRD(t, &mech), []string{kafkaV1Doc}, []string{"--from", "strimzi=0.50.1", "--to", "strimzi=0.51.1", "--resource-scope-complete"},
			scanreport.ReasonLineNotAttested, "did not read release 0.51.1"},
		"earlier release newer than the review": {newAttestedCRD(t, &mech), []string{kafkaV1Doc}, []string{"--from", "strimzi=0.50.4", "--to", "strimzi=0.51.0", "--resource-scope-complete"},
			scanreport.ReasonLineNotAttested, "did not read release 0.50.4"},
		"hop across two lines": {newAttestedCRD(t, &mech), []string{kafkaV1Doc}, []string{"--from", "strimzi=0.49.0", "--to", "strimzi=0.51.0", "--resource-scope-complete"},
			scanreport.ReasonLineNotAttested, "is not a next-minor upgrade"},
		"upgrade within the line": {newAttestedCRD(t, &mech), []string{kafkaV1Doc}, []string{"--from", "strimzi=0.51.0", "--to", "strimzi=0.51.1", "--resource-scope-complete"},
			scanreport.ReasonLineNotAttested, "is not a next-minor upgrade"},
		"expired review": {newAttestedCRD(t, &expired), []string{kafkaV1Doc}, []string{"--from", "strimzi=0.50.1", "--to", "strimzi=0.51.0", "--resource-scope-complete"},
			scanreport.ReasonLineNotAttested, "is not current (stale)"},
		"basis left out": {newAttestedCRD(t, &mech), []string{kafkaV1Doc}, []string{"--from", "strimzi=0.50.1", "--to", "strimzi=0.51.0", "--resource-scope-complete", "--require-basis", "reviewed"},
			scanreport.ReasonLineNotAttested, "rests on basis mechanical"},
		"rule of the line not listed": {newAttestedCRD(t, &mech, crdLineRule), []string{kafkaV1Doc}, []string{"--from", "strimzi=0.50.1", "--to", "strimzi=0.51.0", "--resource-scope-complete"},
			scanreport.ReasonLineNotAttested, "does not list it"},
		"listed rule unknown": {newAttestedCRD(t, &unknownListed), []string{kafkaV1Doc}, []string{"--from", "strimzi=0.50.1", "--to", "strimzi=0.51.0", "--resource-scope-complete"},
			scanreport.ReasonLineNotAttested, "lists rule strimzi.not-a-rule"},
		"scope not declared": {newAttestedCRD(t, &listed, crdLineRule), []string{kafkaV1Doc}, []string{"--from", "strimzi=0.50.1", "--to", "strimzi=0.51.0"},
			scanreport.ReasonDeclarationMissing, "complete set"},
		"objects of an unowned group": {newAttestedCRD(t, &listed, crdLineRule), []string{kafkaV1Doc, serviceMonitorDoc}, []string{"--from", "strimzi=0.50.1", "--to", "strimzi=0.51.0", "--resource-scope-complete"},
			scanreport.ReasonDocumentsNotEvaluated, "no reviewed project owns"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			result := crdScan(t, tc.k, tc.docs, tc.args...)
			requireNeverCovered(t, result)
			hop := strimziHop(t, result.Report)
			if len(hop.Families) != 0 || result.Exit != 11 {
				t.Fatalf("exit %d family %+v", result.Exit, hop.Families)
			}
			if !hasComponentGap(result.Report, "strimzi", tc.reason, tc.detail) {
				var details []string
				for _, g := range result.Report.Gaps {
					details = append(details, g.Reason+": "+g.Detail)
				}
				t.Fatalf("gaps:\n%s", strings.Join(details, "\n"))
			}
			if strings.Contains(string(scanreport.Human(result.Report, scanreport.HumanOptions{})), "PASS within") {
				t.Fatal("a scoped pass without a decided family")
			}
		})
	}
}

// Without a review of the target line, nothing changes: no family result,
// no new gap (the component's own gap says scan checks custom-resource
// versions only).
func TestScanCustomResourceWithoutAttestationUnchanged(t *testing.T) {
	result := crdScan(t, newAttestedCRD(t, nil), []string{kafkaV1Doc}, "--from", "strimzi=0.50.1", "--to", "strimzi=0.51.0", "--resource-scope-complete")
	hop := strimziHop(t, result.Report)
	if result.Exit != 11 || len(hop.Families) != 0 || hop.Attestation != nil || hop.Status != scanreport.HopNoData || len(result.Report.Gaps) != 1 {
		t.Fatalf("exit %d hop %+v gaps %v", result.Exit, hop, gapReasons(result.Report))
	}
}
