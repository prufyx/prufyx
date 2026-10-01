// SPDX-License-Identifier: AGPL-3.0-only

// Package reviewrecord verifies one declared maintainer decision against
// retained source bytes, one exact embedded CNCF rule, and executed vectors.
// It grants no authentication, signing, publication, or store-selection authority.
package reviewrecord

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/maintainer/contribution"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

const (
	RecordSchema  = "prufyx.io/declared-knowledge-review-record/v1"
	ReceiptSchema = "prufyx.io/declared-knowledge-review-consistency-receipt/v1"
	maxRecord     = 64 << 10
	maxVectors    = 4 << 20
	maxTarget     = 1 << 20
	maxManifest   = 4 << 20
)

var (
	errRejected = errors.New("review record rejected")
	ruleIDRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,255}$`)
	revisionRE  = regexp.MustCompile(`^[1-9][0-9]*$`)
)

// Options names all local inputs. Verification performs no network access and
// writes nothing. The landscape is used only by the existing packet validator.
type Options struct {
	RecordPath, PacketPath, LandscapePath string
	SourceManifestPath, SourceRoot        string
	VectorsPath, TargetPath               string
}

type decision struct {
	Authority  string `json:"authority"`
	State      string `json:"state"`
	Maintainer string `json:"maintainer"`
	DecidedAt  string `json:"decidedAt"`
	Scope      string `json:"scope"`
}

type subject struct {
	Project           string `json:"project"`
	RuleID            string `json:"ruleId"`
	KnowledgeRevision string `json:"knowledgeRevision"`
	EvaluationAt      string `json:"evaluationAt"`
}

type bindings struct {
	PacketDigest               string `json:"packetDigest"`
	PacketReceiptDigest        string `json:"packetReceiptDigest"`
	SourceReceiptDigest        string `json:"sourceReceiptDigest"`
	SourceCorpusManifestDigest string `json:"sourceCorpusManifestDigest"`
	SourceCorpusReceiptDigest  string `json:"sourceCorpusReceiptDigest"`
	VectorFileDigest           string `json:"vectorFileDigest"`
	SelectedVectorGroupDigest  string `json:"selectedVectorGroupDigest"`
	TargetDigest               string `json:"targetDigest"`
	EngineCapabilityDigest     string `json:"engineCapabilityDigest"`
	RuleDigest                 string `json:"ruleDigest"`
	RuleEvidenceDigest         string `json:"ruleEvidenceDigest"`
}

type record struct {
	Schema   string   `json:"schema"`
	Decision decision `json:"decision"`
	Subject  subject  `json:"subject"`
	Bindings bindings `json:"bindings"`
}

type targetDocument struct {
	Revision               string `json:"revision"`
	EngineCapabilityDigest string `json:"engineCapabilityDigest"`
	Pack                   struct {
		Entries []struct {
			Project string          `json:"project"`
			Rule    json.RawMessage `json:"rule"`
		} `json:"entries"`
	} `json:"pack"`
}

type ruleDocument struct {
	ID      string `json:"id"`
	Subject struct {
		Component, From, To string
	} `json:"subject"`
	Range    *constraintengine.VersionRange `json:"range"`
	Evidence struct {
		Sources []ruleSource `json:"sources"`
	} `json:"evidence"`
}

func (r ruleDocument) transition() constraintengine.RuleTransition {
	return constraintengine.RuleTransition{Component: r.Subject.Component, From: r.Subject.From, To: r.Subject.To, Range: r.Range}
}

type ruleSource struct {
	ID, URL, Revision, ContentDigest string
	StartLine, EndLine               int
}

type vectorGroup struct {
	Project string       `json:"project"`
	RuleID  string       `json:"ruleId"`
	Cases   []vectorCase `json:"cases"`
}

type vectorCase struct {
	Name   string          `json:"name"`
	Input  json.RawMessage `json:"input"`
	Status string          `json:"status"`
}

type packetSource struct {
	ID, Kind, Version, Commit, URL, FileDigest string
	Spans                                      []packetSpan
}
type packetSpan struct {
	StartLine, EndLine int
	Digest             string
}
type corpusSource struct {
	Project, Repository, Kind, Version, Commit, URL, FileDigest string
	Spans                                                       []packetSpan
	PacketDigest                                                string
	RuleIDs                                                     []string
}

// Verify returns a canonical receipt without a trailing newline.
func Verify(o Options) ([]byte, error) {
	recordRaw, err := sourcecorpus.ReadRegularFile(o.RecordPath, maxRecord)
	if err != nil {
		return nil, errRejected
	}
	r, recordValue, err := parseRecord(recordRaw)
	if err != nil {
		return nil, errRejected
	}
	packetReceipt, err := contribution.Validate(contribution.ValidateOptions{PacketPath: o.PacketPath, LandscapePath: o.LandscapePath})
	if err != nil {
		return nil, errRejected
	}
	sourceReceipt, err := contribution.VerifySources(contribution.ValidateOptions{PacketPath: o.PacketPath, LandscapePath: o.LandscapePath}, o.SourceRoot)
	if err != nil {
		return nil, errRejected
	}
	corpusReceipt, err := sourcecorpus.VerifyPath(o.SourceManifestPath, o.SourceRoot)
	if err != nil {
		return nil, errRejected
	}
	packetRaw, err := sourcecorpus.ReadRegularFile(o.PacketPath, contribution.MaxPacketBytes)
	if err != nil {
		return nil, errRejected
	}
	manifestRaw, err := sourcecorpus.ReadRegularFile(o.SourceManifestPath, maxManifest)
	if err != nil {
		return nil, errRejected
	}
	vectorsRaw, err := sourcecorpus.ReadRegularFile(o.VectorsPath, maxVectors)
	if err != nil {
		return nil, errRejected
	}
	targetRaw, err := sourcecorpus.ReadRegularFile(o.TargetPath, maxTarget)
	if err != nil {
		return nil, errRejected
	}
	return verifyRaw(r, recordValue, packetRaw, packetReceipt, sourceReceipt, manifestRaw, corpusReceipt, vectorsRaw, targetRaw)
}

func verifyRaw(r record, recordValue any, packetRaw, packetReceipt, sourceReceipt, manifestRaw, corpusReceipt, vectorsRaw, targetRaw []byte) ([]byte, error) {
	packetValue, err := sourcecorpus.DecodeBounded(packetRaw, contribution.MaxPacketBytes)
	if err != nil {
		return nil, errRejected
	}
	packet, transition, project, err := parsePacket(packetValue)
	if err != nil || project != r.Subject.Project || transition[0] == transition[1] {
		return nil, errRejected
	}
	manifestValue, err := sourcecorpus.DecodeBounded(manifestRaw, maxManifest)
	if err != nil {
		return nil, errRejected
	}
	corpus, err := parseCorpus(manifestValue)
	if err != nil {
		return nil, errRejected
	}
	packetReceiptValue, err := sourcecorpus.DecodeBounded(packetReceipt, int64(len(packetReceipt)))
	if err != nil {
		return nil, errRejected
	}
	corpusReceiptValue, err := sourcecorpus.DecodeBounded(corpusReceipt, int64(len(corpusReceipt)))
	if err != nil {
		return nil, errRejected
	}
	packetDigest, ok1 := nestedString(packetReceiptValue, "packetDigest")
	packetCanonical, packetCanonicalErr := sourcecorpus.Canonical(packetValue)
	manifestCanonical, manifestCanonicalErr := sourcecorpus.Canonical(manifestValue)
	manifestDigest, ok2 := nestedString(corpusReceiptValue, "manifestDigest")
	if !ok1 || !ok2 || packetCanonicalErr != nil || manifestCanonicalErr != nil || sourcecorpus.SHA(packetCanonical) != packetDigest || sourcecorpus.SHA(manifestCanonical) != manifestDigest || !samePacketAndCorpus(project, r.Subject.RuleID, packetDigest, packet, corpus) {
		return nil, errRejected
	}

	bundle, ruleRaw, rule, err := exactSelectedRule(targetRaw, r.Subject.KnowledgeRevision, r.Subject.Project, r.Subject.RuleID)
	if err != nil || !rule.transition().IsAnchor(transition[0], transition[1]) || !sameRuleAndPacket(rule.Evidence.Sources, packet) {
		return nil, errRejected
	}

	groupValue, group, err := selectedVectors(vectorsRaw, r.Subject.Project, r.Subject.RuleID)
	if err != nil {
		return nil, errRejected
	}
	evaluationAt, err := parseUTC(r.Subject.EvaluationAt)
	if err != nil {
		return nil, errRejected
	}
	coverage, err := evaluateVectors(bundle, rule, group, evaluationAt)
	if err != nil {
		return nil, errRejected
	}

	sourceReceiptValue, err := sourcecorpus.DecodeBounded(sourceReceipt, int64(len(sourceReceipt)))
	if err != nil {
		return nil, errRejected
	}
	packetConsistency, ok3 := nestedString(packetReceiptValue, "consistency")
	packetWorkflow, ok4 := nestedString(packetReceiptValue, "workflowState")
	sourceVerification, ok5 := nestedString(sourceReceiptValue, "verification")
	sourceAdmission, ok6 := nestedString(sourceReceiptValue, "admissionState")
	corpusVerification, ok7 := nestedString(corpusReceiptValue, "verification")
	sourcePacketDigest, ok8 := nestedString(sourceReceiptValue, "packetDigest")
	sourceWorkflow, ok9 := nestedString(sourceReceiptValue, "workflowState")
	corpusAuthority, ok10 := nestedString(corpusReceiptValue, "authority")
	packetReceiptSchema, ok11 := nestedString(packetReceiptValue, "schema")
	sourceReceiptSchema, ok12 := nestedString(sourceReceiptValue, "schema")
	corpusReceiptSchema, ok13 := nestedString(corpusReceiptValue, "schema")
	capability, err := cncfcheck.ExternalCapabilityDigest()
	ruleValue, evidenceValue, identityErr := decodeRuleIdentities(ruleRaw)
	ruleCanon, errRule := sourcecorpus.Canonical(ruleValue)
	evidenceCanon, errEvidence := sourcecorpus.Canonical(evidenceValue)
	groupCanon, errGroup := sourcecorpus.Canonical(groupValue)
	packetReceiptCanon, errPacketReceipt := sourcecorpus.Canonical(packetReceiptValue)
	sourceReceiptCanon, errSourceReceipt := sourcecorpus.Canonical(sourceReceiptValue)
	corpusReceiptCanon, errCorpusReceipt := sourcecorpus.Canonical(corpusReceiptValue)
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 || !ok7 || !ok8 || !ok9 || !ok10 || !ok11 || !ok12 || !ok13 || packetReceiptSchema != "prufyx.io/upstream-evidence-receipt/v1" || sourceReceiptSchema != "prufyx.io/upstream-evidence-source-receipt/v1" || corpusReceiptSchema != sourcecorpus.ReceiptSchema || packetConsistency != "VALID" || packetWorkflow != "CANDIDATE" || sourcePacketDigest != packetDigest || sourceVerification != "LOCAL_DECLARED_PUBLIC_SOURCE_BYTES_MATCHED" || sourceWorkflow != "CANDIDATE" || sourceAdmission != "NOT_ADMITTED" || corpusVerification != "VERIFIED_RETAINED_BYTES" || corpusAuthority != sourcecorpus.LocalAuthority || err != nil || identityErr != nil || errRule != nil || errEvidence != nil || errGroup != nil || errPacketReceipt != nil || errSourceReceipt != nil || errCorpusReceipt != nil {
		return nil, errRejected
	}
	actual := bindings{
		PacketDigest: packetDigest, PacketReceiptDigest: sourcecorpus.SHA(packetReceiptCanon),
		SourceReceiptDigest:        sourcecorpus.SHA(sourceReceiptCanon),
		SourceCorpusManifestDigest: manifestDigest, SourceCorpusReceiptDigest: sourcecorpus.SHA(corpusReceiptCanon),
		VectorFileDigest: sourcecorpus.SHA(vectorsRaw), SelectedVectorGroupDigest: sourcecorpus.SHA(groupCanon),
		TargetDigest: sourcecorpus.SHA(targetRaw), EngineCapabilityDigest: capability,
		RuleDigest: sourcecorpus.SHA(ruleCanon), RuleEvidenceDigest: sourcecorpus.SHA(evidenceCanon),
	}
	if r.Bindings != actual {
		return nil, errRejected
	}
	recordCanon, err := sourcecorpus.Canonical(recordValue)
	if err != nil {
		return nil, errRejected
	}
	receipt := map[string]any{
		"schema": ReceiptSchema, "consistency": "VALID",
		"scope":                  map[string]any{"project": r.Subject.Project, "ruleId": r.Subject.RuleID, "knowledgeRevision": r.Subject.KnowledgeRevision},
		"recordDigest":           sourcecorpus.SHA(recordCanon),
		"declaredDecision":       map[string]any{"state": r.Decision.State, "authority": r.Decision.Authority, "maintainer": r.Decision.Maintainer, "decidedAt": r.Decision.DecidedAt},
		"sourceConsistency":      "LOCAL_RETAINED_BYTES_PACKET_CORPUS_AND_RULE_REFERENCES_MATCHED",
		"engineCompatibility":    map[string]any{"state": "SELECTED_RULE_VECTORS_REPRODUCED", "executedCaseCount": int64(len(group.Cases)), "passCases": coverage["PASS"], "blockedCases": coverage["BLOCKED"], "unknownCases": coverage["UNKNOWN"], "wrongCurrentCases": coverage["wrongCurrent"], "wrongTargetCases": coverage["wrongTarget"]},
		"malformedInputCoverage": "NOT_CHECKED_SEPARATE_PARSER_REJECTION",
		"processAuthorization":   "DECLARED_NOT_AUTHENTICATED",
		"baselineCandidateDelta": "NOT_CHECKED", "fullTargetAdmission": "NOT_DETERMINED",
		"signing": "NOT_PERFORMED", "storeSelection": "NOT_PERFORMED",
		"bindings": actual,
		"limitations": []any{
			"this is one offline consistency gate for one rule; it is not a complete promotion command",
			"the declared maintainer identity and decision are not authenticated",
			"source origin, tag ownership, license, runtime behavior, whole-target admission, signing, publication, and client store selection remain separate gates",
		},
	}
	return sourcecorpus.Canonical(receipt)
}

func exactSelectedRule(raw []byte, revision, project, ruleID string) (cncfcheck.ExternalBundle, []byte, ruleDocument, error) {
	bundle, err := cncfcheck.ParseExternalBundle(raw)
	if err != nil {
		return cncfcheck.ExternalBundle{}, nil, ruleDocument{}, errRejected
	}
	expected, err := cncfcheck.ExportEmbeddedExternalBundle(revision)
	if err != nil || !bytes.Equal(raw, expected) {
		return cncfcheck.ExternalBundle{}, nil, ruleDocument{}, errRejected
	}
	var target targetDocument
	if json.Unmarshal(raw, &target) != nil || target.Revision != revision {
		return cncfcheck.ExternalBundle{}, nil, ruleDocument{}, errRejected
	}
	ruleRaw, rule, err := selectedRule(target, project, ruleID)
	if err != nil {
		return cncfcheck.ExternalBundle{}, nil, ruleDocument{}, errRejected
	}
	return bundle, ruleRaw, rule, nil
}

func parseRecord(raw []byte) (record, any, error) {
	value, err := sourcecorpus.DecodeBounded(raw, maxRecord)
	if err != nil {
		return record{}, nil, errRejected
	}
	if !closed(value, "schema", "decision", "subject", "bindings") {
		return record{}, nil, errRejected
	}
	o := value.(map[string]any)
	if !closed(o["decision"], "authority", "state", "maintainer", "decidedAt", "scope") || !closed(o["subject"], "project", "ruleId", "knowledgeRevision", "evaluationAt") || !closed(o["bindings"], "packetDigest", "packetReceiptDigest", "sourceReceiptDigest", "sourceCorpusManifestDigest", "sourceCorpusReceiptDigest", "vectorFileDigest", "selectedVectorGroupDigest", "targetDigest", "engineCapabilityDigest", "ruleDigest", "ruleEvidenceDigest") {
		return record{}, nil, errRejected
	}
	var r record
	if json.Unmarshal(raw, &r) != nil || r.Schema != RecordSchema || r.Decision.Authority != "DECLARED_MAINTAINER_DECISION_NOT_AUTHENTICATED" || r.Decision.State != "ACCEPTED_FOR_SIGNING_REVIEW" || !validPublicName(r.Decision.Maintainer) || r.Decision.Scope != "ONE_RULE_CONSISTENCY_ONLY" || !ruleIDRE.MatchString(r.Subject.Project) || !ruleIDRE.MatchString(r.Subject.RuleID) || !revisionRE.MatchString(r.Subject.KnowledgeRevision) {
		return record{}, nil, errRejected
	}
	decidedAt, err := parseUTC(r.Decision.DecidedAt)
	evaluationAt, evaluationErr := parseUTC(r.Subject.EvaluationAt)
	if err != nil || evaluationErr != nil || decidedAt.Before(evaluationAt) {
		return record{}, nil, errRejected
	}
	for _, digest := range []string{r.Bindings.PacketDigest, r.Bindings.PacketReceiptDigest, r.Bindings.SourceReceiptDigest, r.Bindings.SourceCorpusManifestDigest, r.Bindings.SourceCorpusReceiptDigest, r.Bindings.VectorFileDigest, r.Bindings.SelectedVectorGroupDigest, r.Bindings.TargetDigest, r.Bindings.EngineCapabilityDigest, r.Bindings.RuleDigest, r.Bindings.RuleEvidenceDigest} {
		if _, err := sourcecorpus.ValidateSHA(digest); err != nil {
			return record{}, nil, errRejected
		}
	}
	return r, value, nil
}

func parsePacket(value any) ([]packetSource, [2]string, string, error) {
	o, ok := value.(map[string]any)
	if !ok || stringAt(o, "schema") != "prufyx.io/upstream-evidence-packet/v1" {
		return nil, [2]string{}, "", errRejected
	}
	sub, ok := o["submission"].(map[string]any)
	if !ok || stringAt(sub, "kind") != "existing_project_transition" {
		return nil, [2]string{}, "", errRejected
	}
	project, ok := o["project"].(map[string]any)
	transition, ok2 := o["transition"].(map[string]any)
	items, ok3 := o["sources"].([]any)
	if !ok || !ok2 || !ok3 {
		return nil, [2]string{}, "", errRejected
	}
	result := make([]packetSource, 0, len(items))
	for _, item := range items {
		s, ok := item.(map[string]any)
		spans, ok2 := s["spans"].([]any)
		if !ok || !ok2 {
			return nil, [2]string{}, "", errRejected
		}
		parsed := packetSource{ID: stringAt(s, "id"), Kind: stringAt(s, "sourceKind"), Version: stringAt(s, "version"), Commit: stringAt(s, "commit"), URL: stringAt(s, "immutableURL"), FileDigest: stringAt(s, "fileDigest")}
		for _, spanItem := range spans {
			span, ok := spanItem.(map[string]any)
			if !ok {
				return nil, [2]string{}, "", errRejected
			}
			excerpt, ok := span["excerpt"].(string)
			if !ok {
				return nil, [2]string{}, "", errRejected
			}
			parsed.Spans = append(parsed.Spans, packetSpan{intAt(span, "startLine"), intAt(span, "endLine"), sourcecorpus.SHA([]byte(excerpt))})
		}
		result = append(result, parsed)
	}
	return result, [2]string{stringAt(transition, "currentVersion"), stringAt(transition, "proposedVersion")}, stringAt(project, "slug"), nil
}

func parseCorpus(value any) ([]corpusSource, error) {
	o, ok := value.(map[string]any)
	items, ok2 := o["records"].([]any)
	if !ok || !ok2 {
		return nil, errRejected
	}
	result := make([]corpusSource, 0, len(items))
	for _, item := range items {
		record, ok := item.(map[string]any)
		project, ok2 := record["project"].(map[string]any)
		source, ok3 := record["source"].(map[string]any)
		spans, ok4 := source["spans"].([]any)
		if !ok || !ok2 || !ok3 || !ok4 {
			return nil, errRejected
		}
		parsed := corpusSource{Project: stringAt(project, "slug"), Repository: stringAt(project, "canonicalRepositoryURL"), Kind: stringAt(source, "sourceKind"), Version: stringAt(source, "version"), Commit: stringAt(source, "commit"), URL: stringAt(source, "immutableURL"), FileDigest: stringAt(source, "fileDigest")}
		declarations, ok5 := record["declarations"].(map[string]any)
		rawRules, ok6 := declarations["ruleIDs"].([]any)
		if !ok5 || !ok6 {
			return nil, errRejected
		}
		parsed.PacketDigest = stringAt(declarations, "packetDigest")
		for _, value := range rawRules {
			ruleID, ok := value.(string)
			if !ok {
				return nil, errRejected
			}
			parsed.RuleIDs = append(parsed.RuleIDs, ruleID)
		}
		for _, item := range spans {
			span, ok := item.(map[string]any)
			if !ok {
				return nil, errRejected
			}
			parsed.Spans = append(parsed.Spans, packetSpan{intAt(span, "startLine"), intAt(span, "endLine"), stringAt(span, "spanDigest")})
		}
		result = append(result, parsed)
	}
	return result, nil
}

func samePacketAndCorpus(project, ruleID, packetDigest string, packet []packetSource, corpus []corpusSource) bool {
	if len(packet) != len(corpus) {
		return false
	}
	used := make([]bool, len(corpus))
	for _, p := range packet {
		found := -1
		for i, c := range corpus {
			if !used[i] && c.Project == project && c.Repository == repositoryOf(p.URL) && c.Kind == p.Kind && c.Version == p.Version && c.Commit == p.Commit && c.URL == p.URL && c.FileDigest == p.FileDigest && c.PacketDigest == packetDigest && len(c.RuleIDs) == 1 && c.RuleIDs[0] == ruleID && sameSpans(c.Spans, p.Spans) {
				found = i
				break
			}
		}
		if found < 0 {
			return false
		}
		used[found] = true
	}
	return true
}

func sameRuleAndPacket(rule []ruleSource, packet []packetSource) bool {
	total := 0
	for _, p := range packet {
		total += len(p.Spans)
	}
	if total != len(rule) {
		return false
	}
	used := make([]bool, len(rule))
	for _, p := range packet {
		for _, span := range p.Spans {
			found := -1
			for i, r := range rule {
				if !used[i] && r.URL == p.URL && r.Revision == p.Commit && (r.ContentDigest == span.Digest || r.ContentDigest == p.FileDigest) && r.StartLine == span.StartLine && r.EndLine == span.EndLine {
					found = i
					break
				}
			}
			if found < 0 {
				return false
			}
			used[found] = true
		}
	}
	return true
}

func selectedRule(target targetDocument, project, ruleID string) ([]byte, ruleDocument, error) {
	var selected []byte
	var rule ruleDocument
	for _, entry := range target.Pack.Entries {
		if entry.Project != project {
			continue
		}
		var candidate ruleDocument
		if json.Unmarshal(entry.Rule, &candidate) != nil {
			return nil, ruleDocument{}, errRejected
		}
		if candidate.ID == ruleID {
			if selected != nil {
				return nil, ruleDocument{}, errRejected
			}
			selected, rule = append([]byte(nil), entry.Rule...), candidate
		}
	}
	if selected == nil || rule.ID != ruleID || len(rule.Evidence.Sources) == 0 {
		return nil, ruleDocument{}, errRejected
	}
	return selected, rule, nil
}

func selectedVectors(raw []byte, project, ruleID string) (any, vectorGroup, error) {
	value, err := sourcecorpus.DecodeBounded(raw, maxVectors)
	items, ok := value.([]any)
	if err != nil || !ok || len(items) == 0 {
		return nil, vectorGroup{}, errRejected
	}
	var selected any
	for _, item := range items {
		if !closed(item, "project", "ruleId", "cases") {
			return nil, vectorGroup{}, errRejected
		}
		o := item.(map[string]any)
		cases, ok := o["cases"].([]any)
		if !ok || len(cases) == 0 {
			return nil, vectorGroup{}, errRejected
		}
		for _, c := range cases {
			if !closed(c, "name", "input", "status") {
				return nil, vectorGroup{}, errRejected
			}
		}
		if stringAt(o, "project") == project && stringAt(o, "ruleId") == ruleID {
			if selected != nil {
				return nil, vectorGroup{}, errRejected
			}
			selected = item
		}
	}
	if selected == nil {
		return nil, vectorGroup{}, errRejected
	}
	canonical, err := sourcecorpus.Canonical(selected)
	var group vectorGroup
	if err != nil || json.Unmarshal(canonical, &group) != nil {
		return nil, vectorGroup{}, errRejected
	}
	return selected, group, nil
}

func evaluateVectors(bundle cncfcheck.ExternalBundle, rule ruleDocument, group vectorGroup, at time.Time) (map[string]int64, error) {
	counts := map[string]int64{"PASS": 0, "BLOCKED": 0, "UNKNOWN": 0, "wrongCurrent": 0, "wrongTarget": 0}
	subject := rule.transition()
	observed := make([]vectorObservation, 0, len(group.Cases))
	seenNames := map[string]bool{}
	seenInputs := map[string]bool{}
	for _, c := range group.Cases {
		inputDigest := sourcecorpus.SHA(c.Input)
		if c.Name == "" || seenNames[c.Name] || seenInputs[inputDigest] || (c.Status != "PASS" && c.Status != "BLOCKED" && c.Status != "UNKNOWN") {
			return nil, errRejected
		}
		seenNames[c.Name] = true
		seenInputs[inputDigest] = true
		report, err := bundle.EvaluateRule(group.Project, group.RuleID, c.Input, at)
		if err != nil {
			return nil, errRejected
		}
		actual := "UNKNOWN"
		if len(report.Check.Claims) > 1 {
			return nil, errRejected
		}
		if len(report.Check.Claims) == 1 {
			claim := report.Check.Claims[0]
			if claim.RuleID != group.RuleID {
				return nil, errRejected
			}
			actual = string(claim.Status)
		}
		if actual != c.Status {
			return nil, errRejected
		}
		counts[c.Status]++
		current, proposed := componentVersions(c.Input, rule.Subject.Component)
		if c.Status == "UNKNOWN" && current != "" && !subject.MatchesFrom(current) {
			counts["wrongCurrent"]++
		}
		if c.Status == "UNKNOWN" && proposed != "" && !subject.MatchesTo(proposed) {
			counts["wrongTarget"]++
		}
		observed = append(observed, vectorObservation{current: current, proposed: proposed, status: c.Status})
	}
	if subject.Range != nil && !rangeBoundsCovered(*subject.Range, observed) {
		return nil, errRejected
	}
	if counts["PASS"] < 1 || counts["BLOCKED"] < 1 || counts["UNKNOWN"] < 1 || counts["wrongCurrent"] < 1 || counts["wrongTarget"] < 1 {
		return nil, errRejected
	}
	return counts, nil
}

type vectorObservation struct{ current, proposed, status string }

// rangeBoundsCovered generalizes the wrongCurrent/wrongTarget requirement to
// a reviewed range: at each of the four bounds there must be one vector just
// inside, which decides (PASS or BLOCKED), and one just outside, which stays
// UNKNOWN, with the other side of the pair inside its range.
//
//   - gte inside: the side equals gte. gte outside: the side is below gte.
//   - lt inside: the side is inside the range and above gte.
//     lt outside: the side equals lt.
func rangeBoundsCovered(rng constraintengine.VersionRange, observed []vectorObservation) bool {
	var fromGteIn, fromGteOut, fromLtIn, fromLtOut, toGteIn, toGteOut, toLtIn, toLtOut bool
	for _, o := range observed {
		decided := o.status == "PASS" || o.status == "BLOCKED"
		unknown := o.status == "UNKNOWN"
		if rng.To.Contains(o.proposed) {
			switch {
			case decided && constraintengine.SameVersion(o.current, rng.From.Gte):
				fromGteIn = true
			case unknown && constraintengine.VersionLess(o.current, rng.From.Gte):
				fromGteOut = true
			case decided && rng.From.Contains(o.current) && constraintengine.VersionLess(rng.From.Gte, o.current):
				fromLtIn = true
			case unknown && constraintengine.SameVersion(o.current, rng.From.Lt):
				fromLtOut = true
			}
		}
		if rng.From.Contains(o.current) {
			switch {
			case decided && constraintengine.SameVersion(o.proposed, rng.To.Gte):
				toGteIn = true
			case unknown && constraintengine.VersionLess(o.proposed, rng.To.Gte):
				toGteOut = true
			case decided && rng.To.Contains(o.proposed) && constraintengine.VersionLess(rng.To.Gte, o.proposed):
				toLtIn = true
			case unknown && constraintengine.SameVersion(o.proposed, rng.To.Lt):
				toLtOut = true
			}
		}
	}
	return fromGteIn && fromGteOut && fromLtIn && fromLtOut && toGteIn && toGteOut && toLtIn && toLtOut
}

func componentVersions(raw []byte, component string) (string, string) {
	var input struct {
		Current, Proposed struct {
			Components []struct{ Component, Version string } `json:"components"`
		}
	}
	if json.Unmarshal(raw, &input) != nil {
		return "", ""
	}
	find := func(items []struct{ Component, Version string }) string {
		for _, item := range items {
			if item.Component == component {
				return item.Version
			}
		}
		return ""
	}
	return find(input.Current.Components), find(input.Proposed.Components)
}

func decodeRuleIdentities(raw []byte) (any, any, error) {
	value, err := sourcecorpus.DecodeBounded(raw, int64(len(raw)))
	if err != nil {
		return nil, nil, errRejected
	}
	o, ok := value.(map[string]any)
	if !ok {
		return nil, nil, errRejected
	}
	evidence, ok := o["evidence"]
	if !ok {
		return nil, nil, errRejected
	}
	return value, evidence, nil
}
func nestedString(value any, key string) (string, bool) {
	o, ok := value.(map[string]any)
	if !ok {
		return "", false
	}
	v, ok := o[key].(string)
	return v, ok
}
func stringAt(o map[string]any, key string) string { value, _ := o[key].(string); return value }
func intAt(o map[string]any, key string) int       { value, _ := o[key].(int64); return int(value) }
func sameSpans(a, b []packetSpan) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func closed(value any, fields ...string) bool {
	o, ok := value.(map[string]any)
	if !ok || len(o) != len(fields) {
		return false
	}
	for _, field := range fields {
		if _, ok := o[field]; !ok {
			return false
		}
	}
	return true
}
func parseUTC(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339) != value {
		return time.Time{}, fmt.Errorf("time: %w", errRejected)
	}
	return parsed, nil
}

func validPublicName(value string) bool {
	if value == "" || len(value) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if r == '/' || r == '\\' || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func repositoryOf(value string) string {
	parts := strings.Split(value, "/")
	if len(parts) < 5 {
		return ""
	}
	return strings.Join(parts[:5], "/")
}

// Run is the redacted CLI adapter.
func Run(args []string, stdout io.Writer) error {
	o, help, err := parseRun(args)
	if err != nil {
		return errRejected
	}
	if help {
		return writeOutput(stdout, []byte("usage: prufyx-maintainer review-record verify --record RECORD.json --packet PACKET.json --landscape LANDSCAPE.json --source-manifest CORPUS.json --source-root OBJECTS --vectors REVIEWED-VECTORS.json --target CONSTRAINTS.json\n"))
	}
	receipt, err := Verify(o)
	if err != nil {
		return errRejected
	}
	return writeOutput(stdout, append(receipt, '\n'))
}

func parseRun(args []string) (Options, bool, error) {
	if len(args) == 1 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help") {
		return Options{}, true, nil
	}
	if len(args) == 0 || args[0] != "verify" || duplicateOptions(args[1:]) {
		return Options{}, false, errRejected
	}
	flags := flag.NewFlagSet("review-record verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var o Options
	flags.StringVar(&o.RecordPath, "record", "", "declared review record")
	flags.StringVar(&o.PacketPath, "packet", "", "validated contribution packet")
	flags.StringVar(&o.LandscapePath, "landscape", "", "pinned landscape catalogue")
	flags.StringVar(&o.SourceManifestPath, "source-manifest", "", "retained source manifest")
	flags.StringVar(&o.SourceRoot, "source-root", "", "retained source object root")
	flags.StringVar(&o.VectorsPath, "vectors", "", "reviewed vector file")
	flags.StringVar(&o.TargetPath, "target", "", "complete exported target")
	if err := flags.Parse(args[1:]); errors.Is(err, flag.ErrHelp) {
		return Options{}, true, nil
	} else if err != nil || flags.NArg() != 0 {
		return Options{}, false, errRejected
	}
	for _, value := range []string{o.RecordPath, o.PacketPath, o.LandscapePath, o.SourceManifestPath, o.SourceRoot, o.VectorsPath, o.TargetPath} {
		if strings.TrimSpace(value) == "" {
			return Options{}, false, errRejected
		}
	}
	return o, false, nil
}

func duplicateOptions(args []string) bool {
	seen := map[string]bool{}
	for _, arg := range args {
		if len(arg) < 2 || arg[0] != '-' || arg == "--" {
			continue
		}
		name := strings.SplitN(strings.TrimLeft(arg, "-"), "=", 2)[0]
		if name == "" {
			continue
		}
		if seen[name] {
			return true
		}
		seen[name] = true
	}
	return false
}

func writeOutput(stdout io.Writer, output []byte) error {
	written, err := stdout.Write(output)
	if err != nil || written != len(output) {
		return errRejected
	}
	return nil
}
