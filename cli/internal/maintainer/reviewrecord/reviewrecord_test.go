// SPDX-License-Identifier: AGPL-3.0-only

package reviewrecord

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

const karmadaRule = "karmada.application-purge-mode-legacy-values-removed.1-19"

func TestKarmadaExistingRuleVectorsAreExecuted(t *testing.T) {
	target, err := cncfcheck.ExportEmbeddedExternalBundle("73")
	if err != nil {
		t.Fatal(err)
	}
	bundle, _, rule, err := exactSelectedRule(target, "73", "karmada", karmadaRule)
	if err != nil {
		t.Fatal(err)
	}
	vectors, err := os.ReadFile(filepath.Join("..", "..", "cncfcheck", "testdata", "reviewed-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	_, group, err := selectedVectors(vectors, "karmada", karmadaRule)
	if err != nil {
		t.Fatal(err)
	}
	counts, err := evaluateVectors(bundle, rule, group, time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"PASS", "BLOCKED", "UNKNOWN", "wrongCurrent", "wrongTarget"} {
		if counts[key] < 1 {
			t.Fatalf("coverage %s=%d", key, counts[key])
		}
	}
}

func TestExactTargetRejectsUnrelatedRuleMutation(t *testing.T) {
	target, err := cncfcheck.ExportEmbeddedExternalBundle("73")
	if err != nil {
		t.Fatal(err)
	}
	mutated := bytes.Replace(target, []byte(`"description":"`), []byte(`"description":"unrelated mutation: `), 1)
	if bytes.Equal(mutated, target) {
		t.Fatal("fixture mutation missed")
	}
	if _, err := cncfcheck.ParseExternalBundle(mutated); err != nil {
		t.Fatalf("mutation should remain a valid generic external target: %v", err)
	}
	if _, _, _, err := exactSelectedRule(mutated, "73", "karmada", karmadaRule); err == nil {
		t.Fatal("unrelated target mutation accepted")
	}
}

func TestSourceBindingsAreBidirectionalAndRoleExact(t *testing.T) {
	span := packetSpan{StartLine: 3, EndLine: 4, Digest: "sha256:" + strings.Repeat("a", 64)}
	packet := []packetSource{{Kind: "source_code", Version: "1.0.0", Commit: strings.Repeat("b", 40), URL: "https://github.com/example/widget/blob/" + strings.Repeat("b", 40) + "/file.go", FileDigest: "sha256:" + strings.Repeat("c", 64), Spans: []packetSpan{span}}}
	digest := "sha256:" + strings.Repeat("d", 64)
	corpus := []corpusSource{{Project: "widget", Repository: "https://github.com/example/widget", Kind: packet[0].Kind, Version: packet[0].Version, Commit: packet[0].Commit, URL: packet[0].URL, FileDigest: packet[0].FileDigest, Spans: []packetSpan{span}, PacketDigest: digest, RuleIDs: []string{"widget.rule"}}}
	if !samePacketAndCorpus("widget", "widget.rule", digest, packet, corpus) {
		t.Fatal("exact source binding rejected")
	}
	corpus[0].Version = "reference_only"
	if samePacketAndCorpus("widget", "widget.rule", digest, packet, corpus) {
		t.Fatal("reference-only source relabelled as endpoint evidence")
	}
	corpus[0].Version = packet[0].Version
	corpus = append(corpus, corpus[0])
	if samePacketAndCorpus("widget", "widget.rule", digest, packet, corpus) {
		t.Fatal("extra corpus source accepted")
	}
	corpus = corpus[:1]
	corpus[0].PacketDigest = "sha256:" + strings.Repeat("e", 64)
	if samePacketAndCorpus("widget", "widget.rule", digest, packet, corpus) {
		t.Fatal("corpus source declared for another packet accepted")
	}
	rule := []ruleSource{{URL: packet[0].URL, Revision: packet[0].Commit, ContentDigest: span.Digest, StartLine: span.StartLine, EndLine: span.EndLine}}
	if !sameRuleAndPacket(rule, packet) {
		t.Fatal("exact rule source rejected")
	}
	rule[0].ContentDigest = packet[0].FileDigest
	if !sameRuleAndPacket(rule, packet) {
		t.Fatal("recomputed full-file rule digest rejected")
	}
	rule[0].URL = "https://github.com/example/widget/blob/" + strings.Repeat("b", 40) + "/other.go"
	if sameRuleAndPacket(rule, packet) {
		t.Fatal("wrong endpoint source accepted")
	}
}

func TestRecordRejectsUnknownAndDuplicateFields(t *testing.T) {
	r := validTestRecord()
	raw, _ := json.Marshal(r)
	if _, _, err := parseRecord(raw); err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}
	unknown := bytes.Replace(raw, []byte(`"schema":`), []byte(`"unknown":true,"schema":`), 1)
	if _, _, err := parseRecord(unknown); err == nil {
		t.Fatal("unknown field accepted")
	}
	duplicate := bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema":"duplicate","schema":`), 1)
	if _, _, err := parseRecord(duplicate); err == nil {
		t.Fatal("duplicate field accepted")
	}
}

func TestParseRecordFieldsAppliesStructuralValidation(t *testing.T) {
	r := validTestRecord()
	r.Bindings.RuleDigest = "sha256:" + strings.Repeat("e", 64)
	raw, _ := json.Marshal(r)
	fields, err := ParseRecordFields(raw)
	if err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}
	if fields.Project != "karmada" || fields.RuleID != karmadaRule || fields.RuleDigest != r.Bindings.RuleDigest || fields.DecidedAt.Format(time.RFC3339) != "2026-09-13T08:00:00Z" {
		t.Fatalf("unexpected fields: %+v", fields)
	}
	unknown := bytes.Replace(raw, []byte(`"schema":`), []byte(`"unknown":true,"schema":`), 1)
	if _, err := ParseRecordFields(unknown); err == nil {
		t.Fatal("unknown field accepted")
	}
	r.Decision.State = "SOMETHING_ELSE"
	wrongState, _ := json.Marshal(r)
	if _, err := ParseRecordFields(wrongState); err == nil {
		t.Fatal("record with a different decision state accepted")
	}
}

func TestDeclaredMaintainerAcceptsOrdinaryUnicodePublicName(t *testing.T) {
	r := validTestRecord()
	r.Decision.Maintainer = "Željko Мария 山田 太郎"
	raw, _ := json.Marshal(r)
	if _, _, err := parseRecord(raw); err != nil {
		t.Fatalf("ordinary Unicode public name rejected: %v", err)
	}
}

func TestPublicVerifyAndRunRejectUnsafeMaintainerWithoutOutput(t *testing.T) {
	tests := []string{
		"/Users/reviewer/PRIVATE_PATH_CANARY",
		`C:\Users\reviewer\PRIVATE_PATH_CANARY`,
		"Reviewer\nPRIVATE_CONTROL_CANARY",
		"Reviewer\u2028PRIVATE_LINE_CANARY",
		"Reviewer\u202ePRIVATE_FORMAT_CANARY",
	}
	for _, unsafe := range tests {
		t.Run(sourcecorpus.SHA([]byte(unsafe)), func(t *testing.T) {
			r := validTestRecord()
			r.Decision.Maintainer = unsafe
			raw, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "record.json")
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			receipt, err := Verify(Options{RecordPath: path})
			if err == nil || len(receipt) != 0 || strings.Contains(err.Error(), unsafe) {
				t.Fatalf("Verify leaked or accepted rejected maintainer: receipt bytes=%d err=%q", len(receipt), err)
			}

			args := []string{"verify", "--target", "target", "--record", path, "--vectors", "vectors", "--packet", "packet", "--source-root", "objects", "--landscape", "landscape", "--source-manifest", "manifest"}
			var stdout bytes.Buffer
			err = Run(args, &stdout)
			if err == nil || stdout.Len() != 0 || strings.Contains(err.Error(), unsafe) {
				t.Fatalf("Run leaked or accepted rejected maintainer: stdout bytes=%d err=%q", stdout.Len(), err)
			}
		})
	}
}

func TestRunHelpAndReorderedOptions(t *testing.T) {
	var stdout bytes.Buffer
	if err := Run([]string{"verify", "--help"}, &stdout); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"usage: prufyx-maintainer review-record verify", "--record", "--packet", "--landscape", "--source-manifest", "--source-root", "--vectors", "--target"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("help missing %q: %q", want, stdout.String())
		}
	}

	o, help, err := parseRun([]string{"verify", "--target", "target", "--record", "record", "--vectors", "vectors", "--packet", "packet", "--source-root", "objects", "--landscape", "landscape", "--source-manifest", "manifest"})
	if err != nil || help {
		t.Fatalf("reordered options rejected: help=%t err=%v", help, err)
	}
	if o != (Options{RecordPath: "record", PacketPath: "packet", LandscapePath: "landscape", SourceManifestPath: "manifest", SourceRoot: "objects", VectorsPath: "vectors", TargetPath: "target"}) {
		t.Fatalf("reordered options parsed incorrectly: %#v", o)
	}
}

func TestRunRejectsMissingDuplicateUnknownAndPositionalOptionsWithoutOutput(t *testing.T) {
	tests := [][]string{
		{"verify", "--record", "PRIVATE_PATH_CANARY"},
		{"verify", "--record", "PRIVATE_PATH_CANARY", "--record", "second"},
		{"verify", "--unknown", "PRIVATE_PATH_CANARY"},
		{"verify", "PRIVATE_PATH_CANARY"},
	}
	for _, args := range tests {
		var stdout bytes.Buffer
		err := Run(args, &stdout)
		if err == nil || stdout.Len() != 0 || strings.Contains(err.Error(), "PRIVATE_PATH_CANARY") {
			t.Fatalf("unsafe option failure: args=%v stdout bytes=%d err=%q", args, stdout.Len(), err)
		}
	}
}

func TestSourceOnlyProposalCannotBeReviewPacket(t *testing.T) {
	packet := map[string]any{"schema": "prufyx.io/upstream-evidence-packet/v1", "submission": map[string]any{"kind": "new_catalogue_identity_proposal"}}
	if _, _, _, err := parsePacket(packet); err == nil {
		t.Fatal("source-only proposal accepted as reviewed transition packet")
	}
}

func TestMalformedVectorInputIsRejectedWithoutClaim(t *testing.T) {
	target, err := cncfcheck.ExportEmbeddedExternalBundle("73")
	if err != nil {
		t.Fatal(err)
	}
	bundle, _, rule, err := exactSelectedRule(target, "73", "karmada", karmadaRule)
	if err != nil {
		t.Fatal(err)
	}
	group := vectorGroup{Project: "karmada", RuleID: karmadaRule, Cases: []vectorCase{{Name: "malformed", Input: json.RawMessage(`{}`), Status: "UNKNOWN"}}}
	if _, err := evaluateVectors(bundle, rule, group, time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("malformed input treated as an executed UNKNOWN claim")
	}
}

func validTestRecord() record {
	digest := "sha256:" + strings.Repeat("d", 64)
	return record{
		Schema:   RecordSchema,
		Decision: decision{Authority: "DECLARED_MAINTAINER_DECISION_NOT_AUTHENTICATED", State: "ACCEPTED_FOR_SIGNING_REVIEW", Maintainer: "Review Fixture", DecidedAt: "2026-09-13T08:00:00Z", Scope: "ONE_RULE_CONSISTENCY_ONLY"},
		Subject:  subject{Project: "karmada", RuleID: karmadaRule, KnowledgeRevision: "73", EvaluationAt: "2026-09-13T08:00:00Z"},
		Bindings: bindings{digest, digest, digest, digest, digest, digest, digest, digest, digest, digest, digest},
	}
}
