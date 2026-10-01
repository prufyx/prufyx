// SPDX-License-Identifier: AGPL-3.0-only

package validation

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func canonicalCandidateFixture() CandidateReport {
	component := "pkg:oci/example/widget"
	return CandidateReport{
		APIVersion: ReportAPIVersion, Kind: ReportKind, SchemaVersion: SchemaVersion,
		Status: CandidateReportStatus, Decision: DecisionUnknown,
		ReasonCode: "candidate_evaluation_unknown", Now: "2026-08-28T00:00:00Z",
		Current: CurrentSummary{KubernetesVersion: "1.35.0", ComponentCount: 1},
		Components: []CandidateComponentReport{{
			ComponentID: component, TargetVersion: "1.3.0", ReleaseCheckpoint: "github-release-checkpoint:2026-08-28",
			SourceEvidence: []SourceEvidence{{SourceID: "fixture-source", URL: "https://github.com/prufyx/fixtures/blob/0123456789abcdef0123456789abcdef01234567/docs/reference.md", ContentDigest: testDigest, StartLine: 1, EndLine: 1}},
			EvidenceState:  CandidateReportStatus, Decision: DecisionUnknown,
		}},
		ComponentEvidenceGaps: map[string][]string{component: {}},
		KnowledgeRevision:     "revision-1", ReleaseCheckpoint: "github-release-checkpoint:2026-08-28",
		Inputs: InputDigests{ObservationProjection: testDigest, ProposedBundle: testDigest, PolicyReference: testDigest, PolicyPin: testDigest, KnowledgeIndex: testDigest, KnowledgeSources: testDigest},
		Truth:  TruthLabels{CandidateOnly: true},
	}
}

func TestCanonicalCandidateReportEqualsLegacyWriterBytes(t *testing.T) {
	report := canonicalCandidateFixture()
	want, err := CanonicalCandidateReport(report)
	if err != nil {
		t.Fatal(err)
	}
	root, err := PrepareOutputRoot(filepath.Join(t.TempDir(), "run"))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := root.WriteCandidateReport(report); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root.Path(), "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) || !bytes.HasSuffix(got, []byte{'\n'}) {
		t.Fatalf("canonical bytes differ from writer: equal=%v suffix=%v", bytes.Equal(got, want), bytes.HasSuffix(got, []byte{'\n'}))
	}
}

func TestCanonicalCandidateReportRejectsForgedAuthority(t *testing.T) {
	cases := []struct {
		name string
		edit func(*CandidateReport)
	}{
		{"aggregate safe", func(r *CandidateReport) { r.Decision = DecisionSafe }},
		{"aggregate blocked", func(r *CandidateReport) { r.Decision = DecisionBlocked }},
		{"component safe", func(r *CandidateReport) { r.Components[0].Decision = DecisionSafe }},
		{"component blocked", func(r *CandidateReport) { r.Components[0].Decision = DecisionBlocked }},
		{"wrong status", func(r *CandidateReport) { r.Status = "SAFE" }},
		{"wrong truth", func(r *CandidateReport) { r.Truth.CandidateOnly = false }},
		{"model truth", func(r *CandidateReport) { r.Truth.ModelUsed = true }},
		{"wrong schema", func(r *CandidateReport) { r.SchemaVersion = "9.9.9" }},
		{"bad digest", func(r *CandidateReport) { r.Inputs.ProposedBundle = "sha256:not-a-digest" }},
		{"too many components", func(r *CandidateReport) { r.Components = make([]CandidateComponentReport, MaxComponents+1) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report := canonicalCandidateFixture()
			tc.edit(&report)
			if _, err := CanonicalCandidateReport(report); err == nil {
				t.Fatal("forged report accepted")
			}
		})
	}
}

func TestCanonicalCandidateReportRejectsOversizedAndInvalidCardinality(t *testing.T) {
	base := canonicalCandidateFixture()
	base.GlobalEvidenceGaps = make([]string, maxReportListItems+1)
	if _, err := CanonicalCandidateReport(base); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized global gaps = %v, want ErrInvalid", err)
	}
	base = canonicalCandidateFixture()
	base.Components[0].SourceEvidence = nil
	if _, err := CanonicalCandidateReport(base); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty source evidence = %v, want ErrInvalid", err)
	}
	base = canonicalCandidateFixture()
	base.Components[0].RequirementDetails = []RequirementDetail{{Code: "CONFIGURATION_MISSING", Reason: strings.Repeat("x", 2), NextAction: "capture bounded fact"}}
	if _, err := CanonicalCandidateReport(base); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mismatched requirement detail = %v, want ErrInvalid", err)
	}
}

func TestCanonicalCandidateReportAllowsPlannerUnknownWithoutTargetEvidence(t *testing.T) {
	report := canonicalCandidateFixture()
	component := &report.Components[0]
	component.CurrentVersion = "1.3.0"
	component.TargetVersion = "1.3.0"
	component.AlreadyCurrent = true
	component.ReleaseCheckpoint = ""
	component.SourceURLs = nil
	component.SourceDigests = nil
	component.SourceEvidence = nil
	component.MissingRequirements = []string{"TARGET_UNSUPPORTED"}
	component.RequirementDetails = []RequirementDetail{{Code: "TARGET_UNSUPPORTED", Reason: "the planner could not select an exact target for this component", NextAction: "admit one supported exact target receipt for this component"}}
	if _, err := CanonicalCandidateReport(report); err != nil {
		t.Fatalf("planner UNKNOWN report rejected: %v", err)
	}
}

func TestCanonicalCandidateReportRejectsInvalidPlannerUnknownProjection(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*CandidateComponentReport)
	}{
		{"exact target has empty evidence", func(c *CandidateComponentReport) {
			c.CurrentVersion = "1.3.0"
			c.TargetVersion = "1.4.0"
			c.AlreadyCurrent = false
			c.ReleaseCheckpoint = ""
			c.SourceURLs = nil
			c.SourceDigests = nil
			c.SourceEvidence = nil
		}},
		{"planner unknown retains source URL", func(c *CandidateComponentReport) {
			c.CurrentVersion = "1.3.0"
			c.TargetVersion = "1.3.0"
			c.AlreadyCurrent = true
			c.ReleaseCheckpoint = ""
			c.SourceURLs = []string{"https://github.com/prufyx/fixtures/blob/0123456789abcdef0123456789abcdef01234567/docs/reference.md"}
			c.SourceDigests = nil
			c.SourceEvidence = nil
			c.MissingRequirements = []string{"TARGET_UNSUPPORTED"}
			c.RequirementDetails = []RequirementDetail{{Code: "TARGET_UNSUPPORTED", Reason: "the planner could not select an exact target for this component", NextAction: "admit one supported exact target receipt for this component"}}
		}},
		{"planner unknown retains source evidence", func(c *CandidateComponentReport) {
			c.CurrentVersion = "1.3.0"
			c.TargetVersion = "1.3.0"
			c.AlreadyCurrent = true
			c.ReleaseCheckpoint = ""
			c.SourceURLs = nil
			c.SourceDigests = nil
			c.SourceEvidence = []SourceEvidence{{SourceID: "fixture-source", URL: "https://github.com/prufyx/fixtures/blob/0123456789abcdef0123456789abcdef01234567/docs/reference.md", ContentDigest: testDigest, StartLine: 1, EndLine: 1}}
			c.MissingRequirements = []string{"TARGET_UNSUPPORTED"}
			c.RequirementDetails = []RequirementDetail{{Code: "TARGET_UNSUPPORTED", Reason: "the planner could not select an exact target for this component", NextAction: "admit one supported exact target receipt for this component"}}
		}},
		{"planner unknown has no stable planner requirement", func(c *CandidateComponentReport) {
			c.CurrentVersion = "1.3.0"
			c.TargetVersion = "1.3.0"
			c.AlreadyCurrent = true
			c.ReleaseCheckpoint = ""
			c.SourceURLs = nil
			c.SourceDigests = nil
			c.SourceEvidence = nil
			c.MissingRequirements = []string{"CONFIGURATION_MISSING"}
			c.RequirementDetails = []RequirementDetail{{Code: "CONFIGURATION_MISSING", Reason: "bounded explanation", NextAction: "capture bounded fact"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := canonicalCandidateFixture()
			tc.edit(&report.Components[0])
			if _, err := CanonicalCandidateReport(report); err == nil {
				t.Fatal("invalid planner UNKNOWN projection accepted")
			}
		})
	}
}
