// SPDX-License-Identifier: AGPL-3.0-only

package prometheusmode

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/currentbundle"
)

const testNowText = "2026-09-07T06:00:00Z"

type expectedVectorFile struct {
	SourceContractDigest string `json:"sourceContractDigest"`
	Aggregate            string `json:"aggregate"`
	Vectors              []struct {
		ID      string `json:"id"`
		Current struct {
			AgentMode bool `json:"agentMode"`
		} `json:"current"`
		Proposed struct {
			Image   string   `json:"image"`
			Command []string `json:"command"`
			Args    []string `json:"args"`
		} `json:"proposed"`
		Expected struct {
			CurrentMode    bool   `json:"currentMode"`
			ProposedMode   *bool  `json:"proposedMode"`
			ProposedOrigin string `json:"proposedOrigin"`
			Status         string `json:"status"`
			ReasonCode     string `json:"reasonCode"`
			Reason         string `json:"reason"`
			NextAction     string `json:"nextAction"`
		} `json:"expected"`
	} `json:"vectors"`
}

func TestExpectedVectorsMatchIndependentSourceDerivedContract(t *testing.T) {
	t.Parallel()
	raw, err := contractFiles.ReadFile("expected-vectors-v1.json")
	if err != nil || digestBytes(raw) != ExpectedVectorsDigest {
		t.Fatalf("expected vector binding: err=%v digest=%s", err, digestBytes(raw))
	}
	var file expectedVectorFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if file.SourceContractDigest != SourceContractDigest || file.Aggregate != "UNKNOWN" || len(file.Vectors) != 8 {
		t.Fatalf("vector envelope = %#v", file)
	}
	now := mustTime(t, testNowText)
	for _, vector := range file.Vectors {
		vector := vector
		t.Run(vector.ID, func(t *testing.T) {
			t.Parallel()
			current := verifiedCurrent(t, vector.Current.AgentMode, now)
			proposed := parseProposed(t, vector.Proposed.Image, vector.Proposed.Command, vector.Proposed.Args)
			report, err := Evaluate(Request{Current: current, Proposed: proposed, Now: now})
			if err != nil {
				t.Fatal(err)
			}
			if report.Assessment != file.Aggregate || report.Current.AgentMode == nil || *report.Current.AgentMode != vector.Expected.CurrentMode || report.Proposed.Origin != vector.Expected.ProposedOrigin || report.Claim.Status != vector.Expected.Status || report.Claim.ReasonCode != vector.Expected.ReasonCode || report.Claim.Reason != vector.Expected.Reason || report.Claim.NextAction != vector.Expected.NextAction {
				t.Fatalf("report semantic mismatch: %#v", report)
			}
			if !equalOptionalBool(report.Proposed.AgentMode, vector.Expected.ProposedMode) {
				t.Fatalf("proposed mode = %v, want %v", report.Proposed.AgentMode, vector.Expected.ProposedMode)
			}
			rawReport, err := MarshalReport(report)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{"prometheus.yml", "rawDigest", "proposed-digest", "/bin/sh -c"} {
				if strings.Contains(string(rawReport), forbidden) {
					t.Fatalf("report retained private/raw value %q: %s", forbidden, rawReport)
				}
			}
		})
	}
}

func TestProposedParserRejectsIntegrityAndBoundsBeforeProjection(t *testing.T) {
	t.Parallel()
	valid := proposedJSON("prom/prometheus:v3.1.0@"+ProposedImageDigest, []string{"/bin/prometheus"}, []string{"--agent"})
	cases := []struct {
		name string
		raw  []byte
		pin  string
	}{
		{name: "wrong digest", raw: valid, pin: "sha256:" + strings.Repeat("0", 64)},
		{name: "duplicate nested key", raw: []byte(`{"apiVersion":"apps/v1","kind":"Deployment","spec":{"template":{"spec":{"containers":[{"image":"prom/prometheus:v3.1.0@` + ProposedImageDigest + `","image":"prom/prometheus:v3.1.0@` + ProposedImageDigest + `"}]}}}}`), pin: ""},
		{name: "case-folded root alias", raw: bytes.Replace(valid, []byte(`"spec":`), []byte(`"Spec":`), 1), pin: ""},
		{name: "case-folded template alias", raw: bytes.Replace(valid, []byte(`"template":`), []byte(`"Template":`), 1), pin: ""},
		{name: "case-folded containers alias", raw: bytes.Replace(valid, []byte(`"containers":`), []byte(`"Containers":`), 1), pin: ""},
		{name: "case-folded image alias", raw: bytes.Replace(valid, []byte(`"image":`), []byte(`"Image":`), 1), pin: ""},
		{name: "case-folded args collision", raw: bytes.Replace(valid, []byte(`"args":["--agent"]`), []byte(`"args":["--agent"],"Args":[]`), 1), pin: ""},
		{name: "too large", raw: []byte(`{"apiVersion":"apps/v1","kind":"Deployment","padding":"` + strings.Repeat("x", maxProposedArtifactSize) + `"}`), pin: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pin := tc.pin
			if pin == "" {
				pin = digestBytes(tc.raw)
			}
			if _, err := ParseProposedArtifact(tc.raw, pin); err == nil {
				t.Fatal("malformed proposed artifact accepted")
			}
		})
	}
}

func TestProposedUnsupportedFormsRemainUnknownAndPrivateHashIsNotExported(t *testing.T) {
	t.Parallel()
	now := mustTime(t, testNowText)
	for _, tc := range []struct {
		name    string
		image   string
		command []string
		args    []string
	}{
		{name: "tag only", image: "prom/prometheus:v3.1.0", command: []string{"/bin/prometheus"}, args: []string{"--agent"}},
		{name: "unprefixed tag", image: "prom/prometheus:3.1.0@" + ProposedImageDigest, command: []string{"/bin/prometheus"}, args: []string{"--agent"}},
		{name: "digest only", image: "prom/prometheus@" + ProposedImageDigest, command: []string{"/bin/prometheus"}, args: []string{"--agent"}},
		{name: "private image", image: "registry.example.invalid/team/prometheus:v3.1.0", command: []string{"/bin/prometheus"}, args: []string{"--agent"}},
		{name: "empty explicit command", image: "prom/prometheus:v3.1.0@" + ProposedImageDigest, command: []string{}, args: []string{"--agent"}},
		{name: "null explicit command", image: "prom/prometheus:v3.1.0@" + ProposedImageDigest, command: nil, args: []string{"--agent"}},
		{name: "assigned boolean", image: "prom/prometheus:v3.1.0@" + ProposedImageDigest, command: []string{"/bin/prometheus"}, args: []string{"--agent=true"}},
		{name: "split boolean", image: "prom/prometheus:v3.1.0@" + ProposedImageDigest, command: []string{"/bin/prometheus"}, args: []string{"--agent", "true"}},
		{name: "implicit no flag", image: "prom/prometheus:v3.1.0@" + ProposedImageDigest, command: []string{"/bin/prometheus"}, args: []string{"--no-agent"}},
		{name: "duplicate boolean", image: "prom/prometheus:v3.1.0@" + ProposedImageDigest, command: []string{"/bin/prometheus"}, args: []string{"--agent", "--agent"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proposed := parseProposed(t, tc.image, tc.command, tc.args)
			report, err := Evaluate(Request{Current: verifiedCurrent(t, true, now), Proposed: proposed, Now: now})
			if err != nil {
				t.Fatal(err)
			}
			if report.Claim.Status != "UNKNOWN" || report.Proposed.AgentMode != nil {
				t.Fatalf("unsupported form result = %#v", report)
			}
		})
	}
}

func TestProposedPublicImageCandidatesBlockAmbiguousPass(t *testing.T) {
	t.Parallel()
	now := mustTime(t, testNowText)
	exact := "prom/prometheus:v3.1.0@" + ProposedImageDigest
	for _, tc := range []struct {
		name       string
		extraImage string
		init       bool
	}{
		{name: "regular host alias", extraImage: "index.docker.io/prom/prometheus:v3.1.0@" + ProposedImageDigest},
		{name: "regular unsupported tag", extraImage: "prom/prometheus:latest"},
		{name: "init host alias", extraImage: "index.docker.io/prom/prometheus:v3.1.0@" + ProposedImageDigest, init: true},
		{name: "init unprefixed tag", extraImage: "prom/prometheus:3.1.0@" + ProposedImageDigest, init: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			primary := map[string]any{"image": exact, "command": []string{"/bin/prometheus"}, "args": []string{"--agent"}}
			extra := map[string]any{"image": tc.extraImage}
			pod := map[string]any{"containers": []any{primary}}
			if tc.init {
				pod["initContainers"] = []any{extra}
			} else {
				pod["containers"] = []any{primary, extra}
			}
			document := map[string]any{
				"apiVersion": "apps/v1", "kind": "Deployment",
				"spec": map[string]any{"template": map[string]any{"spec": pod}},
			}
			raw, _ := json.Marshal(document)
			proposed, err := ParseProposedArtifact(raw, digestBytes(raw))
			if err != nil {
				t.Fatal(err)
			}
			report, err := Evaluate(Request{Current: verifiedCurrent(t, true, now), Proposed: proposed, Now: now})
			if err != nil || report.Claim.Status != "UNKNOWN" || report.Proposed.AgentMode != nil || report.Proposed.ImageIdentityState != "ambiguous_container_role" || report.Proposed.Origin != "unknown_role" {
				t.Fatalf("report=%#v error=%v", report, err)
			}
		})
	}
}

func TestProposedUnrelatedSidecarDoesNotCreatePrometheusAmbiguity(t *testing.T) {
	t.Parallel()
	now := mustTime(t, testNowText)
	document := map[string]any{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{
			map[string]any{"image": "prom/prometheus:v3.1.0@" + ProposedImageDigest, "command": []string{"/bin/prometheus"}, "args": []string{"--agent"}},
			map[string]any{"image": "busybox:1.36", "args": []string{"sleep", "3600"}},
		}}}},
	}
	raw, _ := json.Marshal(document)
	proposed, err := ParseProposedArtifact(raw, digestBytes(raw))
	if err != nil {
		t.Fatal(err)
	}
	report, err := Evaluate(Request{Current: verifiedCurrent(t, true, now), Proposed: proposed, Now: now})
	if err != nil || report.Claim.Status != "PASS" || report.Proposed.AgentMode == nil || !*report.Proposed.AgentMode {
		t.Fatalf("report=%#v error=%v", report, err)
	}
}

func TestProposedOmittedDefaultsAndExplicitEmptyArgs(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		includeArgs bool
		origin      string
	}{
		{name: "omitted command and args", origin: "reviewed_image_default"},
		{name: "omitted command and empty args", includeArgs: true, origin: "explicit_arguments_without_agent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			container := map[string]any{"image": "prom/prometheus:v3.1.0@" + ProposedImageDigest}
			if tc.includeArgs {
				container["args"] = []any{}
			}
			document := map[string]any{
				"apiVersion": "apps/v1", "kind": "Deployment",
				"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{container}}}},
			}
			raw, _ := json.Marshal(document)
			proposed, err := ParseProposedArtifact(raw, digestBytes(raw))
			if err != nil {
				t.Fatal(err)
			}
			report, err := Evaluate(Request{Current: verifiedCurrent(t, false, mustTime(t, testNowText)), Proposed: proposed, Now: mustTime(t, testNowText)})
			if err != nil || report.Proposed.AgentMode == nil || *report.Proposed.AgentMode || report.Proposed.Origin != tc.origin || report.Claim.Status != "PASS" {
				t.Fatalf("report=%#v error=%v", report, err)
			}
		})
	}
}

func TestEvaluationRejectsCallerTimeOutsideFreshnessAndReportMutation(t *testing.T) {
	t.Parallel()
	now := mustTime(t, testNowText)
	current := verifiedCurrent(t, true, now)
	proposed := parseProposed(t, "prom/prometheus:v3.1.0@"+ProposedImageDigest, []string{"/bin/prometheus"}, []string{"--agent"})
	stale, err := Evaluate(Request{Current: current, Proposed: proposed, Now: now.Add(2 * time.Hour)})
	if err != nil || stale.Claim.Status != "UNKNOWN" || stale.Current.ReasonCode != "CURRENT_EVIDENCE_STALE_OR_FUTURE" {
		t.Fatalf("stale caller time report=%#v error=%v", stale, err)
	}
	report, err := Evaluate(Request{Current: current, Proposed: proposed, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	report.Claim.Status = "UNKNOWN"
	if _, err := MarshalReport(report); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("mutated report error = %v", err)
	}
}

func TestValidButIncompleteCurrentEvidenceRemainsUnknown(t *testing.T) {
	t.Parallel()
	now := mustTime(t, testNowText)
	proposed := parseProposed(t, "prom/prometheus:v3.1.0@"+ProposedImageDigest, []string{"/bin/prometheus"}, []string{"--agent"})
	for _, tc := range []struct {
		name   string
		mutate func(*currentbundle.CurrentBundle)
		code   string
	}{
		{name: "old registry", code: "CURRENT_PROMETHEUS_MODE_NOT_ADMITTED", mutate: func(bundle *currentbundle.CurrentBundle) {
			bundle.PredicateRegistryVersion = currentbundle.PredicateRegistryVersion
			bundle.Adapters[0].Version = "current-bundle-v2"
			bundle.Planes.Observed.Components[0].Predicates = nil
		}},
		{name: "missing component", code: "CURRENT_PROMETHEUS_COMPONENT_UNRESOLVED", mutate: func(bundle *currentbundle.CurrentBundle) {
			bundle.Planes.Observed.Components = nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base, err := verifiedCurrent(t, true, now).Artifact()
			if err != nil {
				t.Fatal(err)
			}
			bundle := base.Bundle
			tc.mutate(&bundle)
			current := verifiedBundle(t, bundle)
			report, err := Evaluate(Request{Current: current, Proposed: proposed, Now: now})
			if err != nil || report.Claim.Status != "UNKNOWN" || report.Current.ReasonCode != tc.code {
				t.Fatalf("report=%#v err=%v", report, err)
			}
		})
	}
}

func TestCurrentWorkloadCoverageOmissionsAreScoped(t *testing.T) {
	t.Parallel()
	now := mustTime(t, testNowText)
	proposed := parseProposed(t, "prom/prometheus:v3.1.0@"+ProposedImageDigest, []string{"/bin/prometheus"}, []string{"--agent"})
	base, err := verifiedCurrent(t, true, now).Artifact()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		omission   currentbundle.Omission
		wantStatus string
		wantCode   string
	}{
		{
			name:       "statefulset read failed",
			omission:   currentbundle.Omission{Code: "COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_AUTHORIZATION_RBAC_FORBIDDEN", Scope: "observation", Sources: []string{base.Bundle.Sources[0].Digest}, Reason: "bounded fixture", RequiredForEvaluation: true, SourceFile: "statefulset-images.json", Count: 1},
			wantStatus: "UNKNOWN", wantCode: "CURRENT_PROMETHEUS_WORKLOAD_COVERAGE_INCOMPLETE",
		},
		{
			name:       "unrelated cert manager omission",
			omission:   currentbundle.Omission{Code: "COMPONENT_CONFIGURATION_HEALTH_UNAVAILABLE", Scope: "observation", Sources: []string{base.Bundle.Sources[0].Digest}, Reason: "bounded fixture", RequiredForEvaluation: true, SourceFile: "cert-manager-derived-predicates", Count: 1},
			wantStatus: "PASS",
		},
		{
			name:       "daemonset read failure is outside Prometheus workload kinds",
			omission:   currentbundle.Omission{Code: "COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED", Scope: "observation", Sources: []string{base.Bundle.Sources[0].Digest}, Reason: "bounded fixture", RequiredForEvaluation: true, SourceFile: "daemonset-images.json", Count: 1},
			wantStatus: "PASS",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bundle := base.Bundle
			bundle.Omissions = append([]currentbundle.Omission(nil), tc.omission)
			current := verifiedBundle(t, bundle)
			report, err := Evaluate(Request{Current: current, Proposed: proposed, Now: now})
			if err != nil || report.Claim.Status != tc.wantStatus || report.Current.ReasonCode != tc.wantCode {
				t.Fatalf("report=%#v error=%v", report, err)
			}
		})
	}
}

func TestReadProposedArtifactRequiresPrivateRegularFile(t *testing.T) {
	t.Parallel()
	raw := proposedJSON("prom/prometheus:v3.1.0@"+ProposedImageDigest, []string{"/bin/prometheus"}, []string{"--agent"})
	path := filepath.Join(t.TempDir(), "proposed.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProposedArtifact(path, digestBytes(raw)); err == nil {
		t.Fatal("group-readable proposed input accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProposedArtifact(path, digestBytes(raw)); err != nil {
		t.Fatalf("private proposed input rejected: %v", err)
	}
}

func TestProposedReadErrorClassificationPreservesIntegrity(t *testing.T) {
	if err := classifyProposedReadError(errors.Join(errors.New("descriptor identity changed"), currentbundle.ErrIntegrity)); !errors.Is(err, ErrIntegrity) || errors.Is(err, ErrIO) {
		t.Fatalf("integrity classification=%v", err)
	}
	if err := classifyProposedReadError(errors.Join(errors.New("local open failed"), currentbundle.ErrInvalid)); !errors.Is(err, ErrIO) || errors.Is(err, ErrIntegrity) {
		t.Fatalf("local admission classification=%v", err)
	}
}

func parseProposed(t *testing.T, image string, command, args []string) VerifiedProposedArtifact {
	t.Helper()
	raw := proposedJSON(image, command, args)
	verified, err := ParseProposedArtifact(raw, digestBytes(raw))
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

func proposedJSON(image string, command, args []string) []byte {
	container := map[string]any{"name": "prometheus", "image": image, "command": command, "args": args}
	document := map[string]any{
		"apiVersion": "apps/v1", "kind": "Deployment", "metadata": map[string]any{"name": "private-workload-name"},
		"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{container}}}},
	}
	raw, _ := json.Marshal(document)
	return raw
}

func verifiedCurrent(t *testing.T, agentMode bool, now time.Time) currentbundle.VerifiedArtifact {
	t.Helper()
	sourceDigest := "sha256:" + strings.Repeat("a", 64)
	revisionBytes, _ := json.Marshal([]string{sourceDigest})
	revision := currentbundle.DigestBytes(revisionBytes)
	source := currentbundle.SourceRef{PathClass: "context/projection", Digest: sourceDigest}
	bundle := currentbundle.CurrentBundle{
		APIVersion: currentbundle.APIVersion, Kind: currentbundle.Kind, Schema: currentbundle.Schema,
		PredicateRegistryVersion: currentbundle.PredicateRegistryVersionV2, OmissionRegistryVersion: currentbundle.OmissionRegistryVersion,
		Revision: revision, CapturedAt: now.Add(-time.Hour).Format(time.RFC3339Nano),
		Target:    currentbundle.TargetIdentity{Fingerprint: revision, State: "exact"},
		Assurance: currentbundle.AssuranceState{Class: currentbundle.Assurance},
		Environment: currentbundle.Environment{
			Provider: currentbundle.FieldValue{State: "unknown"}, Distribution: currentbundle.FieldValue{State: "unknown"}, Kubernetes: currentbundle.FieldValue{State: "unknown"},
			NodeOS: currentbundle.FieldValue{State: "unknown"}, Kernel: currentbundle.FieldValue{State: "unknown"}, Architecture: currentbundle.FieldValue{State: "unknown"}, ContainerRuntime: currentbundle.FieldValue{State: "unknown"},
		},
		Planes: currentbundle.EvidencePlanes{
			Observed: currentbundle.EvidencePlane{Status: "supplied", Components: []currentbundle.CanonicalComponent{{
				ComponentID: ComponentID, Version: currentbundle.VersionIdentity{State: "exact", Value: CurrentVersion}, Artifact: currentbundle.ArtifactIdentity{State: "exact", Value: ComponentID}, Roles: []string{"server"}, Sources: []currentbundle.SourceRef{source},
				Predicates: []currentbundle.CanonicalPredicate{
					{ID: AgentModePredicateID, State: "observed", SourceRole: "server", EvidenceClass: currentEvidenceClass, Value: mustJSON(agentMode), Sources: []currentbundle.SourceRef{source}},
					{ID: ImageDigestPredicateID, State: "observed", SourceRole: "server", EvidenceClass: currentEvidenceClass, Value: mustJSON(CurrentImageDigest), Sources: []currentbundle.SourceRef{source}},
				},
			}}},
			Declared: currentbundle.EvidencePlane{Status: "not_supplied"}, Derived: currentbundle.EvidencePlane{Status: "not_derived"}, Unknown: currentbundle.UnknownPlane{Status: "explicit"},
		},
		Sources:   []currentbundle.SourceBinding{{PathClass: "context/projection", Digest: sourceDigest}},
		Adapters:  []currentbundle.AdapterBinding{{Name: "observation-to-current-bundle", Version: "current-bundle-v3"}},
		Collector: currentbundle.CollectorBinding{Profile: "local-observation"},
		Freshness: currentbundle.FreshnessBinding{State: "fresh", CapturedAt: now.Add(-time.Hour).Format(time.RFC3339Nano), PolicyID: "community-prometheus-mode-explicit-age-v1", MaxAgeSeconds: 5400},
	}
	return verifiedBundle(t, bundle)
}

func verifiedBundle(t *testing.T, bundle currentbundle.CurrentBundle) currentbundle.VerifiedArtifact {
	t.Helper()
	digest, err := currentbundle.Digest(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundle.BundleDigest = digest
	raw, err := currentbundle.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "current.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	verified, err := currentbundle.ReadVerifiedArtifact(path)
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

func mustJSON(value any) json.RawMessage {
	raw, _ := json.Marshal(value)
	return raw
}

func mustTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func equalOptionalBool(left, right *bool) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
