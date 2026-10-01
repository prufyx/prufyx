// SPDX-License-Identifier: AGPL-3.0-only

package certmanagervalues

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func requestFor(artifact Artifact) Request {
	return Request{Values: artifact, From: CurrentVersion, To: TargetVersion}
}
func parse(t *testing.T, value string) Artifact {
	t.Helper()
	artifact, err := ParseArtifact([]byte(value), "")
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

func TestCuratedPredicateVectors(t *testing.T) {
	tests := []struct {
		name, raw, status, code string
		matches                 int
	}{
		{"target-port-string", `{"prometheus":{"servicemonitor":{"targetPort":"custom"}}}`, "BLOCKED", "CERT_MANAGER_REMOVED_MONITOR_VALUE_PRESENT", 1},
		{"path-null", `{"prometheus":{"servicemonitor":{"path":null}}}`, "BLOCKED", "CERT_MANAGER_REMOVED_MONITOR_VALUE_PRESENT", 1},
		{"pod-path-false", `{"prometheus":{"podmonitor":{"path":false}}}`, "BLOCKED", "CERT_MANAGER_REMOVED_MONITOR_VALUE_PRESENT", 1},
		{"unknown-nested-outside-rule", `{"prometheus":{"servicemonitor":{"unknownNested":false}}}`, "PASS", "CERT_MANAGER_REMOVED_MONITOR_VALUES_ABSENT", 0},
		{"clean", `{"prometheus":{"servicemonitor":{"enabled":true}}}`, "PASS", "CERT_MANAGER_REMOVED_MONITOR_VALUES_ABSENT", 0},
		{"ambiguous", `{"prometheus":{"servicemonitor":null}}`, "UNKNOWN", "CERT_MANAGER_MONITOR_VALUES_SHAPE_UNRESOLVED", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report, err := Evaluate(requestFor(parse(t, tt.raw)))
			if err != nil {
				t.Fatal(err)
			}
			if report.Assessment != "UNKNOWN" || report.Claim.Status != tt.status || report.Claim.ReasonCode != tt.code || len(report.MatchedPaths) != tt.matches {
				t.Fatalf("report=%#v", report)
			}
		})
	}
}

func TestParserRejectsDuplicateTrailingDepthAndDigestMismatch(t *testing.T) {
	for _, raw := range []string{`{"prometheus":{},"prometheus":{}}`, `{} {}`, strings.Repeat(`{"x":`, maxDepth+2) + `0` + strings.Repeat(`}`, maxDepth+2)} {
		if _, err := ParseArtifact([]byte(raw), ""); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted %q: %v", raw, err)
		}
	}
	if _, err := ParseArtifact([]byte(`{}`), "sha256:"+strings.Repeat("0", 64)); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("digest mismatch=%v", err)
	}
}

func TestReportReplayIsDeterministicAndDetectsDrift(t *testing.T) {
	artifact := parse(t, `{"prometheus":{"servicemonitor":{"path":"/custom"}}}`)
	report, err := Evaluate(requestFor(artifact))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalReport(report)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Replay(requestFor(artifact), append(append([]byte(nil), raw...), '\n')); err != nil {
		t.Fatal(err)
	}
	drift := append([]byte(nil), raw...)
	drift[len(drift)-2] ^= 1
	if _, err := Replay(requestFor(artifact), drift); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("drift=%v", err)
	}
	second, _ := Evaluate(requestFor(artifact))
	secondRaw, _ := MarshalReport(second)
	if !bytes.Equal(raw, secondRaw) {
		t.Fatal("output is not deterministic")
	}
}

func TestReadArtifactRejectsPublicModeSymlinkAndFIFO(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file contract")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "values.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadArtifact(path, ""); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadArtifact(path, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("public mode=%v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadArtifact(link, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("symlink=%v", err)
	}
	fifo := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadArtifact(fifo, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("fifo=%v", err)
	}
}

func TestChartDigestAssertionsFailClosed(t *testing.T) {
	req := requestFor(parse(t, `{}`))
	req.TargetChartDigest = "sha256:" + strings.Repeat("0", 64)
	if _, err := Evaluate(req); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("target assertion=%v", err)
	}
}

func TestIndependentResearchVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/expected-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	const independentlyAuthoredSHA256 = "b38cb213fbb68dc7bbff5490f96e1cf3d5de0a1604713ecdfa1502e6d985f80a"
	if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != independentlyAuthoredSHA256 {
		t.Fatalf("independent vector copy digest=%s want=%s", got, independentlyAuthoredSHA256)
	}
	var fixture struct {
		Vectors []struct {
			ID               string          `json:"id"`
			Values           json.RawMessage `json:"values"`
			SchemaValidation string          `json:"schemaValidation"`
			ExpectedClaim    string          `json:"expectedClaim"`
			ReasonCode       string          `json:"reasonCode"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, vector := range fixture.Vectors {
		if bytes.Equal(bytes.TrimSpace(vector.Values), []byte("null")) {
			continue
		}
		t.Run(vector.ID, func(t *testing.T) {
			artifact, err := ParseArtifact(vector.Values, "")
			if err != nil {
				t.Fatal(err)
			}
			req := requestFor(artifact)
			req.SchemaValidation = vector.SchemaValidation
			report, err := Evaluate(req)
			if err != nil {
				t.Fatal(err)
			}
			if report.Claim.Status != vector.ExpectedClaim || report.Claim.ReasonCode != vector.ReasonCode {
				t.Fatalf("claim=%#v", report.Claim)
			}
		})
	}
}

func TestUnsupportedWellFormedTransitionIsUnknownWithoutEcho(t *testing.T) {
	req := requestFor(parse(t, `{}`))
	req.To = "1.22.0"
	report, err := Evaluate(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalReport(report)
	if err != nil {
		t.Fatal(err)
	}
	if report.Claim.Status != "UNKNOWN" || report.Claim.ReasonCode != "CERT_MANAGER_TRANSITION_NOT_REVIEWED" || bytes.Contains(raw, []byte("1.22.0")) {
		t.Fatalf("report=%s", raw)
	}
	req.To = "not-a-version"
	if _, err := Evaluate(req); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid version=%v", err)
	}
}

func TestLatestPatchTransitionUsesExactOCIChartIdentity(t *testing.T) {
	req := Request{Values: parse(t, `{"prometheus":{"servicemonitor":{"path":"/custom"}}}`), From: CurrentVersion, To: LatestTargetVersion}
	req.TargetChartDigest = LatestTargetChartDigest
	report, err := Evaluate(req)
	if err != nil {
		t.Fatal(err)
	}
	if report.Claim.Status != "BLOCKED" || report.Transition.ReviewedTo != LatestTargetVersion || report.Transition.TargetChartManifestDigest != LatestTargetChartDigest || report.Inputs.KnowledgeRevisionDigest != LatestSourceContractDigest {
		t.Fatalf("latest report=%#v", report)
	}
	if report.Question != "Does the exact proposed merged values object contain any of the three curated monitoring keys rejected by the target cert-manager 1.21.2 chart?" {
		t.Fatalf("question=%q", report.Question)
	}
}

func TestLatestTargetHasFiveExactOriginChartIdentities(t *testing.T) {
	for _, test := range []struct {
		from, digest string
	}{
		{"1.20.3", CurrentChartDigest},
		{"1.19.6", "sha256:5d95e81072636335b7b43fc2517e5336b93b77d41a4c87cbaf291783f03b4a0f"},
		{"1.18.6", "sha256:2c26b0824142c0aec34a78c13b8fbc9bd267c2093f123e4c73cbae2a2e4ab6d3"},
		{"1.17.4", "sha256:d65154bfa18458102b92b412a128063f02324853c5ea202c02bd00239039c47d"},
		{"1.16.5", "sha256:5d5a2739b30525d92c05d53b75744d43fd00f23e4c4b8e526a9126d2e949e02e"},
	} {
		t.Run(test.from, func(t *testing.T) {
			base := Request{From: test.from, To: LatestTargetVersion, CurrentChartDigest: test.digest, TargetChartDigest: LatestTargetChartDigest}
			pass := base
			pass.Values = parse(t, `{}`)
			report, err := Evaluate(pass)
			if err != nil || report.Claim.Status != "PASS" || report.Transition.ReviewedFrom != test.from || report.Transition.CurrentChartManifestDigest != test.digest {
				t.Fatalf("report=%#v err=%v", report, err)
			}
			blocked := base
			blocked.Values = parse(t, `{"prometheus":{"servicemonitor":{"path":"/custom"}}}`)
			if report, err = Evaluate(blocked); err != nil || report.Claim.Status != "BLOCKED" {
				t.Fatalf("blocked report=%#v err=%v", report, err)
			}
			unknown := base
			unknown.Values = parse(t, `{"prometheus":[]}`)
			if report, err = Evaluate(unknown); err != nil || report.Claim.Status != "UNKNOWN" {
				t.Fatalf("unknown report=%#v err=%v", report, err)
			}
			wrongCurrent := pass
			wrongCurrent.CurrentChartDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
			if _, err = Evaluate(wrongCurrent); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("wrong current digest=%v", err)
			}
			wrongPair := pass
			wrongPair.To = "1.21.3"
			wrongPair.CurrentChartDigest = ""
			wrongPair.TargetChartDigest = ""
			if report, err = Evaluate(wrongPair); err != nil || report.Claim.Status != "UNKNOWN" || report.Transition.DeclaredTransitionState != "unsupported" {
				t.Fatalf("wrong pair report=%#v err=%v", report, err)
			}
		})
	}
}

func TestLatestRoutesPreserveHistoricalTransition(t *testing.T) {
	req := Request{Values: parse(t, `{"prometheus":{"servicemonitor":{"path":"/custom"}}}`), From: CurrentVersion, To: TargetVersion, CurrentChartDigest: CurrentChartDigest, TargetChartDigest: TargetChartDigest}
	report, err := Evaluate(req)
	if err != nil || report.Claim.Status != "BLOCKED" || report.Transition.ReviewedFrom != CurrentVersion || report.Transition.ReviewedTo != TargetVersion || report.Inputs.KnowledgeRevisionDigest != SourceContractDigest {
		t.Fatalf("legacy report=%#v err=%v", report, err)
	}
}

func TestLatestPatchTransitionRejectsWrongChartIdentity(t *testing.T) {
	req := Request{Values: parse(t, `{}`), From: CurrentVersion, To: LatestTargetVersion, TargetChartDigest: TargetChartDigest}
	if _, err := Evaluate(req); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("wrong latest target digest=%v", err)
	}
}
