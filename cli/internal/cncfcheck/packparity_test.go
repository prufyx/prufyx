// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/testsupport/packparity"
)

// TestPackParityTable runs the table both rule packs share: the same abstract
// rule sets give the same claim statuses and exit code here and under the
// community-project pack (see projectcheck's parity test).
func TestPackParityTable(t *testing.T) {
	b, err := load()
	if err != nil {
		t.Fatal(err)
	}
	const reviewed, until = "2026-09-20T00:00:00Z", "2026-12-19T00:00:00Z"
	// The rules are written against the shared synthetic pair (noticeInput,
	// syntheticKubernetesRule): PASS and the supported combination require the
	// proposed version itself, UNSUPPORTED the next minor line, so the table
	// follows the fixture when the pair moves.
	inputRaw := noticeInput()
	proposed := proposedVersion(t, inputRaw)
	next := nextMinor(t, proposed)
	concrete := func(index int, kind packparity.Kind) string {
		id := fmt.Sprintf("kubernetes.synthetic-%02d-%s", index, kind)
		switch kind {
		case packparity.Pass:
			return syntheticKubernetesRule(id, "require_component_version", "REVIEWED_SOURCE_CONSTRAINT", "keep the reviewed version", `,"dependency":{"side":"proposed","component":"`+noticeComponent+`","comparison":"gte","version":"`+proposed+`"}`, reviewed, until)
		case packparity.Blocked:
			return syntheticKubernetesRule(id, "forbid_target_version", "REVIEWED_SOURCE_CONSTRAINT", "plan a reviewed route", "", reviewed, until)
		case packparity.Unsupported:
			return syntheticSupportRule(id, next)
		case packparity.Supported:
			return syntheticSupportRule(id, proposed)
		}
		return syntheticNoticeRule(id, reviewed, until)
	}
	// The clock the sibling claim-exit tests use: one at which both
	// generations of the embedded Kubernetes rules are current.
	now := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	input, err := constraintengine.ParseInput(inputRaw, b.registry)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range packparity.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			raw := make([]json.RawMessage, 0, len(tc.Rules))
			for index, kind := range tc.Rules {
				raw = append(raw, json.RawMessage(concrete(index, kind)))
			}
			rules, err := b.parseRules(raw)
			if err != nil {
				t.Fatal(err)
			}
			report, err := b.report("kubernetes", "", false, input, rules, inputRaw, now)
			if err != nil {
				t.Fatal(err)
			}
			claims := make([]packparity.Claim, 0, len(report.Check.Claims))
			for _, claim := range report.Check.Claims {
				claims = append(claims, packparity.Claim{Status: claim.Status, Notice: claim.IsVerdictNeutral()})
			}
			verdicts, notices := packparity.Statuses(claims)
			if got := ClaimExit(report); got != tc.Exit || fmt.Sprint(verdicts) != fmt.Sprint(tc.Verdicts) || notices != tc.Notices {
				t.Fatalf("exit=%d verdicts=%v notices=%d, want exit=%d verdicts=%v notices=%d", got, verdicts, notices, tc.Exit, tc.Verdicts, tc.Notices)
			}
			if _, err := MarshalReport(report); err != nil {
				t.Fatalf("report not publishable: %v", err)
			}
			if report.Assessment != "UNKNOWN" {
				t.Fatalf("assessment=%s", report.Assessment)
			}
		})
	}
}

// proposedVersion is the proposed Kubernetes version of the synthetic input.
func proposedVersion(t *testing.T, inputRaw []byte) string {
	t.Helper()
	var input struct {
		Proposed struct {
			Components []struct {
				Component string `json:"component"`
				Version   string `json:"version"`
			} `json:"components"`
		} `json:"proposed"`
	}
	if err := json.Unmarshal(inputRaw, &input); err != nil {
		t.Fatal(err)
	}
	for _, component := range input.Proposed.Components {
		if component.Component == noticeComponent {
			return component.Version
		}
	}
	t.Fatalf("synthetic input has no proposed %s", noticeComponent)
	return ""
}

// nextMinor is the first version of the minor line after version.
func nextMinor(t *testing.T, version string) string {
	t.Helper()
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		t.Fatalf("version %q is not major.minor.patch", version)
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		t.Fatalf("version %q: %v", version, err)
	}
	return parts[0] + "." + strconv.Itoa(minor+1) + ".0"
}
