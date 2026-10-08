// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/packparity"
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
	concrete := func(index int, kind packparity.Kind) string {
		id := fmt.Sprintf("kubernetes.synthetic-%02d-%s", index, kind)
		switch kind {
		case packparity.Pass:
			return syntheticKubernetesRule(id, "require_component_version", "REVIEWED_SOURCE_CONSTRAINT", "keep the reviewed version", `,"dependency":{"side":"proposed","component":"`+noticeComponent+`","comparison":"gte","version":"1.37.0"}`, reviewed, until)
		case packparity.Blocked:
			return syntheticKubernetesRule(id, "forbid_target_version", "REVIEWED_SOURCE_CONSTRAINT", "plan a reviewed route", "", reviewed, until)
		case packparity.Unsupported:
			return syntheticSupportRule(id, "1.38.0")
		case packparity.Supported:
			return syntheticSupportRule(id, "1.37.0")
		}
		return syntheticNoticeRule(id, reviewed, until)
	}
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	inputRaw := noticeInput()
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
		})
	}
}
