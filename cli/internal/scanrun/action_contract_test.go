// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// scripts/action/run.sh fails the step when the JSON report carries a gap
// whose reason is API_VERSION_NOT_SERVED. This pins the real serializer to
// that contract: the field name and the exact value the script looks for.
func TestScanJSONCarriesTheReasonTheActionChecks(t *testing.T) {
	knowledge := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current"})
	_, paths := files(t, map[string]string{"applyset.yaml": "apiVersion: batch/v1beta1\nkind: CronJob\nmetadata: {name: a}\n"})
	result := mustScan(t, knowledge, args(paths, "--from", "kubernetes=1.25.3", "--to", "kubernetes=1.30.4")...)
	if result.Exit != scanreport.ExitUnknown {
		t.Fatalf("exit %d, want UNKNOWN", result.Exit)
	}
	raw, err := scanreport.MarshalJSON(result.Report)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"reason":"API_VERSION_NOT_SERVED"`) {
		t.Fatalf("report lacks the exact string the Action greps: %s", raw)
	}
	var decoded struct {
		Gaps []struct {
			Reason string `json:"reason"`
		} `json:"gaps"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, gap := range decoded.Gaps {
		found = found || gap.Reason == "API_VERSION_NOT_SERVED"
	}
	if !found {
		t.Fatalf("no gaps[].reason == API_VERSION_NOT_SERVED in %s", raw)
	}
}
