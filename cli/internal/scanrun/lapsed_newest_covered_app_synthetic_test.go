// SPDX-License-Identifier: AGPL-3.0-only

//go:build prufyx_synthetic_knowledge

package scanrun

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// Run with: go test -tags prufyx_synthetic_knowledge -run NewestCovered ./internal/scanrun/

const strimziKey = "pkg:github/strimzi/strimzi-kafka-operator"

// strimziRecords are the embedded pack's records with a current reviewed path
// policy added for strimzi (newest-covered resolves an application only with
// one) and edit applied to its newest line review.
func strimziRecords(t *testing.T, edit newestRecordEdit) cncfcheck.SyntheticRecords {
	t.Helper()
	raw := embeddedPack(t)
	if edit != nil {
		raw = editRecords(t, raw, "strimzi", strimziKey, "1.3", map[string]newestRecordEdit{"lineAttestations": edit}, false)
	}
	var pack struct {
		LineAttestations json.RawMessage  `json:"lineAttestations"`
		PathPolicies     []map[string]any `json:"pathPolicies"`
		ServedAPIs       json.RawMessage  `json:"servedAPIs"`
	}
	if err := json.Unmarshal(raw, &pack); err != nil {
		t.Fatal(err)
	}
	policy := map[string]any{}
	for key, value := range pack.PathPolicies[0] {
		policy[key] = value
	}
	policy["component"] = strimziKey
	policies, err := json.Marshal(append(pack.PathPolicies, policy))
	if err != nil {
		t.Fatal(err)
	}
	return cncfcheck.SyntheticRecords{LineAttestations: pack.LineAttestations, PathPolicies: policies, ServedAPIs: pack.ServedAPIs}
}

func scanNewestStrimzi(t *testing.T, edit newestRecordEdit) Result {
	t.Helper()
	restore, err := cncfcheck.UseSyntheticRecords(nil, nil, strimziRecords(t, edit))
	if err != nil {
		t.Fatalf("records are not admissible: %v", err)
	}
	t.Cleanup(restore)
	knowledge, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	_, paths := files(t, map[string]string{"applyset.yaml": cronjobV1})
	request, err := ParseArgs(args(paths, "--from", "strimzi=1.1.0"))
	if err != nil {
		t.Fatal(err)
	}
	request.NewestCovered = []string{"strimzi"}
	at, err := time.Parse(time.RFC3339, newestCoveredAt)
	if err != nil {
		t.Fatal(err)
	}
	request.Now = at
	result, err := Run(request, Options{Knowledge: knowledge, Build: &testBuild, Clock: func() time.Time { return at }})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// An application whose newest line review expired is planned to the older line
// only with that line named.
func TestNewestCoveredAppNamesTheLapsedNewerLine(t *testing.T) {
	want := scanreport.NewGap("strimzi", nil, scanreport.GapNewestCoveredOlderLine, "strimzi", "1.2", "1.3")
	named := func(report scanreport.Report) int {
		count := 0
		for _, gap := range report.Gaps {
			if gap.Component == "strimzi" && gap.Detail == want.Detail {
				count++
			}
		}
		return count
	}
	t.Run("control", func(t *testing.T) {
		result := scanNewestStrimzi(t, nil)
		if len(result.Report.Paths) != 1 || result.Report.Paths[0].To != "1.3.0" || named(result.Report) != 0 {
			t.Fatalf("paths %+v gaps %+v", result.Report.Paths, result.Report.Gaps)
		}
	})
	t.Run("review expired", func(t *testing.T) {
		result := scanNewestStrimzi(t, lapseExpired)
		if len(result.Report.Paths) != 1 || result.Report.Paths[0].To != "1.2.0" {
			t.Fatalf("paths %+v gaps %+v", result.Report.Paths, result.Report.Gaps)
		}
		if result.Exit != scanreport.ExitUnknown || named(result.Report) != 1 {
			t.Fatalf("exit %d gaps %+v", result.Exit, result.Report.Gaps)
		}
	})
	// KNOWN LIMIT, pinned so a change is noticed: this is the binary's own
	// knowledge, and with the review removed no record or rule names 1.3.
	t.Run("review removed", func(t *testing.T) {
		result := scanNewestStrimzi(t, lapseRemoved)
		if len(result.Report.Paths) != 1 || result.Report.Paths[0].To != "1.2.0" || named(result.Report) != 0 {
			t.Fatalf("known limit changed: paths %+v gaps %+v", result.Report.Paths, result.Report.Gaps)
		}
	})
}
