// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestWithPreparationOmissionsKeepsSealedBytes(t *testing.T) {
	t.Parallel()
	sealed := `{"schema":"x","check":{"claims":[]}}`
	omissions := []string{"ONLY_THE_LISTED_REMOVED_KEYS_INSPECTED_NOT_THEIR_VALUES_OR_ANY_OTHER_SETTING", "SETTING_MAY_BE_REMOVED_BY_TARGET_NO_RULE_COVERS_IT:opensearch.experimental.feature.x.enabled"}
	got := withPreparationOmissions([]byte(sealed), omissions)
	if !strings.HasPrefix(string(got), sealed[:len(sealed)-1]+",") {
		t.Fatalf("sealed bytes changed: %s", got)
	}
	var decoded struct {
		Omissions []string `json:"preparationOmissions"`
	}
	if err := json.Unmarshal(got, &decoded); err != nil || len(decoded.Omissions) != 2 || decoded.Omissions[1] != omissions[1] {
		t.Fatalf("omissions=%v err=%v in %s", decoded.Omissions, err, got)
	}
	if string(withPreparationOmissions([]byte(sealed), nil)) != sealed {
		t.Fatal("empty omissions changed the report")
	}
}

func TestPreparationQualificationsNameEveryOmission(t *testing.T) {
	t.Parallel()
	lines := preparationQualifications([]string{"A", "SETTING_MAY_BE_REMOVED_BY_TARGET_NO_RULE_COVERS_IT:k"})
	if len(lines) != 2 || lines[0] != "input qualification: A" || !strings.HasSuffix(lines[1], ":k") {
		t.Fatalf("lines=%v", lines)
	}
}
