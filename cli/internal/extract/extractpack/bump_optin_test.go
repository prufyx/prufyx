// SPDX-License-Identifier: AGPL-3.0-only

package extractpack

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// A merge never moves a pack to a level it must declare itself, even when the
// loader would admit the pack only there.
func TestBumpNeverDeclaresAnOptInLevel(t *testing.T) {
	t.Parallel()
	head := &Pack{Members: map[string]json.RawMessage{"schema": json.RawMessage(`"prufyx.io/cncf-source-rule-pack/v1alpha15"`)}}
	var tried []string
	admit := func(_ string, raw []byte) error {
		tried = append(tried, string(raw))
		if strings.Contains(string(raw), `cncf-source-rule-pack/v1alpha16"`) {
			return nil
		}
		return errors.New("refused")
	}
	if out, err := bumpToAdmitted(head, "rules.json", admit, 3, errors.New("first")); !errors.Is(err, ErrAdmission) || out != nil {
		t.Fatalf("out=%s err=%v", out, err)
	}
	if len(tried) != 2 {
		t.Fatalf("%d levels tried, want 2", len(tried))
	}
}
