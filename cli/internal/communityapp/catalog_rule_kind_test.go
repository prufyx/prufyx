// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/checkroutemetadata"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// TestCatalogListingShowsRuleKind: a notice or a support range is not listed
// as an ordinary check, and a plain verdict rule prints exactly as before.
func TestCatalogListingShowsRuleKind(t *testing.T) {
	for kind, want := range map[string]string{
		constraintengine.RuleKindOneWayNotice: "rule kind: one_way_notice (informational one-way notice; never a verdict",
		constraintengine.RuleKindSupportRange: "rule kind: support_range (support range; PASS inside the documented range, UNSUPPORTED outside it, never BLOCKED; decided only by check batch",
		"":                                    "",
	} {
		var out bytes.Buffer
		renderCatalogCheck(&out, checkroutemetadata.Check{Project: "p", RuleID: "p.r", From: "1", To: "2", RuleKind: kind})
		text := out.String()
		if want == "" && strings.Contains(text, "rule kind") || want != "" && !strings.Contains(text, want) {
			t.Fatalf("kind %q:\n%s", kind, text)
		}
	}
}
