// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// A project whose store target holds rules this build cannot evaluate is
// answered with its own gap, not as corruption and not as covered.
func TestStoreGapForDeferredRules(t *testing.T) {
	t.Parallel()
	if _, ok := storeGap(nil, "argo-cd"); ok {
		t.Fatal("gap without a store")
	}
	info := &StoreInfo{Absent: map[string]bool{"a": true}, Deferred: map[string]int{"b": 3}}
	if gap, ok := storeGap(info, "a"); !ok || !strings.Contains(gap.Detail, "no knowledge for a") {
		t.Fatalf("absent: %+v %v", gap, ok)
	}
	gap, ok := storeGap(info, "b")
	if !ok || !strings.Contains(gap.Detail, "3 rule(s) of b") || gap.Reason != scanreport.ReasonProjectNotInKnowledge {
		t.Fatalf("deferred: %+v %v", gap, ok)
	}
	if _, ok := storeGap(info, "c"); ok {
		t.Fatal("gap for a project the store answers")
	}
}
