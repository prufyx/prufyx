// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"reflect"
	"testing"
)

func TestClosestOffersOnlyNearNames(t *testing.T) {
	candidates := []string{"bootc", "youki", "etcd", "kubernetes", "bfe"}
	if got := closest("etcdd", candidates, 3); !reflect.DeepEqual(got, []string{"etcd"}) {
		t.Fatalf("near typo: %v", got)
	}
	if got := closest("nosuch", candidates, 3); len(got) != 0 {
		t.Fatalf("a far name got suggestions: %v", got)
	}
	if got := closest("tuf", candidates, 3); len(got) != 0 {
		t.Fatalf("a short far name got suggestions: %v", got)
	}
}
