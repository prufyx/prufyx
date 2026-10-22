// SPDX-License-Identifier: AGPL-3.0-only

package extract

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

func TestReleaseTaggedSpellings(t *testing.T) {
	a, b := strings.Repeat("a", 40), strings.Repeat("b", 40)
	for _, c := range []struct {
		name string
		tags []Tag
		rel  lineattest.Release
		want bool
	}{
		{"plain version", []Tag{{Name: "1.2.3", Commit: a}}, lineattest.Release{Version: "1.2.3", Commit: a}, true},
		{"v prefix", []Tag{{Name: "v1.2.3", Commit: a}}, lineattest.Release{Version: "1.2.3", Commit: a}, true},
		{"edge prefix", []Tag{{Name: "edge-26.3.2", Commit: a}}, lineattest.Release{Version: "26.3.2", Commit: a}, true},
		{"edge suffix", []Tag{{Name: "26.3.2-edge", Commit: a}}, lineattest.Release{Version: "26.3.2", Commit: a}, true},
		{"edge suffix, other commit", []Tag{{Name: "26.3.2-edge", Commit: b}}, lineattest.Release{Version: "26.3.2", Commit: a}, false},
		{"edge suffix, other version", []Tag{{Name: "126.3.2-edge", Commit: a}}, lineattest.Release{Version: "26.3.2", Commit: a}, false},
		{"suffix with a prefix", []Tag{{Name: "v26.3.2-edge", Commit: a}}, lineattest.Release{Version: "26.3.2", Commit: a}, false},
		{"other suffix", []Tag{{Name: "26.3.2-rc1", Commit: a}}, lineattest.Release{Version: "26.3.2", Commit: a}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := releaseTagged(c.tags, c.rel); got != c.want {
				t.Fatalf("releaseTagged = %v, want %v", got, c.want)
			}
		})
	}
}
