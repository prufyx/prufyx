// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"testing"

	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

func TestIsPreviousLine(t *testing.T) {
	const calver = "pkg:github/example/calendar"
	defer lineattest.SetCalverComponentsForTest(calver)()
	for _, c := range []struct {
		component, from, to string
		want                bool
	}{
		{"pkg:github/example/ordinary", "1.27", "1.28", true},
		{"pkg:github/example/ordinary", "25.12", "26.1", false},
		{"pkg:github/example/ordinary", "26.0", "26.1", true},
		{"pkg:github/example/ordinary", "1.0", "1.0", false},
		{calver, "25.12", "26.1", true},
		{calver, "26.0", "26.1", false},
		{calver, "26.1", "26.2", true},
		{calver, "26.1", "26.3", false},
	} {
		if got := isPreviousLine(c.component, c.from, c.to); got != c.want {
			t.Errorf("isPreviousLine(%q, %q, %q) = %v, want %v", c.component, c.from, c.to, got, c.want)
		}
	}
}
