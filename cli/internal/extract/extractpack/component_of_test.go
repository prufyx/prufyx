// SPDX-License-Identifier: AGPL-3.0-only

package extractpack

import "testing"

// A mixed-case repository key gives the lowercase subject component the
// catalog uses.
func TestComponentOfIsLowercase(t *testing.T) {
	for repo, want := range map[string]string{
		"github.com/wasmCloud/wasmCloud": "pkg:github/wasmcloud/wasmcloud",
		"github.com/kedacore/keda":       "pkg:github/kedacore/keda",
	} {
		if got := componentOf(repo); got != want {
			t.Errorf("componentOf(%q) = %q, want %q", repo, got, want)
		}
	}
}
