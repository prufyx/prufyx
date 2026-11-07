// SPDX-License-Identifier: AGPL-3.0-only

package main

import "testing"

func TestCIEnvironmentDetection(t *testing.T) {
	for _, tc := range []struct {
		actions, ci string
		want        bool
	}{{"", "", false}, {"true", "", true}, {"", "true", true}, {"false", "false", false}, {"1", "", false}} {
		t.Setenv("GITHUB_ACTIONS", tc.actions)
		t.Setenv("CI", tc.ci)
		if got := ciEnvironment(); got != tc.want {
			t.Fatalf("%+v: got %v", tc, got)
		}
	}
}
