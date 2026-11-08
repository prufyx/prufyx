// SPDX-License-Identifier: AGPL-3.0-only

package buildidentity

import "testing"

func TestMeetsMinimum(t *testing.T) {
	cases := []struct {
		have, min string
		want      bool
	}{
		{"dev", "v9.9.9", true},
		{"v0.1.0-beta.0", "v0.1.0-beta.0", true},
		{"v0.1.0-beta.0", "v0.1.0-beta.1", false},
		{"v0.1.0-beta.1", "v0.1.0-beta.0", true},
		{"v0.1.0-beta.0", "v0.1.0", false},
		{"v0.1.0", "v0.1.0-beta.9", true},
		{"v0.1.0-beta.10", "v0.1.0-beta.9", true},
		{"0.2.0", "v0.1.9", true},
		{"v0.1.9", "v0.2.0", false},
		{"v1.0.0", "garbage", false},
		{"v1.0.0", "", false},
		{"v1.0.0+build", "v1.0.0", true},
	}
	for _, tc := range cases {
		if got := meetsMinimum(tc.have, tc.min); got != tc.want {
			t.Errorf("meetsMinimum(%q, %q) = %v, want %v", tc.have, tc.min, got, tc.want)
		}
	}
}

func TestAtLeast(t *testing.T) {
	cases := []struct {
		have, min string
		want      bool
	}{
		{"v0.1.0-beta.1", "v0.1.0-beta.1", true},
		{"v0.1.0-beta.0", "v0.1.0-beta.1", false},
		{"v0.1.0-alpha.9", "v0.1.0-beta.1", false},
		{"v0.1.0", "v0.1.0-beta.1", true},
		{"v0.2.0", "v0.1.0-beta.1", true},
		{"v0.0.9", "v0.1.0-beta.1", false},
		{DevelopmentVersion, "v0.1.0-beta.1", false}, // no special case for a development build
		{"v0.1.0-beta.1", "garbage", false},
		{"garbage", "v0.1.0-beta.1", false},
		{"", "v0.1.0-beta.1", false},
		{"v0.1.0-beta.1", "", false},
	}
	for _, tc := range cases {
		if got := AtLeast(tc.have, tc.min); got != tc.want {
			t.Errorf("AtLeast(%q, %q) = %v, want %v", tc.have, tc.min, got, tc.want)
		}
	}
}
