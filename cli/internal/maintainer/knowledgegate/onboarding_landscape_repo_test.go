// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import "testing"

// The landscape keeps the spelling of a project's repository (for example
// OpenFunction/OpenFunction); a target's repository is lowercase. The O4
// comparison folds ASCII case and nothing else.
func TestSameLandscapeRepo(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, landscape, target string
		want                    bool
	}{
		{"identical", "https://github.com/example/widget", "github.com/example/widget", true},
		{"mixed-case landscape", "https://github.com/Example/Widget-Op", "github.com/example/widget-op", true},
		{"upper-case landscape host and path", "https://GitHub.com/EXAMPLE/WIDGET", "github.com/example/widget", true},
		{"other repository", "https://github.com/Example/Widget", "github.com/example/widget-fork", false},
		{"other owner", "https://github.com/Other/Widget", "github.com/example/widget", false},
		{"other host", "https://gitlab.com/Example/Widget", "github.com/example/widget", false},
		{"plain http", "http://github.com/Example/Widget", "github.com/example/widget", false},
		{"trailing slash", "https://github.com/Example/Widget/", "github.com/example/widget", false},
		{"sub path", "https://github.com/Example/Widget/tree/main", "github.com/example/widget", false},
		{"empty landscape", "", "github.com/example/widget", false},
		{"empty target", "https://github.com/Example/Widget", "", false},
		{"userinfo", "https://user@github.com/Example/Widget", "github.com/example/widget", false},
		{"percent-encoded slash", "https://github.com/Example%2FWidget", "github.com/example/widget", false},
		{"upper-case scheme (accepted: scheme case only)", "HTTPS://github.com/Example/Widget", "github.com/example/widget", true},
		{"unicode fold (Kelvin sign)", "https://github.com/examplK/widget", "github.com/example/widget", false},
		{"unicode in target", "https://github.com/example/widget", "github.com/examplK/widget", false},
	} {
		if got := sameLandscapeRepo(tc.landscape, tc.target); got != tc.want {
			t.Errorf("%s: sameLandscapeRepo(%q, %q) = %v, want %v", tc.name, tc.landscape, tc.target, got, tc.want)
		}
	}
}
