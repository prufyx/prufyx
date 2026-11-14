// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// Every non-canonical repo ends in a typed stop and no files; the stop is
// repo-not-canonical when the value is repo-shaped, bad-input when it is not.
func TestRepoNotCanonicalRefusedBeforeAnything(t *testing.T) {
	cases := []struct {
		repo string
		stop string // empty: accepted
	}{
		{"github.com/knative/serving", ""},
		{"github.com/Knative/serving", StopRepoNotCanonical},
		{"github.com/knative/Serving", StopRepoNotCanonical},
		{"github.com/KNATIVE/SERVING", StopRepoNotCanonical},
		{"github.com/knative/serving.git", StopRepoNotCanonical},
		{"GitHub.com/knative/serving", StopBadInput},
		{"github.com/knative/serving ", StopBadInput},
		{" github.com/knative/serving", StopBadInput},
		{"https://github.com/knative/serving", StopBadInput},
		{"github.com/knative/serving/", StopBadInput},
		{"github.com/knative", StopBadInput},
		{"", StopBadInput},
	}
	for _, c := range cases {
		in := knativeInput(t, knativeSource(t, nil), rulesFrom(t, "testdata/knative/rules.json"))
		in.Repo = c.repo
		res, err := Generate(in)
		if c.stop == "" {
			if err != nil || res == nil {
				t.Errorf("%q: refused: %v", c.repo, err)
			}
			continue
		}
		if res != nil {
			t.Errorf("%q: files produced for a refused repo", c.repo)
		}
		if codes := stopCodes(err); len(codes) != 1 || codes[0] != c.stop {
			t.Errorf("%q: stops %v, want [%s]", c.repo, codes, c.stop)
		}
	}
}

// A .git suffix is repo-shaped (dots are legal in names) and canonical for
// the loader's regex, so it must be judged by the loader's own function.
// The verdict must equal the loader's for any spelling.
func TestRepoCanonicalMatchesLoader(t *testing.T) {
	for _, s := range []string{"github.com/o/n", "github.com/O/n", "github.com/o/n.git", "github.com/o/n ", "http://github.com/o/n", "github.com/-o/n", ""} {
		r, err := extract.ParseRepo(s)
		if want := err == nil && r.Key == s && !strings.HasSuffix(s, ".git"); repoCanonical(s) != want {
			t.Errorf("%q: generator %v, loader %v", s, repoCanonical(s), want)
		}
	}
}
