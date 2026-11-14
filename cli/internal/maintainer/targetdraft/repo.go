// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// repoCanonical reports whether repo is exactly the form the extractor's
// target loader accepts: the output of extract.ParseRepo (trimmed, lower
// case, github.com/<owner>/<name>) equal to the input. The same call the
// loader makes is used, so the two cannot diverge. Nothing is normalised
// here: a draft that needs a different spelling is refused, not rewritten.
func repoCanonical(repo string) bool {
	r, err := extract.ParseRepo(repo)
	// The loader's pattern allows dots, so a clone-URL ".git" suffix would
	// pass it; it never names a repository, so the generator refuses it too.
	return err == nil && r.Key == repo && !strings.HasSuffix(repo, ".git")
}
