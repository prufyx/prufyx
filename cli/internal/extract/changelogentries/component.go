// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"strings"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// ComponentPURL is the pack component of a reviewed target: the package URL of
// its GitHub repository, pkg:github/<owner>/<repo> in lower case. It is
// derived from the row's repository key and never listed by hand. A row whose
// repository is not on github.com, or whose package URL is not a valid
// component, has none (ok is false) and is attested for nothing.
func ComponentPURL(t Target) (string, bool) {
	rest, ok := strings.CutPrefix(t.Repo.Key, "github.com/")
	if !ok || strings.Count(rest, "/") != 1 {
		return "", false
	}
	purl := "pkg:github/" + strings.ToLower(rest)
	if !constraintengine.ValidComponent(purl) {
		return "", false
	}
	return purl, true
}

// ReviewedComponents maps the project slug of every reviewed row (its
// component name in targets.json) to the pack component derived from the
// row's repository. It is the member table of the changelog-listed family,
// derived from the reviewed rows: a row is the only way to be a member. Rows
// with no pack component are left out.
func ReviewedComponents() map[string]string { return ComponentsOf(Reviewed) }

// ParseTargets reads and strictly validates a targets document, exactly as the
// embedded table is read: a document that does not satisfy the schema yields
// no rows and an error. It lets a caller read the rows of a tree that is not
// the one built into the binary.
func ParseTargets(data []byte) ([]Target, error) { return parseTargets(data) }

// TargetsPath is the repository-relative path of the reviewed rows.
const TargetsPath = "cli/internal/extract/changelogentries/targets.json"

// ComponentsOf maps the project slug of each given row to the pack component
// derived from its repository; rows with no pack component are left out.
func ComponentsOf(rows []Target) map[string]string {
	out := map[string]string{}
	for _, t := range rows {
		if purl, ok := ComponentPURL(t); ok {
			out[t.Component] = purl
		}
	}
	return out
}
