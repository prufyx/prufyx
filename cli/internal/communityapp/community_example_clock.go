// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/projectcheck"
)

// exampleClockOffset is how long after the newest review of a project's rules
// a bundled example is evaluated.
const exampleClockOffset = time.Hour

// exampleClock is the evaluation time of a bundled example of one project: the
// example's own fixed time, or, when the project's rules were reviewed later
// than that (a renewal), the newest review of the project's embedded rules
// plus exampleClockOffset. It reads only the embedded rule data, never the
// wall clock, so the same data always gives the same output. A project with no
// embedded rule, or an unreadable pack, keeps the fixed time.
func exampleClock(project, fixed string) string {
	at, err := time.Parse(time.RFC3339, fixed)
	if err != nil {
		return fixed
	}
	newest, ok := newestProjectReview(project)
	if !ok {
		return fixed
	}
	if floor := newest.UTC().Add(exampleClockOffset); at.Before(floor) {
		return floor.Format(time.RFC3339)
	}
	return fixed
}

// newestProjectReview is the newest reviewedAt among the embedded rules of the
// named project in the CNCF and community packs.
func newestProjectReview(project string) (time.Time, bool) {
	var newest time.Time
	found := false
	for _, read := range []func() ([]byte, error){cncfcheck.EmbeddedRulePack, projectcheck.EmbeddedRulePack} {
		raw, err := read()
		if err != nil {
			return time.Time{}, false
		}
		var pack struct {
			Entries []struct {
				Project string `json:"project"`
				Rule    struct {
					Evidence struct {
						ReviewedAt string `json:"reviewedAt"`
					} `json:"evidence"`
				} `json:"rule"`
			} `json:"entries"`
		}
		if json.Unmarshal(raw, &pack) != nil {
			return time.Time{}, false
		}
		for _, entry := range pack.Entries {
			if entry.Project != project {
				continue
			}
			at, err := time.Parse(time.RFC3339, entry.Rule.Evidence.ReviewedAt)
			if err != nil {
				return time.Time{}, false
			}
			if !found || at.After(newest) {
				newest, found = at, true
			}
		}
	}
	return newest, found
}
