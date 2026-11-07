// SPDX-License-Identifier: AGPL-3.0-only

package providerderive

import (
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/providerexcerpt"
)

// FetchDay returns the UTC YYYY-MM-DD day of an excerpt's fetchedAt. It is
// the only "today" an extractor may use: the manifest says when the page was
// fetched, the clock is never read. An unusable value is a *DriftError of
// source and KindExcerpt.
func FetchDay(source string, e providerexcerpt.Entry) (string, error) {
	t, err := time.Parse(time.RFC3339, e.FetchedAt)
	if err != nil {
		return "", Drift(source, KindExcerpt, "fetchedAt %q", e.FetchedAt)
	}
	return t.UTC().Format("2006-01-02"), nil
}
