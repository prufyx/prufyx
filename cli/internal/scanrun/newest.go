// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"time"

	"github.com/prufyx/prufyx/cli/internal/scanconfig"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// newestLiner is implemented by knowledge that holds reviewed served-API
// lists per release line.
type newestLiner interface {
	NewestServedLine(component string, now time.Time) (string, bool)
}

// resolveNewestCovered sets the target of each named component to the .0
// release of the newest line the knowledge has a current reviewed list for.
// That is the newest line Prufyx can evaluate, never "latest": the newest
// release may be newer. A component without such a line, or one that also
// has an explicit target, is refused; nothing is guessed.
func resolveNewestCovered(effective *scanconfig.Effective, components []string, knowledge Knowledge, now time.Time) error {
	for _, slug := range components {
		if _, given := effective.Target[slug]; given {
			return usage(scanreport.UsageNewestCoveredTwice, slug)
		}
		resolver, ok := knowledge.(newestLiner)
		if !ok {
			return usage(scanreport.UsageNewestCovered, slug, slug)
		}
		component, known := knowledge.Component(slug)
		if !known {
			return usage(scanreport.UsageNewestCovered, slug, slug)
		}
		line, found := resolver.NewestServedLine(component, now)
		if !found {
			return usage(scanreport.UsageNewestCovered, slug, slug)
		}
		if effective.Target == nil {
			effective.Target = map[string]scanconfig.Value[string]{}
		}
		effective.Target[slug] = scanconfig.Value[string]{Value: line + ".0", Set: true, Source: scanconfig.FromNewestCovered}
	}
	return nil
}
