// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"time"

	"github.com/prufyx/prufyx/cli/internal/distribution"
	"github.com/prufyx/prufyx/cli/internal/providerfacts"
	"github.com/prufyx/prufyx/cli/internal/scanconfig"
)

// providerRecords reads distribution records from the knowledge when it
// holds any; knowledge that holds none answers "not found", which the
// evaluation reports as an absent record.
type providerRecords struct{ knowledge Knowledge }

func (p providerRecords) Record(id string, now time.Time) (distribution.Record, string, bool) {
	if source, ok := p.knowledge.(interface {
		DistributionRecord(string, time.Time) (distribution.Record, string, bool)
	}); ok {
		return source.DistributionRecord(id, now)
	}
	return distribution.Record{}, "", false
}

// providerSection evaluates the advisory provider facts for a declared
// provider distribution. It reads nothing from the cluster and changes no
// finding, gap, verdict or exit code: the caller attaches the section to the
// report after every rule has run.
func providerSection(effective scanconfig.Effective, knowledge Knowledge, now time.Time) (providerfacts.Section, bool) {
	if !effective.Distribution.Set || !providerDeclared(effective.Distribution.Value) {
		return providerfacts.Section{}, false
	}
	current, hasCurrent := effective.Current[kubernetesSlug]
	target, hasTarget := effective.Target[kubernetesSlug]
	if !hasCurrent && !hasTarget {
		return providerfacts.Section{}, false
	}
	return providerfacts.Evaluate(providerfacts.Input{
		Provider: effective.Distribution.Value,
		Current:  providerfacts.Endpoint{Version: current.Value},
		Target:   providerfacts.Endpoint{Version: target.Value},
		Now:      now, Records: providerRecords{knowledge}, KnowledgeRevision: knowledge.Revision(),
		// No declaration of extended support exists in the CLI: the
		// deadline is always the standard support end.
		ExtendedOptIn: false,
	})
}

func providerDeclared(distribution string) bool {
	for _, d := range scanconfig.ProviderDistributions {
		if d == distribution {
			return true
		}
	}
	return false
}
