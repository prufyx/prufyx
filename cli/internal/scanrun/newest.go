// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"time"

	"github.com/prufyx/prufyx/cli/internal/scanconfig"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
	"github.com/prufyx/prufyx/cli/internal/servedapis"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

// newestLiner is implemented by knowledge that holds reviewed served-API
// lists per release line.
type newestLiner interface {
	NewestServedLine(component string, now time.Time) (string, bool)
}

// newestAttester is implemented by knowledge that holds line attestations.
type newestAttester interface {
	NewestAttestedRelease(component string, now time.Time) (line, version string, ok bool)
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
		if component != servedapis.KubernetesComponent {
			// An application has no served-API list: it needs a complete
			// reviewed line attestation and a current reviewed path policy.
			version, err := newestAppRelease(knowledge, slug, component, now)
			if err != nil {
				return err
			}
			setNewestTarget(effective, slug, version)
			continue
		}
		line, found := resolver.NewestServedLine(component, now)
		if !found {
			return usage(scanreport.UsageNewestCovered, slug, slug)
		}
		setNewestTarget(effective, slug, line+".0")
	}
	return nil
}

func setNewestTarget(effective *scanconfig.Effective, slug, version string) {
	if effective.Target == nil {
		effective.Target = map[string]scanconfig.Value[string]{}
	}
	effective.Target[slug] = scanconfig.Value[string]{Value: version, Set: true, Source: scanconfig.FromNewestCovered}
}

// pathPolicier is implemented by knowledge that holds upgrade-path policies.
type pathPolicier interface {
	PathPolicyFor(component string, now time.Time) upgradepath.Status
}

// newestAppRelease is the newest attested patch of an application's newest
// line with a complete reviewed rule set. It resolves only when the
// application also has a current reviewed path policy: without one the plan
// could not say how to reach the target, so nothing is chosen.
func newestAppRelease(knowledge any, slug, component string, now time.Time) (string, error) {
	attested, ok := knowledge.(newestAttester)
	if !ok {
		return "", usage(scanreport.UsageNewestCovered, slug, slug)
	}
	_, version, found := attested.NewestAttestedRelease(component, now)
	if !found {
		return "", usage(scanreport.UsageNewestCovered, slug, slug)
	}
	policies, ok := knowledge.(pathPolicier)
	if !ok || policies.PathPolicyFor(component, now).Policy() == nil {
		return "", usage(scanreport.UsageNewestCoveredNoPolicy, slug, slug)
	}
	return version, nil
}
