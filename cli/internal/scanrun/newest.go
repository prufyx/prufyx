// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
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

// recordLiner is implemented by knowledge that can name the newest release
// line any of its served lists or line reviews is about, usable or not.
type recordLiner interface {
	NewestRecordLine(component string) (string, error)
}

// resolveNewestCovered sets the target of each named component to the .0
// release of the newest line the knowledge has a current reviewed list for.
// That is the newest line Prufyx can evaluate, never "latest": the newest
// release may be newer. A component without such a line, or one that also
// has an explicit target, is refused; nothing is guessed.
//
// When a record or rule names a line newer than the chosen one (that line's
// list or review expired, is incomplete or is missing), the result holds a
// gap naming it: an older target is never presented as if
// nothing newer were known. Knowledge that cannot say which lines it names is
// refused.
func resolveNewestCovered(effective *scanconfig.Effective, components []string, knowledge Knowledge, now time.Time) ([]scanreport.Gap, error) {
	var gaps []scanreport.Gap
	for _, slug := range components {
		if _, given := effective.Target[slug]; given {
			return nil, usage(scanreport.UsageNewestCoveredTwice, slug)
		}
		resolver, ok := knowledge.(newestLiner)
		if !ok {
			return nil, usage(scanreport.UsageNewestCovered, slug, slug)
		}
		component, known := knowledge.Component(slug)
		if !known {
			return nil, usage(scanreport.UsageNewestCovered, slug, slug)
		}
		if component != servedapis.KubernetesComponent {
			// An application has no served-API list: it needs a complete
			// reviewed line attestation and a current reviewed path policy.
			version, err := newestAppRelease(knowledge, slug, component, now)
			if err != nil {
				return nil, err
			}
			line, valid := lineattest.LineOf(version)
			if !valid {
				return nil, ErrIntegrity
			}
			older, err := newerLineGaps(knowledge, slug, component, line)
			if err != nil {
				return nil, err
			}
			gaps = append(gaps, older...)
			setNewestTarget(effective, slug, version)
			continue
		}
		line, found := resolver.NewestServedLine(component, now)
		if !found {
			return nil, usage(scanreport.UsageNewestCovered, slug, slug)
		}
		older, err := newerLineGaps(knowledge, slug, component, line)
		if err != nil {
			return nil, err
		}
		gaps = append(gaps, older...)
		setNewestTarget(effective, slug, line+".0")
	}
	return gaps, nil
}

// newerLineGaps is the gap of a component whose chosen line is older than a
// line the knowledge names, or nothing when no newer line is named.
func newerLineGaps(knowledge Knowledge, slug, component, chosen string) ([]scanreport.Gap, error) {
	records, ok := knowledge.(recordLiner)
	if !ok {
		return nil, usage(scanreport.UsageNewestCovered, slug, slug)
	}
	newest, err := records.NewestRecordLine(component)
	if err != nil {
		return nil, ErrIntegrity
	}
	if newest == "" || lineattest.LineLess(newest, chosen) {
		newest = chosen
	}
	// A rule still names its line when the line's records were removed.
	newest = newestRuleLine(newest, knowledge.Rules(slug), component)
	if !lineattest.LineLess(chosen, newest) {
		return nil, nil
	}
	return []scanreport.Gap{scanreport.NewGap(slug, nil, scanreport.GapNewestCoveredOlderLine, slug, chosen, newest)}, nil
}

// newestRuleLine is the newer of newest ("" for none) and the lines the
// component's rules enter. A rule outside every fact family has no scope
// line, so its line is that of its reviewed target version. A chart rule's
// versions are chart versions and name no release line of the component.
func newestRuleLine(newest string, rules []cncfcheck.ScanRule, component string) string {
	for _, rule := range rules {
		if rule.Scope.Component != component || rule.Chart != nil {
			continue
		}
		line := rule.Scope.Line
		if line == "" {
			entered, ok := lineattest.LineOf(rule.Scope.Transition.To)
			if !ok {
				continue
			}
			line = entered
		}
		if lineattest.ValidLine(line) && (newest == "" || lineattest.LineLess(newest, line)) {
			newest = line
		}
	}
	return newest
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
