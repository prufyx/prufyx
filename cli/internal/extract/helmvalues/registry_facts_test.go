// SPDX-License-Identifier: AGPL-3.0-only

package helmvalues

import (
	"testing"

	"github.com/prufyx/prufyx/cli/internal/chartidentity"
	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// TestEveryActiveChartSourceHasItsValuesPathFactRegistered: the rules this
// extractor derives read the values-path set fact of a chart, and the merged
// pack is admitted only when the engine's fact registry defines that fact. A
// row of the reviewed chart-source table that is active but has no extractor
// target, or whose target's fact the registry does not define as a set of the
// target's component, fails here instead of at assemble.
func TestEveryActiveChartSourceHasItsValuesPathFactRegistered(t *testing.T) {
	t.Parallel()
	sources, _, err := chartidentity.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	defined := map[string]constraintengine.FactDefinition{}
	for _, d := range cncfcheck.CompiledFactDefinitions() {
		defined[d.ID] = d
	}
	active := 0
	for _, r := range sources.Records {
		if r.Evidence.State != chartidentity.StateActive {
			continue
		}
		active++
		var target *Target
		for i := range Targets {
			if Targets[i].Chart.Name == r.Chart && Targets[i].Chart.Source == r.RepoURL {
				target = &Targets[i]
			}
		}
		if target == nil {
			t.Errorf("active chart-source row %s %s has no helm-values target", r.RepoURL, r.Chart)
			continue
		}
		if target.Component != r.Component {
			t.Errorf("%s: target component %s, chart-source component %s", target.FactID(), target.Component, r.Component)
		}
		d, ok := defined[target.FactID()]
		if !ok {
			t.Errorf("%s is not defined by the fact registry", target.FactID())
			continue
		}
		if d.Type != constraintengine.FactSet || d.Component != target.Component {
			t.Errorf("%s: registry defines %s on %s, want a set on %s", target.FactID(), d.Type, d.Component, target.Component)
		}
	}
	if active == 0 {
		t.Fatal("the chart-source table has no active row")
	}
	for _, target := range Targets {
		if _, ok := defined[target.FactID()]; !ok {
			t.Errorf("target %s: %s is not defined by the fact registry", target.Project, target.FactID())
		}
	}
}
