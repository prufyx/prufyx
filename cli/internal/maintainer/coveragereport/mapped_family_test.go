// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import "testing"

// A chart-values target with an anchor mapping is inert and decides no pair:
// it is not a registered family, so it adds no line and no reason to any
// count (its reason stays no-registered-family).
func TestMappedChartTargetIsNotARegisteredFamily(t *testing.T) {
	for _, r := range registrations("openfga") {
		if r.family == FamilyHelmValuesSchema {
			t.Fatalf("openfga is registered in %s while its mapping is inert", r.family)
		}
	}
}
