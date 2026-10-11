// SPDX-License-Identifier: AGPL-3.0-only

package chartidentity

import (
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// chartSourceCorpus mixes normal forms and near misses.
var chartSourceCorpus = []string{
	"https://charts.jetstack.io", "oci://quay.io/jetstack/charts", "https://kedacore.github.io/charts",
	"https://example.io:8443/a/b", "oci://registry.example.io/x.y/z_1~2+3-4",
	"https://charts.jetstack.io/", "https://Charts.jetstack.io", "http://charts.jetstack.io", "https://example.io/x.git",
	"https://example.io/x.git.git", "https://example.io/a//b", "https://example.io/a/./b", "https://example.io/a/../b",
	"https://u@example.io", "https://example.io?a=b", "https://example.io#f", "https://example.io/%41", "HTTPS://example.io",
	"https://", "oci://", "https://-x.io", "https://x-.io", "https://example.io:", "https://example.io:123456",
	"https://example.io/a b", "https://example.io\\a", "", "charts.jetstack.io", "https:/example.io", "https://example.io/.",
	"https://example.io/..", "https://example.io/a/", "oci://quay.io/jetstack/charts/",
}

func fixedPoint(value string) bool {
	normal, err := NormalizeRepoURL(value)
	return err == nil && normal == value
}

// TestEngineChartSourceIsTheNormalFormFixedPoint holds the engine's chart
// source check (constraintengine.ValidChartSource, which cannot import this
// package) to the normaliser: the engine accepts exactly the URLs that
// NormalizeRepoURL leaves unchanged.
func TestEngineChartSourceIsTheNormalFormFixedPoint(t *testing.T) {
	for _, value := range chartSourceCorpus {
		if got, want := constraintengine.ValidChartSource(value), fixedPoint(value) && len(value) <= constraintengine.MaxChartSourceBytes; got != want {
			t.Errorf("%q: engine %v, normaliser fixed point %v", value, got, want)
		}
	}
}

func FuzzEngineChartSourceIsTheNormalFormFixedPoint(f *testing.F) {
	for _, value := range chartSourceCorpus {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if got, want := constraintengine.ValidChartSource(value), fixedPoint(value) && len(value) <= constraintengine.MaxChartSourceBytes; got != want {
			t.Fatalf("%q: engine %v, normaliser fixed point %v", value, got, want)
		}
	})
}
