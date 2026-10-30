// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/extract/supersedeids"
	"github.com/prufyx/prufyx/cli/internal/intake"
)

func TestNativeAPIVersionGaps(t *testing.T) {
	t.Parallel()
	clock := supersedeids.Clock()
	stale := clock.AddDate(10, 0, 0)
	for _, test := range []struct {
		name, apiVersion, kind, to string
		now                        time.Time
		want                       string // substring of the one gap line; empty means no gap
	}{
		{"served", "apps/v1", "Deployment", "1.32.0", clock, ""},
		{"custom resource", "example.com/v1", "Widget", "1.32.0", clock, ""},
		{"removed", "extensions/v1beta1", "Ingress", "1.32.0", clock, "was removed in Kubernetes"},
		{"alpha", "apps/v1alpha1", "Deployment", "1.32.0", clock, "alpha API version"},
		{"not listed", "apps/v1", "Bogus", "1.32.0", clock, "not in the reviewed served-API list"},
		{"no current list", "apps/v1", "Deployment", "1.32.0", stale, "no reviewed served-API list"},
		{"uppercase group", "Extensions/v1beta1", "Ingress", "1.32.0", clock, "not a clean lowercase"},
		{"leading space", " extensions/v1beta1", "Ingress", "1.32.0", clock, "not a clean lowercase"},
		{"trailing space", "apps/v1 ", "Deployment", "1.32.0", clock, "not a clean lowercase"},
		{"empty", "", "Deployment", "1.32.0", clock, "not a clean lowercase"},
		{"target not a line", "apps/v1", "Deployment", "nope", clock, "not a release line"},
	} {
		t.Run(test.name, func(t *testing.T) {
			gaps := NativeAPIVersionGaps(cncfcheck.TrustPolicy{}, []intake.Document{{APIVersion: test.apiVersion, Kind: test.kind}}, test.to, test.now)
			if test.want == "" {
				if len(gaps) != 0 {
					t.Fatalf("unexpected gaps %q", gaps)
				}
				return
			}
			if len(gaps) != 1 || !strings.Contains(gaps[0], test.want) {
				t.Fatalf("gaps=%q want substring %q", gaps, test.want)
			}
		})
	}
}
