// SPDX-License-Identifier: AGPL-3.0-only

package onecommand

import (
	"bytes"
	"context"
	"testing"
)

// Top-30 projects whose upstream images the reviewed registry identifies reach
// the scan with their tag version; a tag the strict parser rejects (a suffix or
// a pre-release) gives no version and an unknown applicability, never a guess.
func TestTop30RegistryImagesReachScanWithTagVersion(t *testing.T) {
	for _, tc := range []struct {
		name, project, image, want string
	}{
		{"coredns kubeadm tag", "coredns", "registry.k8s.io/coredns/coredns:v1.11.3", "1.11.3"},
		{"fluent-bit plain tag", "fluent-bit", "cr.fluentbit.io/fluent/fluent-bit:3.1.9", "3.1.9"},
		{"keda plain tag", "keda", "ghcr.io/kedacore/keda:2.15.1", "2.15.1"},
		{"kibana plain tag", "kibana", "docker.elastic.co/kibana/kibana:8.15.0", "8.15.0"},
		{"kyverno v-tag", "kyverno", "reg.kyverno.io/kyverno/kyverno:v1.12.5", "1.12.5"},
		{"loki plain tag", "loki", "docker.io/grafana/loki:3.2.1", "3.2.1"},
		{"loki suffixed tag", "loki", "docker.io/grafana/loki:3.2.1-amd64", ""},
		{"kyverno prerelease tag", "kyverno", "reg.kyverno.io/kyverno/kyverno:v1.13.0-rc.1", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &imagesRunner{fakeRunner: fakeRunner{t: t}, images: []string{tc.image}}
			var stdout, stderr bytes.Buffer
			report, code := Run(context.Background(), baseTestOptions(t, runner), &stdout, &stderr)
			if code != ExitOK {
				t.Fatalf("code=%d stderr=%s", code, stderr.String())
			}
			seen := 0
			for _, c := range report.Contexts[0].Checks {
				if c.Project != tc.project {
					continue
				}
				seen++
				if c.ObservedVersion != tc.want {
					t.Fatalf("%s %s: observed %q, want %q (%+v)", c.Project, c.RuleID, c.ObservedVersion, tc.want, c)
				}
				if tc.want == "" && c.Applicability != IndeterminateNotObservable {
					t.Fatalf("%s %s: unversioned image must be unknown: %+v", c.Project, c.RuleID, c)
				}
			}
			if seen == 0 {
				t.Fatalf("no %s checks", tc.project)
			}
		})
	}
}
