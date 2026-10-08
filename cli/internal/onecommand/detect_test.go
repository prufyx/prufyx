// SPDX-License-Identifier: AGPL-3.0-only

package onecommand

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/imageidentity"
	"github.com/prufyx/prufyx/cli/internal/localcollector"
)

// imagesRunner answers Deployments with one container per configured image and
// everything else like fakeRunner.
type imagesRunner struct {
	fakeRunner
	images []string
}

func (r *imagesRunner) Run(ctx context.Context, argv, env []string, timeout time.Duration) (localcollector.CommandResult, error) {
	if strings.Contains(strings.Join(argv, " "), " deployments.apps ") {
		items := []any{}
		for _, image := range r.images {
			items = append(items, map[string]any{"kind": "Deployment", "spec": map[string]any{"template": map[string]any{"spec": map[string]any{
				"containers": []any{map[string]any{"image": image, "args": []any{}}},
			}}}})
		}
		raw, _ := json.Marshal(map[string]any{"items": items})
		return localcollector.CommandResult{Stdout: raw}, nil
	}
	return r.fakeRunner.Run(ctx, argv, env, timeout)
}

func TestImageRegistryMakesProjectsObservableWithFailClosedVersions(t *testing.T) {
	runner := &imagesRunner{fakeRunner: fakeRunner{t: t}, images: []string{
		"ghcr.io/cloudnative-pg/cloudnative-pg:1.29.0",           // operator image: its own project at 1.29.0
		"docker.io/velero/velero:latest",                         // present, no version
		"goharbor/harbor-core@sha256:" + strings.Repeat("a", 64), // digest-only: no version
		"mariadb:10.11.8",
		"ghcr.io/mariadb-operator/mariadb-operator:26.3.0",
		"docker.io/library/nats:2.10.0-alpine",                          // alpine scheme
		"example-artifactregistry.gcr.io/gke-release/etcd:v9.9.9-gke.1", // distribution: ignored
		"registry.example.com/mirror/projectcontour/contour:v1.19.0",    // mirror: unknown image
	}}
	var stdout, stderr bytes.Buffer
	report, code := Run(context.Background(), baseTestOptions(t, runner), &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	checks := report.Contexts[0].Checks
	applicable := func(c CheckAssessment) bool {
		return c.Applicability == ApplicableNeedsDeclaration || c.Applicability == ApplicableFullySatisfied
	}
	for _, tc := range []struct{ project, from, version string }{
		{"cloudnativepg", "1.29.0", "1.29.0"}, {"mariadb", "10.11.8", "10.11.8"}, {"mariadb-operator", "26.3.0", "26.3.0"}, {"nats", "2.10.0", "2.10.0"},
	} {
		c := findCheck(t, checks, tc.project, tc.from)
		if !applicable(c) || c.ObservedVersion != tc.version {
			t.Fatalf("%s: %+v", tc.project, c)
		}
	}
	// present with an unknown version: indeterminate, never a version mismatch.
	for _, c := range checks {
		switch c.Project {
		case "velero", "harbor":
			if c.Applicability != IndeterminateNotObservable || c.ObservedVersion != "" {
				t.Fatalf("%s %s: %+v", c.Project, c.RuleID, c)
			}
		case "contour", "kubeedge", "opencost", "etcd", "grafana", "thanos":
			// registry-only and not seen: mirrors hide images, so never "absent".
			if c.Applicability != IndeterminateNotObservable {
				t.Fatalf("%s %s: %+v", c.Project, c.RuleID, c)
			}
		case "loki", "keycloak", "jaeger":
			if c.Applicability != IndeterminateNotObservable {
				t.Fatalf("%s must stay not observable: %+v", c.Project, c)
			}
		}
	}
}

func TestObservableComponentDerivesFromRegistryAndHonoursValidity(t *testing.T) {
	now := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	for project, id := range observableComponents {
		if got, ok := observableComponent(project, now); !ok || got != id {
			t.Fatalf("adapter project %s lost", project)
		}
	}
	if id, ok := observableComponent("cloudnativepg", now); !ok || id != "pkg:oci/cloudnative-pg/cloudnative-pg" {
		t.Fatalf("cloudnativepg: %q %v", id, ok)
	}
	for _, p := range []string{"mariadb", "mariadb-operator"} {
		if _, ok := observableComponent(p, now); !ok {
			t.Fatalf("%s is not observable", p)
		}
	}
	if _, ok := observableComponent("loki", now); ok {
		t.Fatal("loki must not be observable")
	}
	if _, ok := observableComponent("cloudnativepg", time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)); ok {
		t.Fatal("an expired record must make the project not observable")
	}
	// The two sources never disagree or overlap on a project or component.
	registry := imageidentity.ObservableComponents(now)
	adapterComponents := map[string]bool{}
	for project, id := range observableComponents {
		adapterComponents[id] = true
		if _, dup := registry[project]; dup {
			t.Fatalf("%s is in both maps", project)
		}
	}
	for project, id := range registry {
		if adapterComponents[id] {
			t.Fatalf("%s shares component %s with the adapter map", project, id)
		}
	}
}

// A component with any unversioned image row is unknown for the whole
// component: it never takes an exact version from a sibling image.
func TestUnversionedSiblingImageMakesComponentUnknown(t *testing.T) {
	digest := "@sha256:" + strings.Repeat("b", 64)
	for _, tc := range []struct {
		name, project string
		images        []string
	}{
		{"harbor with digest-only sibling", "harbor", []string{"docker.io/goharbor/harbor-core:v2.13.0", "docker.io/goharbor/harbor-portal" + digest}},
		{"velero with latest", "velero", []string{"docker.io/velero/velero:v1.16.0", "docker.io/velero/velero:latest"}},
		{"cnpg with rc tag", "cloudnativepg", []string{"ghcr.io/cloudnative-pg/cloudnative-pg:1.29.0", "ghcr.io/cloudnative-pg/cloudnative-pg:1.29.0-rc1"}},
		{"velero with two exact versions", "velero", []string{"docker.io/velero/velero:v1.16.0", "docker.io/velero/velero:v1.15.0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &imagesRunner{fakeRunner: fakeRunner{t: t}, images: tc.images}
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
				if c.Applicability != IndeterminateNotObservable || c.ObservedVersion != "" {
					t.Fatalf("%s %s: must be unknown, got %+v", c.Project, c.RuleID, c)
				}
			}
			if seen == 0 {
				t.Fatalf("no %s checks", tc.project)
			}
		})
	}
}

func TestSameVersionSiblingImagesStayExact(t *testing.T) {
	runner := &imagesRunner{fakeRunner: fakeRunner{t: t}, images: []string{
		"docker.io/goharbor/harbor-core:v2.13.0", "docker.io/goharbor/harbor-portal:v2.13.0",
	}}
	var stdout, stderr bytes.Buffer
	report, code := Run(context.Background(), baseTestOptions(t, runner), &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	got := false
	for _, c := range report.Contexts[0].Checks {
		if c.Project == "harbor" && c.ObservedVersion == "2.13.0" {
			got = true
		}
	}
	if !got {
		t.Fatal("two images at one version must stay exact")
	}
}
