// SPDX-License-Identifier: AGPL-3.0-only

package onecommand

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/localcollector"
)

// imageRunner serves one Deployment whose single container uses the given
// image (nil image means no Deployment at all) and otherwise behaves like
// fakeRunner.
type imageRunner struct {
	t *testing.T
	// resource is the resource name served (default deployments.apps).
	resource string
	image    string
	args     []any
}

func (r *imageRunner) Run(_ context.Context, argv, _ []string, _ time.Duration) (localcollector.CommandResult, error) {
	joined := strings.Join(argv, " ")
	if strings.Contains(joined, " "+r.servedResource()+" ") {
		items := []any{}
		if r.image != "" {
			container := map[string]any{"image": r.image}
			if r.args != nil {
				container["args"] = r.args
			}
			items = append(items, map[string]any{
				"kind": "Deployment",
				"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{container}}}},
			})
		}
		raw, _ := json.Marshal(map[string]any{"items": items})
		return localcollector.CommandResult{Stdout: raw}, nil
	}
	return localcollector.CommandResult{Stdout: fakeKubectlResponse(joined)}, nil
}

func (r *imageRunner) servedResource() string {
	if r.resource != "" {
		return r.resource
	}
	return "deployments.apps"
}

func TestWorkloadKindOutsideAdapterIsNeverAbsent(t *testing.T) {
	opts := baseTestOptions(t, &imageRunner{t: t, resource: "daemonsets.apps", image: "quay.io/argoproj/workflow-controller:v4.1.2"})
	opts.AllowPartial = true
	opts.ComponentConfigurationProfile = "v3"
	var stdout, stderr bytes.Buffer
	report, code := Run(context.Background(), opts, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("code=%d", code)
	}
	n := 0
	for _, c := range report.Contexts[0].Checks {
		if c.Project != "argo-workflows" {
			continue
		}
		n++
		if c.Applicability == NotApplicableComponentAbsent || strings.HasPrefix(c.Applicability, "APPLICABLE") {
			t.Fatalf("%s applicability=%q", c.RuleID, c.Applicability)
		}
	}
	if n == 0 {
		t.Fatal("no argo-workflows checks")
	}
}

func argoChecks(t *testing.T, image string) []CheckAssessment {
	t.Helper()
	opts := baseTestOptions(t, &imageRunner{t: t, image: image})
	opts.AllowPartial = true
	opts.ComponentConfigurationProfile = "v3"
	var stdout, stderr bytes.Buffer
	report, code := Run(context.Background(), opts, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var out []CheckAssessment
	for _, c := range report.Contexts[0].Checks {
		if c.Project == "argo-workflows" {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		t.Fatal("no argo-workflows checks in the shipped catalog")
	}
	return out
}

func TestIdentifiedButUnboundImageIsNeverAbsent(t *testing.T) {
	// Identity matches a reviewed component, but the image reference form has
	// no reviewed binding, so no component row exists.
	for _, c := range argoChecks(t, "index.docker.io/argoproj/workflow-controller:v3.4.6") {
		if c.Applicability == NotApplicableComponentAbsent || !strings.HasPrefix(c.Applicability, "INDETERMINATE") {
			t.Fatalf("%s applicability=%q, want an INDETERMINATE state", c.RuleID, c.Applicability)
		}
		if !strings.Contains(c.Reason, "COMPONENT_VERSION_UNBOUND") || !strings.Contains(c.Reason, "Next:") {
			t.Fatalf("reason must name the missing evidence and next action, got %q", c.Reason)
		}
	}
}

func TestUnboundVersionWithRowIsNeverAbsentOrPass(t *testing.T) {
	for _, image := range []string{
		"quay.io/argoproj/workflow-controller:v3.4.6",
		"docker.io/argoproj/workflow-controller:v3.4.6",
		"quay.io/argoproj/workflow-controller@sha256:" + strings.Repeat("a", 64),
	} {
		for _, c := range argoChecks(t, image) {
			if c.Applicability == NotApplicableComponentAbsent || strings.HasPrefix(c.Applicability, "APPLICABLE") {
				t.Fatalf("%s: %s applicability=%q", image, c.RuleID, c.Applicability)
			}
		}
	}
}

func TestUnboundOmissionIsTheOnlyNewCollectorOutput(t *testing.T) {
	opts := baseTestOptions(t, &imageRunner{t: t, image: "index.docker.io/argoproj/workflow-controller:v3.4.6"})
	opts.AllowPartial = true
	opts.ComponentConfigurationProfile = "v3"
	var stdout, stderr bytes.Buffer
	report, code := Run(context.Background(), opts, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("code=%d", code)
	}
	if report.Contexts[0].CollectionStatus != "partial_for_declared_surface" {
		t.Fatalf("status=%q, want partial", report.Contexts[0].CollectionStatus)
	}
	raw, _ := os.ReadFile(filepath.Join(report.Contexts[0].RunDirectory, "000", "omissions.tsv"))
	if strings.Count(string(raw), "COMPONENT_VERSION_UNBOUND") != 1 || strings.Contains(string(raw), "workflow-controller") || strings.Contains(string(raw), "3.4.6") {
		t.Fatalf("omission row must carry the code only, got %q", raw)
	}
}

func TestTrulyAbsentComponentStaysNotApplicable(t *testing.T) {
	for _, c := range argoChecks(t, "") {
		if c.Applicability != NotApplicableComponentAbsent {
			t.Fatalf("%s applicability=%q, want NOT_APPLICABLE_COMPONENT_ABSENT", c.RuleID, c.Applicability)
		}
	}
	// An unrelated, unidentified image is not an argo identity either.
	for _, c := range argoChecks(t, "registry.example/other/app:v1.0.0") {
		if c.Applicability != NotApplicableComponentAbsent {
			t.Fatalf("%s applicability=%q for an unrelated image, want NOT_APPLICABLE_COMPONENT_ABSENT", c.RuleID, c.Applicability)
		}
	}
}

func TestBoundVersionIsUnchanged(t *testing.T) {
	for _, c := range argoChecks(t, "quay.io/argoproj/workflow-controller:v4.1.2") {
		if c.Applicability == NotApplicableComponentAbsent || c.Reason != "" && strings.Contains(c.Reason, "no reviewed") {
			t.Fatalf("%s: bound version regressed: %q %q", c.RuleID, c.Applicability, c.Reason)
		}
	}
}
