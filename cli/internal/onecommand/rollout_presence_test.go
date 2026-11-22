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

type rolloutRunner map[string]map[string]any

func (r rolloutRunner) Run(_ context.Context, argv, _ []string, _ time.Duration) (localcollector.CommandResult, error) {
	joined := strings.Join(argv, " ")
	for resource, item := range r {
		if strings.Contains(joined, " "+resource+" ") {
			raw, _ := json.Marshal(map[string]any{"items": []any{item}})
			return localcollector.CommandResult{Stdout: raw}, nil
		}
	}
	return localcollector.CommandResult{Stdout: fakeKubectlResponse(joined)}, nil
}

func TestOwnedRolloutNeverBecomesComponentAbsent(t *testing.T) {
	const image = "quay.io/argoproj/workflow-controller:v4.1.2"
	workload := func(kind, name, image, ownerKind, ownerName string) map[string]any {
		meta := map[string]any{"name": name, "namespace": "ns"}
		if ownerKind != "" {
			meta["ownerReferences"] = []any{map[string]any{"kind": ownerKind, "apiVersion": "apps/v1", "name": ownerName, "controller": true}}
		}
		spec := map[string]any{"containers": []any{map[string]any{"image": image}}}
		if kind != "Pod" {
			spec = map[string]any{"template": map[string]any{"spec": spec}}
		}
		return map[string]any{"kind": kind, "metadata": meta, "spec": spec}
	}
	for _, parent := range []string{"different image", "missing parent", "matching image"} {
		t.Run(parent, func(t *testing.T) {
			parentImage := "registry.example/other/app:v1.0.0"
			if parent == "matching image" {
				parentImage = image
			}
			r := rolloutRunner{
				"deployments.apps": workload("Deployment", "dep", parentImage, "", ""),
				"replicasets.apps": workload("ReplicaSet", "rs", image, "Deployment", "dep"),
				"pods":             workload("Pod", "pod", image, "ReplicaSet", "rs"),
			}
			if parent == "missing parent" {
				delete(r, "deployments.apps")
			}
			opts := baseTestOptions(t, r)
			opts.AllowPartial = true
			opts.ComponentConfigurationProfile = "v3"
			var stdout, stderr bytes.Buffer
			report, code := Run(context.Background(), opts, &stdout, &stderr)
			if code != ExitOK || len(report.Contexts) != 1 {
				t.Fatalf("code=%d contexts=%d stderr=%q", code, len(report.Contexts), stderr.String())
			}
			ctx := report.Contexts[0]
			raw, err := os.ReadFile(filepath.Join(ctx.RunDirectory, "000", "omissions.tsv"))
			if err != nil {
				t.Fatal(err)
			}
			wantUnbound := parent != "matching image"
			if got := strings.Contains(string(raw), "COMPONENT_VERSION_UNBOUND"); got != wantUnbound {
				t.Fatalf("unbound=%v want %v: omissions=%q", got, wantUnbound, raw)
			}
			n := 0
			for _, check := range ctx.Checks {
				if check.Project != "argo-workflows" {
					continue
				}
				n++
				if check.Applicability == NotApplicableComponentAbsent || wantUnbound && check.Applicability != IndeterminatePartialCollection {
					t.Fatalf("%s applicability=%q", check.RuleID, check.Applicability)
				}
			}
			if n == 0 {
				t.Fatal("no argo-workflows checks")
			}
		})
	}
}
