// SPDX-License-Identifier: AGPL-3.0-only

package onecommand

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/localcollector"
)

// observedRunner layers a synthetic three-node cluster and one unsupported
// API read on top of the shared fake. All names are invented fixtures.
type observedRunner struct{ fakeRunner }

func (o *observedRunner) Run(ctx context.Context, argv, env []string, timeout time.Duration) (localcollector.CommandResult, error) {
	joined := strings.Join(argv, " ")
	node := func(v string) map[string]any {
		return map[string]any{"status": map[string]any{"nodeInfo": map[string]any{
			"kubeletVersion": v, "containerRuntimeVersion": "containerd://1.7.0", "osImage": "synthetic-os",
			"kernelVersion": "6.1.0", "architecture": "amd64", "operatingSystem": "linux"}}}
	}
	switch {
	case strings.Contains(joined, "get nodes"):
		raw, _ := json.Marshal(map[string]any{"items": []any{node("v1.30.2"), node("v1.31.0"), node("v1.30.2")}})
		return localcollector.CommandResult{Stdout: raw}, nil
	case strings.Contains(joined, "storageclasses.storage.k8s.io"):
		return localcollector.CommandResult{Exit: 1, Class: "unsupported_not_found_api"}, nil
	}
	return o.fakeRunner.Run(ctx, argv, env, timeout)
}

func TestReportCarriesObservedSection(t *testing.T) {
	opts := baseTestOptions(t, &observedRunner{fakeRunner{t: t}})
	opts.AllowPartial = true
	var stdout, stderr bytes.Buffer
	report, code := Run(context.Background(), opts, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	obs := report.Contexts[0].Observed
	if obs.KubernetesVersion != "v1.31.0" {
		t.Fatalf("kubernetesVersion=%q", obs.KubernetesVersion)
	}
	k := obs.Kubelets
	if k.NodeCount != 3 || k.Min != "v1.30.2" || k.Max != "v1.31.0" || len(k.Versions) != 2 || k.Versions[0].Nodes != 2 || k.Versions[1].Nodes != 1 {
		t.Fatalf("kubelets=%+v", k)
	}
	var prom *ObservedComp
	for i := range obs.Components {
		if strings.HasSuffix(obs.Components[i].ComponentID, "prometheus/prometheus") {
			prom = &obs.Components[i]
		}
	}
	if prom == nil || prom.Version != "2.55.1" || prom.State != "observed" {
		t.Fatalf("components=%+v", obs.Components)
	}
	found := false
	for _, om := range obs.Omissions {
		if om.Code == "kubernetes_api_read_failed_unsupported_not_found_api" {
			found = true
			if om.Resource == "" || om.Hint != "API not served by this cluster (component likely not installed)" {
				t.Fatalf("omission=%+v", om)
			}
		}
	}
	if !found {
		t.Fatalf("omissions=%+v", obs.Omissions)
	}
	raw, err := MarshalReport(report)
	if err != nil || !strings.Contains(string(raw), `"observed"`) || !strings.Contains(string(raw), `"kubelets"`) {
		t.Fatalf("json missing observed: %v", err)
	}
}

func TestOmissionHints(t *testing.T) {
	cases := map[string]string{
		"kubernetes_api_read_failed_unsupported_not_found_api":    "API not served by this cluster (component likely not installed)",
		"projection_filter_rejected":                              "the API response contained fields the collector's allow-list does not accept; please report",
		"kubernetes_api_read_failed_authorization_rbac_forbidden": "grant read access to nodes (get/list) for the kubeconfig identity",
	}
	for code, want := range cases {
		if got := omissionHint("nodes", code); got != want {
			t.Errorf("%s: %q", code, got)
		}
	}
	if omissionHint("x", "brand_new_code") == "" {
		t.Error("unknown code needs a hint")
	}
}

func TestVersionOrdering(t *testing.T) {
	if !versionLess("v1.9.0", "v1.10.0") || !versionLess("v1.30.2-eks-1", "v1.31.0") || versionLess("v1.31.0", "v1.30.9") {
		t.Fatal("bad version ordering")
	}
}
