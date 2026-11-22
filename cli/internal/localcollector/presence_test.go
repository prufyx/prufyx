// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// itemRunner serves one raw item for the given resource.
type itemRunner struct {
	resource string
	item     map[string]any
}

func (r itemRunner) Run(_ context.Context, argv, _ []string, _ time.Duration) (CommandResult, error) {
	if strings.Contains(strings.Join(argv, " "), " "+r.resource+" ") {
		raw, _ := json.Marshal(map[string]any{"items": []any{r.item}})
		return CommandResult{Stdout: raw}, nil
	}
	return CommandResult{Stdout: fakeResponse(argv)}, nil
}

const presenceImage = "quay.io/argoproj/workflow-controller:v4.1.2"

func ctr(image string) []any { return []any{map[string]any{"name": "c", "image": image}} }

func deployment(spec map[string]any) map[string]any {
	return map[string]any{"kind": "Deployment", "metadata": map[string]any{},
		"spec": map[string]any{"template": map[string]any{"spec": spec}}}
}

func owner(kind, apiVersion string, controller bool) map[string]any {
	return map[string]any{"metadata": map[string]any{"ownerReferences": []any{
		map[string]any{"kind": kind, "apiVersion": apiVersion, "name": "x", "controller": controller}}}}
}

func TestImagesOutsideRegularContainersAreNeverAbsent(t *testing.T) {
	other := ctr("registry.example/other/app:v1.0.0")
	cases := map[string]itemRunner{
		"init only":                     {"deployments.apps", deployment(map[string]any{"containers": other, "initContainers": ctr(presenceImage)})},
		"ephemeral only":                {"pods", map[string]any{"kind": "Pod", "metadata": owner("ReplicaSet", "apps/v1", true)["metadata"], "spec": map[string]any{"containers": other, "ephemeralContainers": ctr(presenceImage)}}},
		"bare pod":                      {"pods", map[string]any{"kind": "Pod", "metadata": map[string]any{}, "spec": map[string]any{"containers": ctr(presenceImage)}}},
		"bare pod init":                 {"pods", map[string]any{"kind": "Pod", "metadata": map[string]any{}, "spec": map[string]any{"containers": other, "initContainers": ctr(presenceImage)}}},
		"pod owned by non-controller":   {"pods", map[string]any{"kind": "Pod", "metadata": owner("ReplicaSet", "apps/v1", false)["metadata"], "spec": map[string]any{"containers": ctr(presenceImage)}}},
		"pod owned by wrong apiVersion": {"pods", map[string]any{"kind": "Pod", "metadata": owner("ReplicaSet", "example.io/v1", true)["metadata"], "spec": map[string]any{"containers": ctr(presenceImage)}}},
	}
	for name, r := range cases {
		for _, components := range []bool{true, false} {
			if got := collectOmissions(t, r, components); strings.Count(got, OmissionComponentVersionUnbound) != 1 {
				t.Fatalf("%s components=%v: omissions=%q", name, components, got)
			}
		}
	}
}

func TestOwnerMustBeControllerWithExactAPIVersion(t *testing.T) {
	rs := func(o map[string]any) itemRunner {
		item := map[string]any{"kind": "ReplicaSet", "metadata": o["metadata"],
			"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"containers": ctr(presenceImage)}}}}
		return itemRunner{"replicasets.apps", item}
	}
	for name, r := range map[string]itemRunner{
		"wrong apiVersion": rs(owner("Deployment", "example.io/v1", true)),
		"not controller":   rs(owner("Deployment", "apps/v1", false)),
		"missing version":  rs(owner("Deployment", "", true)),
	} {
		if got := collectOmissions(t, r, true); strings.Count(got, OmissionComponentVersionUnbound) != 1 {
			t.Fatalf("%s: omissions=%q", name, got)
		}
	}
	// A valid owner reference alone does not prove its image was represented.
	if got := collectOmissions(t, rs(owner("Deployment", "apps/v1", true)), true); !strings.Contains(got, OmissionComponentVersionUnbound) {
		t.Fatalf("unread Deployment: omissions=%q", got)
	}
}

func TestRealAbsenceAndHealthyPodsStayQuiet(t *testing.T) {
	other := ctr("registry.example/other/app:v1.0.0")
	for name, r := range map[string]itemRunner{
		"no matching image anywhere":  {"deployments.apps", deployment(map[string]any{"containers": other, "initContainers": other})},
		"unrelated bare pod":          {"pods", map[string]any{"kind": "Pod", "metadata": map[string]any{}, "spec": map[string]any{"containers": other, "ephemeralContainers": other}}},
		"same image in init and main": {"deployments.apps", deployment(map[string]any{"containers": ctr(presenceImage), "initContainers": ctr(presenceImage)})},
	} {
		if got := collectOmissions(t, r, true); strings.Contains(got, OmissionComponentVersionUnbound) {
			t.Fatalf("%s: unexpected %q", name, got)
		}
	}
}

func TestInjectedSidecarInOwnedPodIsNotAbsent(t *testing.T) {
	other := ctr("registry.example/other/app:v1.0.0")
	rs := map[string]any{"kind": "ReplicaSet", "metadata": map[string]any{"name": "rs1", "namespace": "ns"},
		"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"containers": other}}}}
	podMeta := func() map[string]any {
		return map[string]any{"name": "p", "namespace": "ns", "ownerReferences": []any{
			map[string]any{"kind": "ReplicaSet", "apiVersion": "apps/v1", "name": "rs1", "controller": true}}}
	}
	run := func(containers []any) string {
		pod := map[string]any{"kind": "Pod", "metadata": podMeta(), "spec": map[string]any{"containers": containers}}
		return collectOmissions(t, multiRunner{"replicasets.apps": rs, "pods": pod}, true)
	}
	// Sidecar with a reviewed component image that the owner template lacks.
	if got := run(append(append([]any{}, other...), ctr(presenceImage)...)); strings.Count(got, OmissionComponentVersionUnbound) != 1 {
		t.Fatalf("injected sidecar: omissions=%q", got)
	}
	// Pod matching its owner template stays quiet.
	if got := run(other); strings.Contains(got, OmissionComponentVersionUnbound) {
		t.Fatalf("template-matching pod: unexpected %q", got)
	}
	// An owner that was not read cannot vouch for the Pod.
	pod := map[string]any{"kind": "Pod", "metadata": podMeta(), "spec": map[string]any{"containers": ctr(presenceImage)}}
	if got := collectOmissions(t, multiRunner{"pods": pod}, true); strings.Count(got, OmissionComponentVersionUnbound) != 1 {
		t.Fatalf("unread owner: omissions=%q", got)
	}
}

func TestOwnedReplicaSetRolloutDoesNotHideUnrepresentedImage(t *testing.T) {
	for _, components := range []bool{false, true} {
		for _, parent := range []string{"different image", "missing parent", "matching image"} {
			t.Run(parent+"/components="+map[bool]string{false: "off", true: "on"}[components], func(t *testing.T) {
				dep := deployment(map[string]any{"containers": ctr("registry.example/other/app:v1.0.0")})
				dep["metadata"] = map[string]any{"name": "dep", "namespace": "ns"}
				if parent == "matching image" {
					dep["spec"] = map[string]any{"template": map[string]any{"spec": map[string]any{"containers": ctr(presenceImage)}}}
				}
				rs := map[string]any{"kind": "ReplicaSet", "metadata": map[string]any{
					"name": "rs", "namespace": "ns", "ownerReferences": []any{
						map[string]any{"kind": "Deployment", "apiVersion": "apps/v1", "name": "dep", "controller": true}}},
					"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"containers": ctr(presenceImage)}}}}
				pod := map[string]any{"kind": "Pod", "metadata": map[string]any{
					"name": "pod", "namespace": "ns", "ownerReferences": []any{
						map[string]any{"kind": "ReplicaSet", "apiVersion": "apps/v1", "name": "rs", "controller": true}}},
					"spec": map[string]any{"containers": ctr(presenceImage)}}
				r := multiRunner{"deployments.apps": dep, "replicasets.apps": rs, "pods": pod}
				if parent == "missing parent" {
					delete(r, "deployments.apps")
				}
				got := collectOmissions(t, r, components)
				unbound := strings.Contains(got, OmissionComponentVersionUnbound)
				if want := parent != "matching image"; unbound != want {
					t.Fatalf("unbound=%v want %v: omissions=%q", unbound, want, got)
				}
			})
		}
	}
}

// multiRunner serves one raw item per resource.
type multiRunner map[string]map[string]any

func (r multiRunner) Run(_ context.Context, argv, _ []string, _ time.Duration) (CommandResult, error) {
	joined := strings.Join(argv, " ")
	for resource, item := range r {
		if strings.Contains(joined, " "+resource+" ") {
			raw, _ := json.Marshal(map[string]any{"items": []any{item}})
			return CommandResult{Stdout: raw}, nil
		}
	}
	return CommandResult{Stdout: fakeResponse(argv)}, nil
}

func TestLocalCollectionDocListsEveryWorkloadRead(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "local-collection.md"))
	if err != nil {
		t.Fatal(err)
	}
	var always string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "| Always |") {
			always = strings.ToLower(line)
		}
	}
	if always == "" {
		t.Fatal("Always row missing")
	}
	for _, q := range baseQueries {
		if !isWorkload(q.name) {
			continue
		}
		resource := strings.SplitN(q.args[1], ".", 2)[0]
		if !strings.Contains(always, resource) {
			t.Fatalf("docs Always row does not list %s", resource)
		}
	}
	if strings.Contains(string(raw), "adds the declared Pod read without") {
		t.Fatal("stale statement that Pods are read only with --include-pod-status-images")
	}
}
