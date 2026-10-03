// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

var updateReplay = flag.Bool("update", false, "rewrite the golden files")

// kubernetesReplayInputs are the apply sets the replay covers: the published
// Kubernetes examples and inline sets for every removal kind and every
// decoder outcome (List items, typed lists, templates, nested lists,
// pagination, unreviewed versions, non-Kubernetes documents).
func kubernetesReplayInputs(t *testing.T) map[string][]byte {
	t.Helper()
	inputs := map[string][]byte{}
	dir := filepath.Join("..", "..", "examples", "cncf", "native-resources", "kubernetes")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		inputs["example/"+entry.Name()] = raw
	}
	var every []string
	for _, line := range sortedRemovalLines() {
		for _, removal := range kubernetesRemovalsByTargetMinor[line] {
			for _, kind := range removal.Kinds {
				every = append(every, fmt.Sprintf("apiVersion: %s/%s\nkind: %s\nmetadata: {name: x}\n", removal.Group, removal.Removed, kind))
			}
		}
	}
	inputs["every-removed-kind"] = []byte(strings.Join(every, "---\n"))
	inputs["cronjob-list"] = []byte(`{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"batch/v1beta1","kind":"CronJob","metadata":{"name":"nightly-report","namespace":"default"}}]}`)
	inputs["cronjob-migrated"] = []byte("apiVersion: batch/v1\nkind: CronJob\nmetadata: {name: n}\n---\napiVersion: v1\nkind: ConfigMap\nmetadata: {name: c}\n")
	inputs["typed-list"] = []byte("apiVersion: batch/v1beta1\nkind: CronJobList\nitems:\n- metadata: {name: a}\n")
	inputs["templated"] = []byte("apiVersion: batch/v1beta1\nkind: CronJob\nmetadata: {name: '{{ .Values.name }}'}\n")
	inputs["unparseable-template"] = []byte("apiVersion: batch/v1\nkind: CronJob\nmetadata:\n  name: {{ .Values.name }}\n")
	inputs["nested-list"] = []byte(`{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"batch/v1beta1","kind":"CronJob"}]}]}`)
	inputs["paginated"] = []byte(`{"apiVersion":"v1","kind":"List","metadata":{"continue":"abc"},"items":[{"apiVersion":"batch/v1","kind":"CronJob"}]}`)
	inputs["bad-list-metadata"] = []byte(`{"apiVersion":"v1","kind":"List","metadata":{"remainingItemCount":"x"},"items":[{"apiVersion":"batch/v1","kind":"CronJob"}]}`)
	inputs["unreviewed-version"] = []byte("apiVersion: batch/v2alpha1\nkind: CronJob\nmetadata: {name: a}\n")
	inputs["flowcontrol-v1beta3"] = []byte("apiVersion: flowcontrol.apiserver.k8s.io/v1beta3\nkind: FlowSchema\nmetadata: {name: a}\n")
	inputs["flowcontrol-unreviewed"] = []byte("apiVersion: flowcontrol.apiserver.k8s.io/v1beta2\nkind: PriorityLevelConfiguration\nmetadata: {name: a}\n")
	inputs["values-file"] = []byte("replicas: 2\n---\napiVersion: batch/v1beta1\nkind: CronJob\n")
	inputs["invalid-gvk"] = []byte("apiVersion: Batch/V1\nkind: CronJob\n")
	inputs["empty-documents"] = []byte("---\n---\n")
	inputs["not-yaml"] = []byte("a: [\n")
	return inputs
}

func sortedRemovalLines() []string {
	lines := make([]string, 0, len(kubernetesRemovalsByTargetMinor))
	for line := range kubernetesRemovalsByTargetMinor {
		lines = append(lines, line)
	}
	sort.Strings(lines)
	return lines
}

// kubernetesReplayPairs covers every reviewed line from its first and a later
// patch to its first and a later patch, the flow-control pair, a same-line
// patch upgrade, a multi-line jump and a downgrade.
func kubernetesReplayPairs() [][2]string {
	pairs := [][2]string{{"1.31.0", "1.32.0"}, {"1.31.4", "1.32.9"}, {"1.30.1", "1.30.4"}, {"1.24.17", "1.30.4"}, {"1.25.0", "1.24.0"}, {"1.27.3", "1.28.1"}}
	for _, line := range sortedRemovalLines() {
		parts := strings.SplitN(line, ".", 2)
		var minor int
		fmt.Sscanf(parts[1], "%d", &minor)
		previous := fmt.Sprintf("%s.%d", parts[0], minor-1)
		pairs = append(pairs, [2]string{previous + ".0", line + ".0"}, [2]string{previous + ".9", line + ".3"})
	}
	return pairs
}

type replayDeclarations struct {
	distribution string
	apply, scope bool
}

func kubernetesReplayDeclarations() []replayDeclarations {
	return []replayDeclarations{
		{"official_upstream", true, true},
		{"official_upstream", true, false},
		{"official_upstream", false, true},
		{"custom_build", true, true},
		{"", true, true},
	}
}

// TestKubernetesPreparedReplay pins the prepared input of the rendered
// apply-set route for every input, pair and declaration combination: the
// digest of the canonical engine input, its state and reason. The golden file
// was produced before the preparation was split into a byte path and a
// documents path, so any change of behaviour fails here.
func TestKubernetesPreparedReplay(t *testing.T) {
	inputs := kubernetesReplayInputs(t)
	names := make([]string, 0, len(inputs))
	for name := range inputs {
		names = append(names, name)
	}
	sort.Strings(names)
	var lines []string
	for _, name := range names {
		for _, pair := range kubernetesReplayPairs() {
			for _, decl := range kubernetesReplayDeclarations() {
				prepared, err := PrepareKubernetesRemovedAPIs(inputs[name], pair[0], pair[1], decl.distribution, decl.apply, decl.scope)
				key := fmt.Sprintf("%s %s->%s %s apply=%t scope=%t", name, pair[0], pair[1], decl.distribution, decl.apply, decl.scope)
				if err != nil {
					lines = append(lines, key+" error")
					continue
				}
				lines = append(lines, fmt.Sprintf("%s %s %s %s source=%s", key, prepared.InputDigest, prepared.State, prepared.Reason, prepared.SourceDigest))
			}
		}
	}
	got := strings.Join(lines, "\n") + "\n"
	path := filepath.Join("testdata", "kubernetes-prepared-replay.golden")
	if *updateReplay {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		gotLines, wantLines := strings.Split(got, "\n"), strings.Split(string(want), "\n")
		for index := range gotLines {
			if index >= len(wantLines) || gotLines[index] != wantLines[index] {
				t.Fatalf("prepared replay changed at line %d:\n got %s", index+1, gotLines[index])
			}
		}
		t.Fatal("prepared replay changed")
	}
}
