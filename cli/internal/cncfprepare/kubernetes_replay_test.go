// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/intake"
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
	inputs["items-under-another-kind"] = []byte(`{"apiVersion":"example.io/v1","kind":"Bundle","metadata":{"name":"b"},"items":[{"apiVersion":"batch/v1beta1","kind":"CronJob","metadata":{"name":"hidden"}},{"apiVersion":"flowcontrol.apiserver.k8s.io/v1beta3","kind":"FlowSchema","metadata":{"name":"hidden"}}]}`)
	inputs["items-beside-removed-cronjob"] = []byte("apiVersion: batch/v1beta1\nkind: CronJob\nmetadata: {name: n}\n---\napiVersion: v1\nkind: ConfigMap\nmetadata: {name: c}\nitems: []\n")
	inputs["items-empty-under-another-kind"] = []byte("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c}\nitems: []\n")
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

// TestKubernetesScanMatchesBytePreparation: for every replay case whose bytes
// decode, the documents path yields the same canonical input, state and
// reason as the byte path (and refuses exactly when it refuses), so a scan
// evaluates the engine input that the single-file route would.
func TestKubernetesScanMatchesBytePreparation(t *testing.T) {
	inputs := kubernetesReplayInputs(t)
	compared := 0
	for name, raw := range inputs {
		workspace, err := intake.Decode("input", raw)
		if err != nil {
			continue
		}
		workspace.Digest = "sha256:" + strings.Repeat("0", 64)
		for _, pair := range kubernetesReplayPairs() {
			for _, decl := range kubernetesReplayDeclarations() {
				want, wantErr := PrepareKubernetesRemovedAPIs(raw, pair[0], pair[1], decl.distribution, decl.apply, decl.scope)
				got, gotErr := PrepareKubernetesScan(workspace, pair[0], pair[1], decl.distribution, decl.apply, decl.scope)
				key := fmt.Sprintf("%s %v %+v", name, pair, decl)
				if (wantErr == nil) != (gotErr == nil) {
					t.Fatalf("%s: byte error %v, documents error %v", key, wantErr, gotErr)
				}
				if wantErr != nil {
					continue
				}
				compared++
				if string(got.Prepared.CanonicalInputJSON) != string(want.CanonicalInputJSON) || got.Prepared.InputDigest != want.InputDigest || got.Prepared.State != want.State || got.Prepared.Reason != want.Reason || !reflect.DeepEqual(got.Prepared.Omissions, want.Omissions) {
					t.Fatalf("%s: documents path differs:\n%s\n%s", key, got.Prepared.CanonicalInputJSON, want.CanonicalInputJSON)
				}
				if got.Prepared.SourceDigest != workspace.Digest {
					t.Fatalf("%s: source digest %s", key, got.Prepared.SourceDigest)
				}
				for fact, sources := range got.Sources {
					if len(sources) == 0 || !strings.Contains(string(got.Prepared.CanonicalInputJSON), `{"id":"`+fact+`","state":"declared","boolValue":true}`) {
						t.Fatalf("%s: sources for %s, which is not declared true", key, fact)
					}
				}
			}
		}
	}
	if compared < 1000 {
		t.Fatalf("only %d cases compared", compared)
	}
}

// TestKubernetesScanSources: the documents that made a fact true are listed
// exactly, with file, document, item and line, and documents at served
// versions are not.
func TestKubernetesScanSources(t *testing.T) {
	first, err := intake.Decode("a.yaml", []byte("apiVersion: batch/v1beta1\nkind: CronJob\nmetadata: {name: one}\n---\napiVersion: batch/v1\nkind: CronJob\nmetadata: {name: served}\n"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := intake.Decode("b.json", []byte(`{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"v1","kind":"ConfigMap"},{"apiVersion":"batch/v1beta1","kind":"CronJob","metadata":{"name":"two"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	workspace := intake.Workspace{Documents: append(first.Documents, second.Documents...), Digest: "sha256:" + strings.Repeat("1", 64)}
	scan, err := PrepareKubernetesScan(workspace, "1.24.17", "1.25.0", "official_upstream", true, true)
	if err != nil {
		t.Fatal(err)
	}
	const fact = "component.kubernetes.cronjob_v1beta1_removed_gvk_present"
	want := []intake.Source{first.Documents[0].Source, second.Documents[1].Source}
	if !reflect.DeepEqual(scan.Sources[fact], want) || len(scan.Sources) != 1 {
		t.Fatalf("sources %+v", scan.Sources)
	}
	if want[0].Line != 1 || want[1].Item != 1 || want[1].Line != 1 {
		t.Fatalf("provenance %+v", want)
	}
	flow, err := intake.Decode("f.yaml", []byte("apiVersion: flowcontrol.apiserver.k8s.io/v1beta3\nkind: FlowSchema\n"))
	if err != nil {
		t.Fatal(err)
	}
	flow.Digest = workspace.Digest
	scan, err = PrepareKubernetesScan(flow, "1.31.0", "1.32.0", "official_upstream", true, true)
	if err != nil || len(scan.Sources[KubernetesFlowControlFact]) != 1 {
		t.Fatalf("flow-control sources %+v %v", scan.Sources, err)
	}
	scan, err = PrepareKubernetesScan(flow, "1.31.0", "1.32.0", "official_upstream", true, false)
	if err != nil || len(scan.Sources) != 0 {
		t.Fatalf("sources without a declared fact %+v %v", scan.Sources, err)
	}
}

// TestKubernetesRemovedVersions: the exported list is the removal table plus
// the 1.32 flow-control removal, in line order.
func TestKubernetesRemovedVersions(t *testing.T) {
	list := KubernetesRemovedVersions()
	count := 1
	for _, removals := range kubernetesRemovalsByTargetMinor {
		count += len(removals)
	}
	if len(list) != count || list[0].Line != "1.22" || list[len(list)-1].Line != "1.37" {
		t.Fatalf("list %d of %d, %v .. %v", len(list), count, list[0], list[len(list)-1])
	}
	found := false
	for _, removal := range list {
		found = found || removal.Line == "1.32" && removal.Version == "v1beta3" && removal.Group == "flowcontrol.apiserver.k8s.io"
	}
	if !found {
		t.Fatal("1.32 flow-control removal missing")
	}
}
