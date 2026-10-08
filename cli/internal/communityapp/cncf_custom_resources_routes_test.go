// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

const (
	crdRouteComponent = "pkg:github/strimzi/strimzi-kafka-operator"
	crdRouteFact      = "component.strimzi.custom_resource_versions_set"
	crdRouteRevision  = "4836c7dd74ce973f06d97936916ed7f20c1a2ff0"
)

// crdRouteEntry is a test-only pack entry of the shape the CRD extractor
// derives (Kafka v1beta2 is not served by Strimzi 1.0.0), with evidence
// current at now. It is never published.
func crdRouteEntry(now time.Time) map[string]any {
	rule := `{"id":"strimzi.crd-version-removal.kafkas-kafka-strimzi-io.0-51-0-to-1-0-0","operator":"forbid_set_member","subject":{"component":"` + crdRouteComponent + `","from":"0.51.0","to":"1.0.0"},` +
		`"setCondition":{"side":"proposed","component":"` + crdRouteComponent + `","factId":"` + crdRouteFact + `","members":["kafka.strimzi.io/v1beta2/Kafka"]},` +
		`"evidence":{"state":"active","reviewedAt":"` + now.Add(-24*time.Hour).Format(time.RFC3339) + `","validUntil":"` + now.Add(60*24*time.Hour).Format(time.RFC3339) + `","sources":[{"id":"crd-1-0-0","url":"https://github.com/strimzi/strimzi-kafka-operator/blob/` + crdRouteRevision + `/install/cluster-operator/040-Crd-kafka.yaml","revision":"` + crdRouteRevision + `","contentDigest":"sha256:` + strings.Repeat("0", 64) + `","startLine":1,"endLine":2}]},` +
		`"reasonCode":"CRD_VERSION_NOT_SERVED","nextAction":"change apiVersion of Kafka to kafka.strimzi.io/v1 before upgrading to 1.0.0"}`
	var decoded map[string]any
	if err := json.Unmarshal([]byte(rule), &decoded); err != nil {
		panic(err)
	}
	return map[string]any{
		"project": "strimzi", "description": "Synthetic test-only CRD version removal.", "rule": decoded,
		"requiredFacts": []any{map[string]any{"side": "proposed", "id": crdRouteFact, "component": crdRouteComponent, "type": "set", "enumTokens": nil, "description": "Custom-resource versions of the Strimzi custom resources."}},
	}
}

// crdRoutePack is the embedded pack with the published Strimzi rule replaced
// by the test-only custom-resource rule, at the set-rule pack level.
func crdRoutePack(t *testing.T, now time.Time) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "cncfcheck", "data", "rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pack map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&pack); err != nil {
		t.Fatal(err)
	}
	entries := []any{crdRouteEntry(now)}
	for _, item := range pack["entries"].([]any) {
		if item.(map[string]any)["project"] != "strimzi" {
			entries = append(entries, item)
		}
	}
	id := func(item any) string { return item.(map[string]any)["rule"].(map[string]any)["id"].(string) }
	sort.SliceStable(entries, func(i, j int) bool { return id(entries[i]) < id(entries[j]) })
	pack["entries"] = entries
	pack["schema"] = "prufyx.io/cncf-source-rule-pack/v1alpha3"
	out, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// crdRouteInput is a hand-written operator input declaring a complete
// Strimzi custom-resource version set that holds only served versions.
const crdRouteInput = `{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED",` +
	`"current":{"components":[{"component":"` + crdRouteComponent + `","version":"0.51.0","facts":[]}]},` +
	`"proposed":{"components":[{"component":"` + crdRouteComponent + `","version":"1.0.0","facts":[{"id":"` + crdRouteFact + `","state":"declared","setValue":{"members":["kafka.strimzi.io/v1/Kafka"],"complete":true}}]}]}}`

// TestExternalGenericInputNeverPassesCustomResourceRules: with a selected
// signed store whose Strimzi rule reads the custom-resource version set,
// the generic caller-input route passes the rule but exits 11, never 0,
// both for the current check and for its historical replay, and the human
// output says why.
func TestExternalGenericInputNeverPassesCustomResourceRules(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	bundle, err := cncfcheck.ExportExternalBundleFromPack(crdRoutePack(t, now), "9")
	if err != nil {
		t.Fatal(err)
	}
	repo, err := knowledgefixture.NewProjectsRepository(now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(repo.Close)
	pkg, err := repo.Package(knowledgefixture.ProjectsPackage{Version: 1, Targets: map[string][]byte{knowledge.ConstraintsTargetPath: bundle}})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	if err := os.Mkdir(store, 0o700); err != nil {
		t.Fatal(err)
	}
	root := writeCNCFFile(t, "root.json", repo.Root, 0o600)
	pkgPath := writeCNCFFile(t, "package.tar", pkg, 0o600)
	receipt, err := knowledge.ImportConstraints(knowledge.ImportRequest{PackagePath: pkgPath, StoreRoot: store, BootstrapRootPath: root, BootstrapRootDigest: repo.RootDigest})
	if err != nil {
		t.Fatal(err)
	}
	inputRaw := []byte(crdRouteInput)
	input := writeCNCFFile(t, "input.json", inputRaw, 0o600)
	args := func(extra ...string) []string {
		return append([]string{"check", "cncf", "--project", "strimzi", "--input", input, "--input-digest", cncfDigest(inputRaw), "--knowledge-db", store, "--knowledge-revision", "9", "--knowledge-bundle-digest", cncfDigest(bundle), "--knowledge-trust-receipt-digest", receipt.TrustReceiptDigest}, extra...)
	}
	code, original, stderr := runCNCFCLI(t, args("--format", "json")...)
	if code != ExitUnknown || stderr != "" || strings.Count(original, `"status":"PASS"`) != 1 || strings.Contains(original, `"status":"UNKNOWN"`) || !strings.Contains(original, `"knowledgeOrigin":"external_declared"`) {
		t.Fatalf("external json code=%d stdout=%q stderr=%q", code, original, stderr)
	}
	code, human, stderr := runCNCFCLI(t, args()...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(human, customResourceScopeLine) || !strings.Contains(human, "PASS") {
		t.Fatalf("external human code=%d stdout=%q stderr=%q", code, human, stderr)
	}
	report := writeCNCFFile(t, "report.json", []byte(original), 0o600)
	code, replay, stderr := runCNCFCLI(t, args("--format", "json", "--replay-report", report)...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(replay, `"status":"MATCH"`) {
		t.Fatalf("external replay code=%d stdout=%q stderr=%q", code, replay, stderr)
	}
}

// No custom-resource rule is published, so the embedded generic route keeps
// its outputs: no claim reads a set and no scope line is added.
func TestGenericInputWithoutCustomResourceRulesHasNoScopeLine(t *testing.T) {
	t.Parallel()
	input := writeCNCFFile(t, "strimzi.json", []byte(strings.Replace(crdRouteInput, `{"id":"`+crdRouteFact+`","state":"declared","setValue":{"members":["kafka.strimzi.io/v1/Kafka"],"complete":true}}`, `{"id":"component.strimzi.distribution","state":"declared","enumValue":"official_upstream"},{"id":"component.strimzi.execution_surface","state":"declared","enumValue":"kafka_custom_resource"},{"id":"component.strimzi.kafka_v1beta2_api_present","state":"declared","boolValue":false},{"id":"component.strimzi.target_kafka_crd_admission_required","state":"declared","boolValue":true}`, 1)), 0o600)
	code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "strimzi", "--input", input, "--now", "2026-10-04T00:00:00Z")
	if code != ExitOK || stderr != "" || strings.Contains(stdout, customResourceScopeLine) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}
