// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeLifecycleConfig(t *testing.T, path, version string, supported []string, private string) []byte {
	t.Helper()
	apis, _ := json.Marshal(map[string]any{"buildpack": map[string]any{"supported": []string{"0.9"}, "deprecated": []string{}}, "platform": map[string]any{"supported": supported, "deprecated": []string{}}})
	metadata, _ := json.Marshal(map[string]any{"lifecycle": map[string]any{"version": version}})
	raw, err := json.Marshal(map[string]any{"architecture": "arm64", "history": []any{map[string]any{"created_by": private}}, "config": map[string]any{"Labels": map[string]any{"io.buildpacks.lifecycle.version": version, "io.buildpacks.lifecycle.apis": string(apis), "io.buildpacks.builder.metadata": string(metadata), "private.example/canary": private}}})
	if err != nil {
		t.Fatal(err)
	}
	writeCNCFFileAt(t, path, raw)
	return raw
}

func buildpacksRawArgs(current, proposed, proposedAPI, format string) []string {
	return []string{"check", "cncf", "--project", "buildpacks", "--current-lifecycle-config", current, "--proposed-lifecycle-config", proposed, "--from", "0.16.5", "--to", "0.17.7", "--current-platform-api", "0.11", "--proposed-platform-api", proposedAPI, "--now", "2026-09-10T17:00:00Z", "--format", format}
}

func TestBuildpacksRawLifecyclePlanEditAndRepeat(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, "current-private.json")
	proposed := filepath.Join(dir, "proposed-private.json")
	currentRaw := writeLifecycleConfig(t, current, "0.16.5", []string{"0.3", "0.11"}, "CURRENT_PRIVATE")
	proposedRaw := writeLifecycleConfig(t, proposed, "0.17.7", []string{"0.3", "0.11", "0.12"}, "TARGET_PRIVATE")
	args := buildpacksRawArgs(current, proposed, "0.13", "human")
	code, before, stderr := runCNCFCLI(t, args...)
	if code != ExitBlocked || stderr != "" || !strings.Contains(before, "target lifecycle does not declare support") && !strings.Contains(before, "scoped result: BLOCKED") || !strings.Contains(before, "CNB_PLATFORM_API: current 0.11 (declared supported); proposed 0.13 (not declared supported)") || !strings.Contains(before, "aggregate: UNKNOWN") || !strings.Contains(before, "not official registry provenance") {
		t.Fatalf("code=%d stderr=%q output=%s", code, stderr, before)
	}
	assertBuildpacksRedacted(t, before, current, proposed)
	fixed := buildpacksRawArgs(current, proposed, "0.12", "human")
	code, after, stderr := runCNCFCLI(t, fixed...)
	if code != ExitOK || stderr != "" || !strings.Contains(after, "scoped result: PASS") || !strings.Contains(after, "proposed 0.12 (declared supported)") || !strings.Contains(after, "only that target metadata declares") {
		t.Fatalf("code=%d stderr=%q output=%s", code, stderr, after)
	}
	code, repeat, stderr := runCNCFCLI(t, fixed...)
	if code != ExitOK || stderr != "" || repeat != after {
		t.Fatalf("repeat code=%d stderr=%q equal=%t", code, stderr, repeat == after)
	}
	jsonArgs := buildpacksRawArgs(current, proposed, "0.13", "json")
	jsonArgs = append(jsonArgs, "--current-lifecycle-config-digest", digestCommunityBytes(currentRaw), "--proposed-lifecycle-config-digest", digestCommunityBytes(proposedRaw))
	code, output, stderr := runCNCFCLI(t, jsonArgs...)
	if code != ExitBlocked || stderr != "" || !json.Valid([]byte(output)) {
		t.Fatalf("json code=%d stderr=%q output=%s", code, stderr, output)
	}
	assertBuildpacksRedacted(t, output, current, proposed)
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Fatalf("unexpected intermediates: %v", entries)
	}
}

func TestBuildpacksRawLifecycleUnknownAndModeGuards(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, "current.json")
	proposed := filepath.Join(dir, "proposed.json")
	writeLifecycleConfig(t, current, "0.16.5", []string{"0.11"}, "CURRENT_PRIVATE")
	writeLifecycleConfig(t, proposed, "0.17.6", []string{"0.12"}, "TARGET_PRIVATE")
	code, output, stderr := runCNCFCLI(t, buildpacksRawArgs(current, proposed, "0.13", "human")...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(output, "RULE_FACT_UNAVAILABLE") {
		t.Fatalf("identity code=%d stderr=%q output=%s", code, stderr, output)
	}
	writeLifecycleConfig(t, proposed, "0.17.7", []string{"0.12"}, "TARGET_PRIVATE")
	wrongPair := buildpacksRawArgs(current, proposed, "0.13", "human")
	for i := range wrongPair {
		if wrongPair[i] == "0.16.5" {
			wrongPair[i] = "0.16.6"
			break
		}
	}
	code, output, stderr = runCNCFCLI(t, wrongPair...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(output, "RULE_TRANSITION_NOT_REVIEWED") {
		t.Fatalf("pair code=%d stderr=%q output=%s", code, stderr, output)
	}
	writeLifecycleConfig(t, current, "0.16.5", []string{"0.10"}, "CURRENT_PRIVATE")
	code, output, stderr = runCNCFCLI(t, buildpacksRawArgs(current, proposed, "0.13", "human")...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(output, "current 0.11 (not declared supported)") || !strings.Contains(output, "RULE_APPLICABILITY_NOT_MATCHED") {
		t.Fatalf("known unsupported current code=%d stderr=%q output=%s", code, stderr, output)
	}
	writeLifecycleConfig(t, current, "0.16.5", []string{"0.11"}, "CURRENT_PRIVATE")
	base := buildpacksRawArgs(current, proposed, "0.13", "json")
	for _, extra := range [][]string{{"--input", current}, {"--service", current}, {"--config-map", current}, {"--knowledge-db", dir}, {"--replay-report", current}} {
		code, stdout, stderr := runCNCFCLI(t, append(append([]string{}, base...), extra...)...)
		if code != ExitUsage || stdout != "" || stderr == "" || strings.Contains(stderr, current) {
			t.Fatalf("extra=%v code=%d stdout=%q stderr=%q", extra, code, stdout, stderr)
		}
	}
	badPin := append(base, "--current-lifecycle-config-digest", digestCommunityBytes([]byte("wrong")))
	code, stdout, stderr := runCNCFCLI(t, badPin...)
	if code != ExitIntegrity || stdout != "" || !strings.Contains(stderr, "INTEGRITY") {
		t.Fatalf("pin code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	outsideDomain := buildpacksRawArgs(current, proposed, "0.14", "human")
	code, stdout, stderr = runCNCFCLI(t, outsideDomain...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, "RULE_FACT_UNAVAILABLE") {
		t.Fatalf("outside-domain code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	malformed := filepath.Join(dir, "malformed.json")
	writeCNCFFileAt(t, malformed, []byte(`{bad`))
	invalidArgs := buildpacksRawArgs(malformed, proposed, "0.13", "human")
	code, stdout, stderr = runCNCFCLI(t, invalidArgs...)
	if code != ExitUsage || stdout != "" || !strings.Contains(stderr, "BUILDPACKS_LIFECYCLE_PREPARATION_INPUT_INVALID") || strings.Contains(stderr, "KNATIVE") || strings.Contains(stderr, malformed) {
		t.Fatalf("malformed code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func assertBuildpacksRedacted(t *testing.T, output string, paths ...string) {
	t.Helper()
	for _, forbidden := range append(paths, "CURRENT_PRIVATE", "TARGET_PRIVATE", "created_by", "private.example") {
		if strings.Contains(output, forbidden) {
			t.Fatalf("private OCI data crossed output: %q", forbidden)
		}
	}
}
