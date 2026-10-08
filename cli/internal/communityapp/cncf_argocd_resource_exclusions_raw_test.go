// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeArgoExclusionsConfig(t *testing.T, value string) (string, []byte) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "argocd-cm.yaml")
	raw := []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: argocd-cm\ndata:\n  resource.exclusions: '" + value + "'\n  private.example: hidden-value\n")
	if err := os.WriteFile(p, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return p, raw
}
func argoExclusionsArgs(path string, intent bool) []string {
	a := []string{"check", "cncf", "--project", "argo-cd", "--resource-exclusions-config-map", path, "--from", "2.14.0", "--to", "3.0.0", "--resource-exclusions-config-complete", "--resource-exclusions-precedence-resolved", "--now", "2026-09-12T01:23:59Z", "--format", "json"}
	if intent {
		a = append(a, "--requires-v2-visibility-of-v3-default-excluded-resources", "true")
	}
	return a
}
func TestArgoCDResourceExclusionsNativeRouteSealsSelectionAndPrivacy(t *testing.T) {
	t.Parallel()
	p, raw := writeArgoExclusionsConfig(t, "[]")
	code, out, errout := runCNCFCLI(t, argoExclusionsArgs(p, true)...)
	if code != ExitOK || errout != "" || strings.Contains(out, "hidden-value") || strings.Contains(out, "resource.exclusions: [") {
		t.Fatalf("%d %q %s", code, errout, out)
	}
	var report map[string]any
	if json.Unmarshal([]byte(out), &report) != nil || report["requestedRuleId"] != argoCDResourceExclusionsRuleID || report["selectedRuleId"] != argoCDResourceExclusionsRuleID {
		t.Fatalf("report %s", out)
	}
	pinArgs := append(argoExclusionsArgs(p, true), "--resource-exclusions-config-map-digest", digestCommunityBytes(raw))
	c, repeat, e := runCNCFCLI(t, pinArgs...)
	if c != ExitOK || e != "" || repeat != out {
		t.Fatalf("pin %d %q", c, e)
	}
	c, missingOutput, missingErr := runCNCFCLI(t, argoExclusionsArgs(p, false)...)
	if c != ExitUnknown || missingErr != "" || strings.Contains(missingOutput, "hidden-value") {
		t.Fatalf("missing intent %d %q %q", c, missingOutput, missingErr)
	}
	for _, bad := range [][]string{append(argoExclusionsArgs(p, true), "--config-map", p), append(argoExclusionsArgs(p, true), "--knowledge-db", filepath.Dir(p))} {
		c, o, e := runCNCFCLI(t, bad...)
		if c != ExitUsage || o != "" || e == "" || strings.Contains(e, "hidden-value") {
			t.Fatalf("bad=%v %d %q %q", bad, c, o, e)
		}
	}
}

func TestArgoCDResourceExclusionsNativeRouteRejectsMismatchedPinWithoutLeak(t *testing.T) {
	t.Parallel()
	p, _ := writeArgoExclusionsConfig(t, "[]")
	args := append(argoExclusionsArgs(p, true), "--resource-exclusions-config-map-digest", digestCommunityBytes([]byte("different")))
	code, out, errout := runCNCFCLI(t, args...)
	if code != ExitIntegrity || out != "" || errout != "prufyx: ARGO_CD_RESOURCE_EXCLUSIONS_INTEGRITY_FAILURE\n" || strings.Contains(errout, p) || strings.Contains(errout, "hidden-value") {
		t.Fatalf("%d %q %q", code, out, errout)
	}
}
