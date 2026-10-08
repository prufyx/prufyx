// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

type componentFixture struct {
	dir, selection, kubelet string
	selectionRaw            []byte
}

func writeComponentFixture(t *testing.T, kubeletMode os.FileMode, sourceDigest string) componentFixture {
	t.Helper()
	dir := t.TempDir()
	kubelet := filepath.Join(dir, "kubeadm-flags.env")
	writeCNCFFileAt(t, kubelet, []byte("KUBELET_KUBEADM_ARGS=\"--network-plugin=cni --node-ip=10.9.8.7\"\n"))
	if err := os.Chmod(kubelet, kubeletMode); err != nil {
		t.Fatal(err)
	}
	digest := ""
	if sourceDigest != "" {
		digest = ", digest: " + sourceDigest
	}
	selection := filepath.Join(dir, "selection.yaml")
	raw := []byte("apiVersion: prufyx.io/kubernetes-component-config/v1alpha1\nkind: ComponentConfigSelection\ncomplete: [kubelet]\nsources:\n- {scope: kubelet, format: kubelet-env, path: " + kubelet + digest + "}\n")
	writeCNCFFileAt(t, selection, raw)
	return componentFixture{dir: dir, selection: selection, kubelet: kubelet, selectionRaw: raw}
}

func componentConfigArgs(selection string, extra ...string) []string {
	return append([]string{"check", "cncf", "--project", "kubernetes", "--component-config", selection, "--from", "1.23.17", "--to", "1.24.0", "--distribution", "official_upstream", "--now", "2026-10-01T00:00:00Z"}, extra...)
}

func assertComponentOutputRedacted(t *testing.T, fixture componentFixture, output string) {
	t.Helper()
	for _, forbidden := range []string{fixture.dir, "kubeadm-flags.env", "10.9.8.7", "network-plugin", "KUBELET_KUBEADM_ARGS"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("private input crossed the output boundary: %q in %s", forbidden, output)
		}
	}
}

func TestKubernetesComponentConfigCheckWithoutReviewedRuleStaysUnknown(t *testing.T) {
	t.Parallel()
	fixture := writeComponentFixture(t, 0o600, "")
	// No predicate covers the 1.38 line, so no rule can be selected.
	args := componentConfigArgs(fixture.selection)
	for index, value := range args {
		switch value {
		case "1.23.17":
			args[index] = "1.37.2"
		case "1.24.0":
			args[index] = "1.38.0"
		}
	}
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, "Kubernetes component configuration review") || !strings.Contains(stdout, "aggregate: UNKNOWN") || !strings.Contains(stdout, "KUBERNETES_COMPONENT_NO_REVIEWED_PREDICATE_FOR_TRANSITION") || strings.Contains(stdout, ": PASS") || strings.Contains(stdout, ": BLOCKED") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	assertComponentOutputRedacted(t, fixture, stdout)
}

// TestKubernetesComponentConfigCheckFollowsPublication: the removed dockershim
// flag blocks once a reviewed rule consumes its fact; until then the route
// reports UNKNOWN and never PASS.
func TestKubernetesComponentConfigCheckFollowsPublication(t *testing.T) {
	t.Parallel()
	fixture := writeComponentFixture(t, 0o600, "")
	want := ExitUnknown
	if cncfcheck.RegisteredFact("component.kubernetes.kubelet_dockershim_flags_removed") {
		want = ExitBlocked
	}
	code, stdout, stderr := runCNCFCLI(t, componentConfigArgs(fixture.selection, "--component-config-digest", cncfDigest(fixture.selectionRaw), "--format", "json")...)
	if code != want || stderr != "" || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || strings.Contains(stdout, `"status":"PASS"`) {
		t.Fatalf("code=%d want=%d stdout=%q stderr=%q", code, want, stdout, stderr)
	}
	assertComponentOutputRedacted(t, fixture, stdout)
}

func TestKubernetesComponentConfigCheckRejectsUnsafeInputs(t *testing.T) {
	t.Parallel()
	t.Run("source not owner-only", func(t *testing.T) {
		fixture := writeComponentFixture(t, 0o644, "")
		code, stdout, stderr := runCNCFCLI(t, componentConfigArgs(fixture.selection)...)
		if code != ExitUsage || stdout != "" || !strings.Contains(stderr, "KUBERNETES_COMPONENT_SOURCE_INPUT_INVALID") || !strings.Contains(stderr, "chmod 600") {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
		assertComponentOutputRedacted(t, fixture, stderr)
	})
	t.Run("source digest mismatch", func(t *testing.T) {
		fixture := writeComponentFixture(t, 0o600, cncfDigest([]byte("other")))
		code, stdout, stderr := runCNCFCLI(t, componentConfigArgs(fixture.selection)...)
		if code != ExitIntegrity || stdout != "" || !strings.Contains(stderr, "KUBERNETES_COMPONENT_SOURCE_INTEGRITY_FAILURE") {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	})
	t.Run("selection digest mismatch", func(t *testing.T) {
		fixture := writeComponentFixture(t, 0o600, "")
		code, stdout, stderr := runCNCFCLI(t, componentConfigArgs(fixture.selection, "--component-config-digest", cncfDigest([]byte("other")))...)
		if code != ExitIntegrity || stdout != "" || !strings.Contains(stderr, "KUBERNETES_COMPONENT_SELECTION_INTEGRITY_FAILURE") {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	})
	t.Run("symlinked source", func(t *testing.T) {
		fixture := writeComponentFixture(t, 0o600, "")
		link := filepath.Join(fixture.dir, "link.env")
		if err := os.Symlink(fixture.kubelet, link); err != nil {
			t.Fatal(err)
		}
		raw := []byte("apiVersion: prufyx.io/kubernetes-component-config/v1alpha1\nkind: ComponentConfigSelection\nsources:\n- {scope: kubelet, format: kubelet-env, path: " + link + "}\n")
		writeCNCFFileAt(t, fixture.selection, raw)
		code, stdout, stderr := runCNCFCLI(t, componentConfigArgs(fixture.selection)...)
		if code != ExitUsage || stdout != "" || strings.Contains(stderr, fixture.dir) {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	})
	t.Run("relative source path", func(t *testing.T) {
		fixture := writeComponentFixture(t, 0o600, "")
		writeCNCFFileAt(t, fixture.selection, []byte("apiVersion: prufyx.io/kubernetes-component-config/v1alpha1\nkind: ComponentConfigSelection\nsources:\n- {scope: kubelet, format: kubelet-env, path: kubeadm-flags.env}\n"))
		code, stdout, stderr := runCNCFCLI(t, componentConfigArgs(fixture.selection)...)
		if code != ExitUsage || stdout != "" || !strings.Contains(stderr, "KUBERNETES_COMPONENT_SELECTION_INPUT_INVALID") {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	})
}

func TestKubernetesComponentConfigCheckRejectsWrongModesBeforeReading(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"check", "cncf", "--project", "helm", "--component-config", "PRIVATE-NOT-READ.yaml", "--from", "1.23.0", "--to", "1.24.0", "--now", "2026-10-01T00:00:00Z"},
		{"check", "cncf", "--project", "kubernetes", "--component-config", "PRIVATE-NOT-READ.yaml", "--native-resource", "PRIVATE-NOT-READ.json", "--from", "1.23.0", "--to", "1.24.0", "--now", "2026-10-01T00:00:00Z"},
		{"check", "cncf", "--project", "kubernetes", "--component-config", "PRIVATE-NOT-READ.yaml", "--from", "1.23.0", "--to", "1.24.0"},
		{"check", "cncf", "--project", "kubernetes", "--component-config", "PRIVATE-NOT-READ.yaml", "--from", "1.23.0", "--to", "1.24.0", "--knowledge-db", "PRIVATE-NOT-OPENED-STORE"},
		{"check", "cncf", "--project", "kubernetes", "--component-config", "PRIVATE-NOT-READ.yaml", "--to", "1.24.0", "--now", "2026-10-01T00:00:00Z"},
		{"check", "cncf", "--project", "kubernetes", "--component-config", "PRIVATE-NOT-READ.yaml", "--from", "1.23.0", "--to", "1.24.0", "--distribution", "vendor", "--now", "2026-10-01T00:00:00Z"},
		{"check", "cncf", "--project", "kubernetes", "--component-config", "PRIVATE-NOT-READ.yaml", "--component-config-digest", "sha256:00", "--from", "1.23.0", "--to", "1.24.0", "--now", "2026-10-01T00:00:00Z"},
	} {
		code, stdout, stderr := runCNCFCLI(t, args...)
		if code != ExitUsage || stdout != "" || strings.Contains(stderr, "PRIVATE-NOT") {
			t.Fatalf("args=%q code=%d stdout=%q stderr=%q", args, code, stdout, stderr)
		}
	}
}

// TestKubernetesComponentConfigHumanOutputShowsEvidenceBasis: like every other
// human writer, each claim prints its evidence basis once, before its pinned
// sources, for both a reviewed and a mechanically derived rule.
func TestKubernetesComponentConfigHumanOutputShowsEvidenceBasis(t *testing.T) {
	t.Parallel()
	sources := []constraintengine.SourceEvidence{{ID: "s", URL: "https://example.com/a", Revision: "r1", ContentDigest: "sha256:aa", StartLine: 3, EndLine: 4}}
	for _, test := range []struct {
		name  string
		claim constraintengine.Claim
		line  string
	}{
		{"reviewed", constraintengine.Claim{RuleID: "kubernetes.example", Status: "BLOCKED", ReasonCode: "X", NextAction: "act", Sources: sources}, "evidence basis: reviewed by maintainer\n"},
		{"mechanical", constraintengine.Claim{RuleID: "kubernetes.example", Status: "BLOCKED", ReasonCode: "X", NextAction: "act", Sources: sources, EvidenceBasis: "mechanical", EvidenceExtractor: &constraintengine.Extractor{ID: "example.removal", Version: "1.2.3", CodeDigest: "sha256:bb"}}, "evidence basis: derived from source by example.removal v1.2.3\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var out strings.Builder
			if err := writeKubernetesComponentClaims(&out, []constraintengine.Claim{test.claim, test.claim}); err != nil {
				t.Fatal(err)
			}
			for _, block := range strings.Split(out.String(), "kubernetes.example: ")[1:] {
				basis, source := strings.Index(block, test.line), strings.Index(block, "pinned source:")
				if strings.Count(block, test.line) != 1 || source < 0 || basis > source {
					t.Fatalf("basis line must appear once before the pinned sources: %q", block)
				}
			}
		})
	}
}

// TestKubernetesComponentConfigHumanOutputNamesMatchedMembers: a BLOCKED set
// claim names the forbidden members it found; every other claim prints
// exactly as before.
func TestKubernetesComponentConfigHumanOutputNamesMatchedMembers(t *testing.T) {
	t.Parallel()
	blocked := constraintengine.Claim{RuleID: "kubernetes.example", Operator: constraintengine.OperatorForbidSetMember, Status: "BLOCKED", ReasonCode: "X", NextAction: "act", MatchedMembers: []string{"GateA", "GateB"}}
	var out strings.Builder
	if err := writeKubernetesComponentClaims(&out, []constraintengine.Claim{blocked}); err != nil {
		t.Fatal(err)
	}
	if out.String() != "kubernetes.example: BLOCKED (X)\nnext action: act\nforbidden members present: GateA, GateB\nevidence basis: reviewed by maintainer\n" {
		t.Fatalf("output=%q", out.String())
	}
	out.Reset()
	blocked.MatchedMembers = nil
	if err := writeKubernetesComponentClaims(&out, []constraintengine.Claim{blocked}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "forbidden members") {
		t.Fatalf("output=%q", out.String())
	}
}
