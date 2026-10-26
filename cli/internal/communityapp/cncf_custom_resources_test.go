// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
)

const customResourceManifests = "apiVersion: kafka.strimzi.io/v1beta2\nkind: Kafka\nmetadata:\n  name: private-cluster\n  namespace: private-ns\n---\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: private-app\n"

func customResourceArgs(path string, extra ...string) []string {
	return customResourceArgsFor("strimzi", "0.51.0", "1.0.0", path, extra...)
}

func customResourceArgsFor(project, from, to, path string, extra ...string) []string {
	return append([]string{"check", "cncf", "--project", project, "--custom-resources", path, "--from", from, "--to", to, "--now", "2026-10-04T00:00:00Z"}, extra...)
}

// kedaCustomResourceManifests are KEDA custom resources: KEDA has no
// custom-resource rule in the embedded knowledge before or after the batch
// ships.
const kedaCustomResourceManifests = "apiVersion: keda.sh/v1alpha1\nkind: ScaledObject\nmetadata:\n  name: private-scaler\n  namespace: private-ns\n---\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: private-app\n"

// For a project the embedded knowledge holds no custom-resource rule of
// (KEDA always; Strimzi until the custom-resource batch ships), the mode
// reads the manifests, prepares the set and stays UNKNOWN, without naming
// any private value.
func TestCustomResourceCheckWithoutPublishedRules(t *testing.T) {
	t.Parallel()
	type subject struct{ project, manifests, from, to string }
	subjects := []subject{{"keda", kedaCustomResourceManifests, "2.16.0", "2.17.0"}}
	if len(batchRuleIDs("strimzi")) == 0 {
		subjects = append(subjects, subject{"strimzi", customResourceManifests, "0.51.0", "1.0.0"})
	}
	for _, s := range subjects {
		path := writeCNCFFile(t, s.project+"-manifests.yaml", []byte(s.manifests), 0o600)
		for _, format := range []string{"json", "human"} {
			code, stdout, stderr := runCNCFCLI(t, customResourceArgsFor(s.project, s.from, s.to, path, "--custom-resources-complete", "--format", format)...)
			if code != ExitUnknown || stderr != "" || strings.Contains(stdout, "private-") || strings.Contains(stdout, path) {
				t.Fatalf("%s %s: code=%d stdout=%q stderr=%q", s.project, format, code, stdout, stderr)
			}
			if format == "human" && (!strings.HasPrefix(stdout, "UNKNOWN  ") || !strings.Contains(stdout, "custom-resource set: complete") || !strings.Contains(stdout, "Whole upgrade: not proven")) {
				t.Fatalf("%s human output %q", s.project, stdout)
			}
			if format == "json" && (!strings.Contains(stdout, `"claims":[]`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`)) {
				t.Fatalf("%s json output %q", s.project, stdout)
			}
		}
		code, stdout, _ := runCNCFCLI(t, customResourceArgsFor(s.project, s.from, s.to, path)...)
		if code != ExitUnknown || !strings.Contains(stdout, "custom-resource set: not complete (the manifests are not declared") {
			t.Fatalf("%s incomplete: code=%d %q", s.project, code, stdout)
		}
	}
}

// Once the custom-resource batch ships, the Strimzi mode evaluates its ten
// rules on the prepared set: on a complete set holding Kafka v1beta2 the
// Kafka rule blocks and the nine others pass (exit 10); on an incomplete set
// the Kafka rule still blocks and the nine others stay UNKNOWN. Before the batch ships this is the previous test's
// Strimzi case.
func TestCustomResourceCheckWithPublishedRules(t *testing.T) {
	t.Parallel()
	ids := batchRuleIDs("strimzi")
	if len(ids) == 0 {
		t.Skip("the embedded knowledge holds no Strimzi custom-resource rule yet (TestCustomResourceCheckWithoutPublishedRules covers Strimzi)")
	}
	path := writeCNCFFile(t, "manifests.yaml", []byte(customResourceManifests), 0o600)
	// At a time inside the batch rules' review window.
	args := func(extra ...string) []string {
		out := customResourceArgs(path, extra...)
		for i := range out {
			if out[i] == "2026-10-04T00:00:00Z" {
				out[i] = "2026-11-01T00:00:00Z"
			}
		}
		return out
	}
	code, stdout, stderr := runCNCFCLI(t, args("--custom-resources-complete", "--format", "json")...)
	if code != ExitBlocked || stderr != "" || strings.Contains(stdout, "private-") || strings.Contains(stdout, path) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("complete: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	statuses := batchClaimStatuses(t, stdout)
	if len(statuses) != len(ids) {
		t.Fatalf("claims %v, want the %d batch rules", statuses, len(ids))
	}
	for _, id := range ids {
		want := "PASS"
		if id == "strimzi.crd-version-removal.kafkas-kafka-strimzi-io.0-51-0-to-1-0-0" {
			want = "BLOCKED"
		}
		if statuses[id] != want {
			t.Fatalf("%s: %s, want %s", id, statuses[id], want)
		}
	}
	// Without a complete set the removed version still blocks (it is a
	// witness either way), and no other rule passes.
	code, stdout, _ = runCNCFCLI(t, args("--format", "json")...)
	if code != ExitBlocked {
		t.Fatalf("incomplete: code=%d %q", code, stdout)
	}
	statuses = batchClaimStatuses(t, stdout)
	if len(statuses) != len(ids) {
		t.Fatalf("incomplete: claims %v, want the %d batch rules", statuses, len(ids))
	}
	for _, id := range ids {
		want := "UNKNOWN"
		if id == "strimzi.crd-version-removal.kafkas-kafka-strimzi-io.0-51-0-to-1-0-0" {
			want = "BLOCKED"
		}
		if statuses[id] != want {
			t.Fatalf("incomplete: %s: %s, want %s", id, statuses[id], want)
		}
	}
}
func TestCustomResourceCheckArguments(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "manifests.yaml", []byte(customResourceManifests), 0o600)
	for name, args := range map[string][]string{
		"project without a set":  {"check", "cncf", "--project", "kubernetes", "--custom-resources", path, "--from", "1.30.0", "--to", "1.31.0", "--now", "2026-10-04T00:00:00Z"},
		"no file":                customResourceArgs("", "--custom-resources-complete"),
		"no versions":            {"check", "cncf", "--project", "strimzi", "--custom-resources", path, "--now", "2026-10-04T00:00:00Z"},
		"no time":                {"check", "cncf", "--project", "strimzi", "--custom-resources", path, "--from", "0.51.0", "--to", "1.0.0"},
		"external knowledge":     {"check", "cncf", "--project", "strimzi", "--custom-resources", path, "--from", "0.51.0", "--to", "1.0.0", "--knowledge-db", t.TempDir()},
		"other mode flag":        customResourceArgs(path, "--kafka-resource", path),
		"scope flag of k8s mode": customResourceArgs(path, "--resource-scope-complete"),
		"malformed digest":       customResourceArgs(path, "--custom-resources-digest", "sha256:abc"),
		"bad time":               {"check", "cncf", "--project", "strimzi", "--custom-resources", path, "--from", "0.51.0", "--to", "1.0.0", "--now", "2026-10-04T00:00:00.5Z"},
	} {
		t.Run(name, func(t *testing.T) {
			if code, stdout, stderr := runCNCFCLI(t, args...); code != ExitUsage {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
	// A pinned digest that does not match the file is an integrity failure.
	code, _, _ := runCNCFCLI(t, customResourceArgs(path, "--custom-resources-digest", "sha256:"+strings.Repeat("0", 64))...)
	if code != ExitIntegrity {
		t.Fatalf("digest mismatch: code=%d", code)
	}
	// A group-readable file is refused like every other private input.
	open := writeCNCFFile(t, "open.yaml", []byte(customResourceManifests), 0o644)
	if code, _, _ := runCNCFCLI(t, customResourceArgs(open)...); code != ExitUsage {
		t.Fatalf("readable file: code=%d", code)
	}
}

// The human set line names why a set is not complete.
func TestCustomResourceSetLine(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "manifests.yaml", []byte(customResourceManifests+"---\napiVersion: unknown.example.invalid/v1beta1\nkind: PostgresCluster\nmetadata:\n  name: private-tls\n"), 0o600)
	code, stdout, _ := runCNCFCLI(t, customResourceArgs(path, "--custom-resources-complete")...)
	if code != ExitUnknown || !strings.Contains(stdout, "custom-resource set: not complete (objects of a custom-resource group that no reviewed project owns are present)\n") {
		t.Fatalf("code=%d %q", code, stdout)
	}
	seen := map[string]bool{}
	for reason, want := range map[string]string{
		cncfprepare.ReasonCustomResourcesComplete:        "complete",
		cncfprepare.ReasonCustomResourcesScopeIncomplete: "not complete (the manifests are not declared",
		cncfprepare.ReasonCustomResourcesUnattributed:    "not complete (objects of a custom-resource group",
		cncfprepare.ReasonCustomResourcesPaginated:       "not complete (a list is paginated)",
		cncfprepare.ReasonCustomResourcesMemberInvalid:   "not complete (an apiVersion is too long",
		cncfprepare.ReasonCustomResourcesTooMany:         "not declared (too many",
		cncfprepare.ReasonCustomResourcesRendering:       "not declared (a document contains unrendered templates",
		cncfprepare.ReasonCustomResourcesUnresolved:      "not declared (the manifests cannot be read",
	} {
		line := customResourceSetLine(reason, reason != cncfprepare.ReasonCustomResourcesRendering && reason != cncfprepare.ReasonCustomResourcesUnresolved && reason != cncfprepare.ReasonCustomResourcesTooMany)
		if !strings.HasPrefix(line, want) || seen[line] {
			t.Fatalf("%s: %q", reason, line)
		}
		seen[line] = true
	}
	for reason, want := range map[string]string{
		cncfprepare.ReasonCustomResourcesRendering:  "not complete (a document contains unrendered templates or cannot be parsed; only the versions",
		cncfprepare.ReasonCustomResourcesUnresolved: "not complete (the manifests cannot be read as one apply set; only the versions",
	} {
		if line := customResourceSetLine(reason, true); !strings.HasPrefix(line, want) || seen[line] {
			t.Fatalf("%s recorded: %q", reason, line)
		}
	}
}

// A document that cannot be read beside one of the project's objects keeps
// that object's version as an incomplete set; with no such object no set is
// declared. Neither ever passes.
func TestCustomResourceSetBesideUnreadableDocument(t *testing.T) {
	t.Parallel()
	templated := "---\napiVersion: v1\nkind: ConfigMap\nmetadata: {name: '{{ .Release.Name }}'}\n"
	for name, tc := range map[string]struct {
		manifests, line string
	}{
		"object read":       {customResourceManifests + templated, "custom-resource set: not complete (a document contains unrendered templates or cannot be parsed; only the versions in the documents that were read are recorded)\n"},
		"no object read":    {"apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: private-app\n" + templated, "custom-resource set: not declared (a document contains unrendered templates or cannot be parsed)\n"},
		"values beside one": {customResourceManifests + "---\nreplicas: 2\n", "custom-resource set: not complete (the manifests cannot be read as one apply set; only the versions in the documents that were read are recorded)\n"},
	} {
		t.Run(name, func(t *testing.T) {
			path := writeCNCFFile(t, "manifests.yaml", []byte(tc.manifests), 0o600)
			code, stdout, _ := runCNCFCLI(t, customResourceArgs(path, "--custom-resources-complete")...)
			if code != ExitUnknown || !strings.Contains(stdout, tc.line) {
				t.Fatalf("code=%d %q", code, stdout)
			}
		})
	}
}
