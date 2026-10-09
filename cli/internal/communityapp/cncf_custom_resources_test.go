// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
)

const customResourceManifests = "apiVersion: kafka.strimzi.io/v1beta2\nkind: Kafka\nmetadata:\n  name: private-cluster\n  namespace: private-ns\n---\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: private-app\n"

func customResourceArgs(path string, extra ...string) []string {
	return append([]string{"check", "cncf", "--project", "strimzi", "--custom-resources", path, "--from", "0.51.0", "--to", "1.0.0", "--now", "2026-10-04T00:00:00Z"}, extra...)
}

// The embedded knowledge holds no custom-resource rule: the mode reads the
// manifests, prepares the set and stays UNKNOWN, without naming any private
// value.
func TestCustomResourceCheckWithoutPublishedRules(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "manifests.yaml", []byte(customResourceManifests), 0o600)
	for _, format := range []string{"json", "human"} {
		code, stdout, stderr := runCNCFCLI(t, customResourceArgs(path, "--custom-resources-complete", "--format", format)...)
		if code != ExitUnknown || stderr != "" || strings.Contains(stdout, "private-") || strings.Contains(stdout, path) {
			t.Fatalf("%s: code=%d stdout=%q stderr=%q", format, code, stdout, stderr)
		}
		if format == "human" && (!strings.Contains(stdout, "strimzi custom-resource version review") || !strings.Contains(stdout, "custom-resource set: complete") || !strings.Contains(stdout, "scoped result: UNKNOWN\naggregate: UNKNOWN")) {
			t.Fatalf("human output %q", stdout)
		}
		if format == "json" && (!strings.Contains(stdout, `"claims":[]`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`)) {
			t.Fatalf("json output %q", stdout)
		}
	}
	code, stdout, _ := runCNCFCLI(t, customResourceArgs(path)...)
	if code != ExitUnknown || !strings.Contains(stdout, "custom-resource set: not complete (the manifests are not declared") {
		t.Fatalf("incomplete: code=%d %q", code, stdout)
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
	path := writeCNCFFile(t, "manifests.yaml", []byte(customResourceManifests+"---\napiVersion: monitoring.coreos.com/v1\nkind: ServiceMonitor\nmetadata:\n  name: private-tls\n"), 0o600)
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
