// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"strings"
	"testing"
)

const customResourceManifests = "apiVersion: kafka.strimzi.io/v1beta2\nkind: Kafka\nmetadata:\n  name: private-cluster\n  namespace: private-ns\n---\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: private-app\n"

func customResourceArgs(path string, extra ...string) []string {
	return append([]string{"check", "cncf", "--project", "strimzi", "--custom-resources", path, "--from", "0.51.0", "--to", "1.0.0", "--now", "2026-10-04T00:00:00Z"}, extra...)
}

// The embedded knowledge holds no custom-resource rule: the mode reads the
// manifests, prepares the set and stays UNKNOWN, without naming any private
// value.
func TestCustomResourceCheckWithoutPublishedRules(t *testing.T) {
	path := writeCNCFFile(t, "manifests.yaml", []byte(customResourceManifests), 0o600)
	for _, format := range []string{"json", "human"} {
		code, stdout, stderr := runCNCFCLI(t, customResourceArgs(path, "--custom-resources-complete", "--format", format)...)
		if code != ExitUnknown || stderr != "" || strings.Contains(stdout, "private-") || strings.Contains(stdout, path) {
			t.Fatalf("%s: code=%d stdout=%q stderr=%q", format, code, stdout, stderr)
		}
		if format == "human" && (!strings.Contains(stdout, "strimzi custom-resource version review") || !strings.Contains(stdout, "custom-resource set: complete")) {
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
