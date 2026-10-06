// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"strings"
	"testing"
)

const strimziRemovedKafkaResource = `{"apiVersion":"kafka.strimzi.io/v1beta2","kind":"Kafka","metadata":{"name":"private-cluster","namespace":"private-ns"},"spec":{"kafka":{"replicas":3}}}`
const strimziTargetKafkaResource = `{"apiVersion":"kafka.strimzi.io/v1","kind":"Kafka","metadata":{"name":"private-cluster","namespace":"private-ns"},"spec":{"kafka":{"replicas":3}}}`

func strimziNativeArgs(path string) []string {
	return []string{
		"check", "cncf", "--project", "strimzi", "--kafka-resource", path,
		"--strimzi-distribution", "official_upstream", "--target-kafka-crd-admission-required",
		"--from", "0.51.0", "--to", "1.0.0", "--now", "2026-09-18T10:00:00Z", "--format", "json",
	}
}

func TestStrimziNativeKafkaAPICheck_BoundedOutcomesAndPrivacy(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, raw, reason string
		want              int
	}{
		{"removed v1beta2 blocks", strimziRemovedKafkaResource, "REVIEWED_SOURCE_CONSTRAINT", ExitBlocked},
		{"target v1 passes", strimziTargetKafkaResource, "REVIEWED_SOURCE_CONSTRAINT", ExitOK},
		{"list keeps the removed witness", `{"apiVersion":"v1","kind":"List","items":[` + strimziTargetKafkaResource + `,` + strimziRemovedKafkaResource + `]}`, "REVIEWED_SOURCE_CONSTRAINT", ExitBlocked},
		{"other kind stays unknown", `{"apiVersion":"kafka.strimzi.io/v1beta2","kind":"KafkaTopic","metadata":{"name":"private-topic","namespace":"private-ns"}}`, "RULE_APPLICABILITY_NOT_MATCHED", ExitUnknown},
		{"unreviewed served version stays unknown", `{"apiVersion":"kafka.strimzi.io/v1beta1","kind":"Kafka","metadata":{"name":"private-cluster","namespace":"private-ns"}}`, "RULE_APPLICABILITY_FACT_UNAVAILABLE", ExitUnknown},
		{"unresolved rendering stays unknown", `{"apiVersion":"kafka.strimzi.io/{{ .Values.api }}","kind":"Kafka"}`, "RULE_APPLICABILITY_FACT_UNAVAILABLE", ExitUnknown},
		{"pagination stays unknown", `{"apiVersion":"v1","kind":"List","metadata":{"remainingItemCount":1},"items":[` + strimziRemovedKafkaResource + `]}`, "RULE_APPLICABILITY_FACT_UNAVAILABLE", ExitUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := writeCNCFFile(t, "strimzi.json", []byte(test.raw), 0o600)
			code, stdout, stderr := runCNCFCLI(t, strimziNativeArgs(path)...)
			if code != test.want || stderr != "" || !strings.Contains(stdout, test.reason) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || strings.Contains(stdout, "private-") || strings.Contains(stdout, path) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

// The aggregate gate is unchanged by this route: even a scoped PASS keeps the
// whole-upgrade assessment UNKNOWN.
func TestStrimziNativeKafkaAPICheck_KeepsWholeUpgradeAggregateUnknown(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "strimzi.json", []byte(strimziTargetKafkaResource), 0o600)
	code, stdout, stderr := runCNCFCLI(t, strimziNativeArgs(path)...)
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"status":"PASS"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED") {
		t.Fatalf("missing whole-upgrade omission: %q", stdout)
	}
}

func TestStrimziNativeKafkaAPICheck_CustomBuildAndUndeclaredIntentStayUnknown(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "strimzi.json", []byte(strimziRemovedKafkaResource), 0o600)
	for _, test := range []struct {
		name   string
		mutate func([]string) []string
	}{
		{"custom build", func(args []string) []string {
			for index, value := range args {
				if value == "official_upstream" {
					args[index] = "custom_build"
				}
			}
			return args
		}},
		{"admission intent not declared", func(args []string) []string {
			for index, value := range args {
				if value == "--target-kafka-crd-admission-required" {
					return append(args[:index:index], args[index+1:]...)
				}
			}
			return args
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			code, stdout, stderr := runCNCFCLI(t, test.mutate(strimziNativeArgs(path))...)
			if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, "RULE_APPLICABILITY_NOT_MATCHED") {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

func TestStrimziNativeKafkaAPICheck_RejectsMalformedWrongPairAndWrongRoute(t *testing.T) {
	t.Parallel()
	duplicate := writeCNCFFile(t, "strimzi.json", []byte(`{"apiVersion":"kafka.strimzi.io/v1beta2","kind":"Kafka","metadata":{"name":"a","namespace":"b"}}`), 0o600)
	args := strimziNativeArgs(duplicate)
	for index := range args {
		if args[index] == "1.0.0" {
			args[index] = "1.0.1"
		}
	}
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, "RULE_TRANSITION_NOT_REVIEWED") {
		t.Fatalf("wrong pair code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "strimzi", "--kafka-resource", duplicate, "--strimzi-distribution", "vendor_build", "--target-kafka-crd-admission-required", "--from", "0.51.0", "--to", "1.0.0", "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitUsage || stdout != "" || strings.Contains(stderr, duplicate) {
		t.Fatalf("bad distribution code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "kubernetes", "--kafka-resource", "PRIVATE-NOT-READ.json", "--from", "1.31.0", "--to", "1.32.0", "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitUsage || stdout != "" || strings.Contains(stderr, "PRIVATE-NOT-READ") {
		t.Fatalf("cross-project code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "strimzi", "--kafka-resource", duplicate, "--native-resource", duplicate, "--strimzi-distribution", "official_upstream", "--target-kafka-crd-admission-required", "--from", "0.51.0", "--to", "1.0.0", "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitUsage || stdout != "" {
		t.Fatalf("cross-mode selector code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestStrimziNativeKafkaAPICheck_RejectsIntegrityPinMismatch(t *testing.T) {
	t.Parallel()
	raw := []byte(strimziRemovedKafkaResource)
	path := writeCNCFFile(t, "strimzi.json", raw, 0o600)
	args := append(strimziNativeArgs(path), "--kafka-resource-digest", cncfDigest([]byte(strimziTargetKafkaResource)))
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitIntegrity || strings.Contains(stdout, "BLOCKED") || strings.Contains(stderr, path) {
		t.Fatalf("pin mismatch code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestStrimziPrepareKafkaResourceFeedsCheck(t *testing.T) {
	t.Parallel()
	raw := []byte(strimziRemovedKafkaResource)
	path := writeCNCFFile(t, "strimzi.json", raw, 0o600)
	code, canonical, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "strimzi", "--kafka-resource", path, "--kafka-resource-digest", cncfDigest(raw), "--from", "0.51.0", "--to", "1.0.0", "--strimzi-distribution", "official_upstream", "--target-kafka-crd-admission-required", "--format", "input")
	if code != ExitOK || stderr != "" || !strings.Contains(canonical, "component.strimzi.kafka_v1beta2_api_present") || strings.Contains(canonical, "private-") {
		t.Fatalf("prepare code=%d stdout=%q stderr=%q", code, canonical, stderr)
	}
	prepared := writeCNCFFile(t, "strimzi-canonical.json", []byte(canonical), 0o600)
	code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "strimzi", "--input", prepared, "--input-digest", cncfDigest([]byte(canonical)), "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitBlocked || stderr != "" || !strings.Contains(report, `"status":"BLOCKED"`) {
		t.Fatalf("check code=%d stdout=%q stderr=%q", code, report, stderr)
	}
}
