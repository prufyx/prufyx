// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"strings"
	"testing"
)

const strimziOperatorCanary = "canary-private-value"

func strimziOperatorFile(env string) string {
	return `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"private-operator","namespace":"private-ns"},"spec":{"template":{"spec":{"containers":[{"name":"strimzi-cluster-operator","image":"registry.invalid/private/operator:0.44.0"` + env + `}]}}}}`
}

func strimziOperatorGates(value string) string {
	encoded, _ := json.Marshal(value)
	return `,"env":[{"name":"STRIMZI_NAMESPACE","value":"` + strimziOperatorCanary + `"},{"name":"STRIMZI_FEATURE_GATES","value":` + string(encoded) + `}]`
}

func strimziOperatorArgs(path string, extra ...string) []string {
	args := []string{
		"check", "cncf", "--project", "strimzi", "--strimzi-operator-deployment", path,
		"--strimzi-distribution", "official_upstream",
		"--from", "0.41.0", "--to", "0.44.0", "--now", "2026-11-20T10:00:00Z", "--format", "json",
	}
	return append(args, extra...)
}

func TestStrimziOperatorGatesCheck_Outcomes(t *testing.T) {
	t.Parallel()
	const known = "ContinueReconciliationOnManualRollingUpdateFailure"
	for _, test := range []struct {
		name, raw string
		extra     []string
		want      int
		status    string
		reason    string
	}{
		{"plus UseKRaft blocks", strimziOperatorFile(strimziOperatorGates("+UseKRaft")), nil, ExitBlocked, "BLOCKED", "REVIEWED_SOURCE_CONSTRAINT"},
		{"minus UseKRaft blocks", strimziOperatorFile(strimziOperatorGates("-UseKRaft")), nil, ExitBlocked, "BLOCKED", "REVIEWED_SOURCE_CONSTRAINT"},
		{"UseKRaft beside the known gate blocks", strimziOperatorFile(strimziOperatorGates("+" + known + ", -UseKRaft")), nil, ExitBlocked, "BLOCKED", "REVIEWED_SOURCE_CONSTRAINT"},
		{"UseKRaft beside an unknown gate still blocks", strimziOperatorFile(strimziOperatorGates("+UseKRaft,+SomeOtherGate")), nil, ExitBlocked, "BLOCKED", "REVIEWED_SOURCE_CONSTRAINT"},
		{"the one accepted gate passes", strimziOperatorFile(strimziOperatorGates("+" + known)), nil, ExitOK, "PASS", "REVIEWED_SOURCE_CONSTRAINT"},
		{"empty value passes", strimziOperatorFile(strimziOperatorGates("")), nil, ExitOK, "PASS", "REVIEWED_SOURCE_CONSTRAINT"},
		{"absent variable passes only with the declaration", strimziOperatorFile(""), []string{"--strimzi-operator-env-complete"}, ExitOK, "PASS", "REVIEWED_SOURCE_CONSTRAINT"},
		{"absent variable without the declaration is unknown", strimziOperatorFile(""), nil, ExitUnknown, "UNKNOWN", "RULE_FACT_UNAVAILABLE"},
		{"absent variable with envFrom is unknown even when declared", strimziOperatorFile(`,"envFrom":[{"secretRef":{"name":"` + strimziOperatorCanary + `"}}]`), []string{"--strimzi-operator-env-complete"}, ExitUnknown, "UNKNOWN", "RULE_FACT_UNAVAILABLE"},
		{"bare UseKRaft never blocks", strimziOperatorFile(strimziOperatorGates("UseKRaft")), nil, ExitUnknown, "UNKNOWN", "SET_FACT_INCOMPLETE"},
		{"a bare name beside a valid UseKRaft emits nothing", strimziOperatorFile(strimziOperatorGates("+UseKRaft,Other")), nil, ExitUnknown, "UNKNOWN", "SET_FACT_INCOMPLETE"},
		{"leading space before a bare name", strimziOperatorFile(strimziOperatorGates(" UseKRaft ")), nil, ExitUnknown, "UNKNOWN", "SET_FACT_INCOMPLETE"},
		{"double prefix", strimziOperatorFile(strimziOperatorGates("++UseKRaft")), nil, ExitUnknown, "UNKNOWN", "SET_FACT_INCOMPLETE"},
		{"inner whitespace", strimziOperatorFile(strimziOperatorGates("+Use KRaft")), nil, ExitUnknown, "UNKNOWN", "SET_FACT_INCOMPLETE"},
		{"empty tokens", strimziOperatorFile(strimziOperatorGates(",,")), nil, ExitUnknown, "UNKNOWN", "SET_FACT_INCOMPLETE"},
		{"case-exact spelling", strimziOperatorFile(strimziOperatorGates("+usekraft")), nil, ExitUnknown, "UNKNOWN", "SET_FACT_INCOMPLETE"},
		{"an unknown gate alone is not a pass", strimziOperatorFile(strimziOperatorGates("+SomeOtherGate")), nil, ExitUnknown, "UNKNOWN", "SET_FACT_INCOMPLETE"},
		{"valueFrom", strimziOperatorFile(`,"env":[{"name":"STRIMZI_FEATURE_GATES","valueFrom":{"secretKeyRef":{"name":"` + strimziOperatorCanary + `","key":"k"}}}]`), nil, ExitUnknown, "UNKNOWN", "RULE_FACT_UNAVAILABLE"},
		{"duplicate variable", strimziOperatorFile(`,"env":[{"name":"STRIMZI_FEATURE_GATES","value":"+UseKRaft"},{"name":"STRIMZI_FEATURE_GATES","value":"-UseKRaft"}]`), nil, ExitUnknown, "UNKNOWN", "RULE_FACT_UNAVAILABLE"},
		{"templated", strings.Replace(strimziOperatorFile(strimziOperatorGates("+UseKRaft")), "+UseKRaft", "{{ .Values.gates }}", 1), nil, ExitUnknown, "UNKNOWN", "RULE_FACT_UNAVAILABLE"},
		{"not a Deployment", `{"apiVersion":"v1","kind":"List","items":[]}`, nil, ExitUnknown, "UNKNOWN", "RULE_FACT_UNAVAILABLE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := writeCNCFFile(t, "operator.json", []byte(test.raw), 0o600)
			code, stdout, stderr := runCNCFCLI(t, strimziOperatorArgs(path, test.extra...)...)
			if code != test.want || stderr != "" || !strings.Contains(stdout, `"status":"`+test.status+`"`) || !strings.Contains(stdout, test.reason) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			for _, leaked := range []string{strimziOperatorCanary, "private-", "registry.invalid", path} {
				if strings.Contains(stdout, leaked) {
					t.Fatalf("output retained %q: %s", leaked, stdout)
				}
			}
			if strings.Contains(stdout, `"status":"PASS"`) != (test.status == "PASS") {
				t.Fatalf("unexpected PASS state: %s", stdout)
			}
		})
	}
}

// A hand-written value never reaches the report: not on a valid path and not
// on an error path.
func TestStrimziOperatorGatesCheck_RawValueIsNeverEchoed(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"+UseKRaft," + strimziOperatorCanary, "bare-" + strimziOperatorCanary, "+" + strimziOperatorCanary} {
		path := writeCNCFFile(t, "operator.json", []byte(strimziOperatorFile(strimziOperatorGates(value))), 0o600)
		for _, args := range [][]string{
			strimziOperatorArgs(path),
			{"prepare", "cncf", "--project", "strimzi", "--strimzi-operator-deployment", path, "--strimzi-distribution", "official_upstream", "--from", "0.41.0", "--to", "0.44.0", "--format", "json"},
			{"prepare", "cncf", "--project", "strimzi", "--strimzi-operator-deployment", path, "--strimzi-distribution", "official_upstream", "--from", "0.41.0", "--to", "0.44.0"},
		} {
			code, stdout, stderr := runCNCFCLI(t, args...)
			if strings.Contains(stdout+stderr, strimziOperatorCanary) || strings.Contains(stdout+stderr, "private-") || code == ExitOK && args[0] == "check" {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		}
	}
	// Error paths: unreadable file, wrong pin, YAML, usage errors.
	path := writeCNCFFile(t, "operator.json", []byte(strimziOperatorFile(strimziOperatorGates("+"+strimziOperatorCanary))), 0o600)
	yaml := writeCNCFFile(t, "operator.yaml", []byte("kind: Deployment\nvalue: "+strimziOperatorCanary+"\n"), 0o600)
	for name, args := range map[string][]string{
		"wrong pin":    strimziOperatorArgs(path, "--strimzi-operator-deployment-digest", "sha256:"+strings.Repeat("0", 64)),
		"yaml":         strimziOperatorArgs(yaml),
		"missing file": strimziOperatorArgs(path + ".absent"),
		"bad distribution": {"check", "cncf", "--project", "strimzi", "--strimzi-operator-deployment", path,
			"--strimzi-distribution", strimziOperatorCanary, "--from", "0.41.0", "--to", "0.44.0", "--now", "2026-11-20T10:00:00Z"},
	} {
		code, stdout, stderr := runCNCFCLI(t, args...)
		if code == ExitOK || code == ExitBlocked || strings.Contains(stdout+stderr, strimziOperatorCanary) {
			t.Fatalf("%s: code=%d stdout=%q stderr=%q", name, code, stdout, stderr)
		}
	}
}

func TestStrimziOperatorGatesCheck_ScopeAndReplay(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "operator.json", []byte(strimziOperatorFile(strimziOperatorGates("+UseKRaft"))), 0o600)
	_, first, _ := runCNCFCLI(t, strimziOperatorArgs(path)...)
	_, second, _ := runCNCFCLI(t, strimziOperatorArgs(path)...)
	if first != second || !strings.Contains(first, StrimziOperatorRuleIDForTest) || !strings.Contains(first, "WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED") {
		t.Fatalf("not stable or scope omissions missing: %q", first)
	}
	// The preparation names what it does not check.
	_, prepared, _ := runCNCFCLI(t, "prepare", "cncf", "--project", "strimzi", "--strimzi-operator-deployment", path, "--strimzi-distribution", "official_upstream", "--from", "0.41.0", "--to", "0.44.0", "--format", "json")
	for _, omission := range []string{"OPERATOR_IMAGE_AND_VERSION_NOT_CHECKED", "ONLY_STRIMZI_FEATURE_GATES_ENV_LITERAL_READ", "OTHER_FEATURE_GATES_AND_OPERATOR_CONFIGURATION_NOT_EVALUATED"} {
		if !strings.Contains(prepared, omission) {
			t.Fatalf("preparation omits %s: %q", omission, prepared)
		}
	}
	// Only the reviewed pair is decided: any other version pair is UNKNOWN.
	for _, pair := range [][2]string{{"0.41.0", "0.45.0"}, {"0.41.1", "0.44.0"}, {"0.41.0", "0.44.1"}, {"0.40.0", "0.44.0"}} {
		args := strimziOperatorArgs(path)
		for index, value := range args {
			switch value {
			case "--from":
				args[index+1] = pair[0]
			case "--to":
				args[index+1] = pair[1]
			}
		}
		code, stdout, stderr := runCNCFCLI(t, args...)
		if code != ExitUnknown || stderr != "" || strings.Contains(stdout, `"status":"BLOCKED"`) || strings.Contains(stdout, `"status":"PASS"`) {
			t.Fatalf("%v: code=%d stdout=%q stderr=%q", pair, code, stdout, stderr)
		}
	}
	for name, mutate := range map[string]func([]string) []string{
		"custom build": func(args []string) []string {
			for index, value := range args {
				if value == "official_upstream" {
					args[index] = "custom_build"
				}
			}
			return args
		},
		"distribution not declared": func(args []string) []string {
			for index, value := range args {
				if value == "--strimzi-distribution" {
					return append(args[:index:index], args[index+2:]...)
				}
			}
			return args
		},
	} {
		code, stdout, stderr := runCNCFCLI(t, mutate(strimziOperatorArgs(path))...)
		if code != ExitUnknown || stderr != "" || strings.Contains(stdout, `"status":"BLOCKED"`) {
			t.Fatalf("%s: code=%d stdout=%q stderr=%q", name, code, stdout, stderr)
		}
	}
}

const StrimziOperatorRuleIDForTest = "strimzi.feature-gate-usekraft-removed.0-44"

func TestStrimziOperatorGatesCheck_ModesAreExclusive(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "operator.json", []byte(strimziOperatorFile(strimziOperatorGates("+UseKRaft"))), 0o600)
	kafka := writeCNCFFile(t, "kafka.json", []byte(strimziRemovedKafkaResource), 0o600)
	base := strimziOperatorArgs(path)
	for name, args := range map[string][]string{
		"with a Kafka resource":          append(append([]string(nil), base...), "--kafka-resource", kafka),
		"with the admission declaration": append(append([]string(nil), base...), "--target-kafka-crd-admission-required"),
		"with another project's input":   append(append([]string(nil), base...), "--falco-argv", kafka),
		"with the generic input":         append(append([]string(nil), base...), "--input", kafka),
		"declaration without a file":     {"check", "cncf", "--project", "strimzi", "--strimzi-operator-env-complete", "--strimzi-distribution", "official_upstream", "--from", "0.41.0", "--to", "0.44.0", "--now", "2026-11-20T10:00:00Z"},
		"another project":                {"check", "cncf", "--project", "falco", "--strimzi-operator-deployment", path, "--from", "0.41.0", "--to", "0.44.0", "--now", "2026-11-20T10:00:00Z"},
		"prepare with a Kafka resource":  {"prepare", "cncf", "--project", "strimzi", "--strimzi-operator-deployment", path, "--kafka-resource", kafka, "--strimzi-distribution", "official_upstream", "--from", "0.41.0", "--to", "0.44.0"},
		"prepare other project":          {"prepare", "cncf", "--project", "falco", "--strimzi-operator-deployment", path, "--from", "0.41.0", "--to", "0.44.0"},
	} {
		code, stdout, _ := runCNCFCLI(t, args...)
		if code != ExitUsage || stdout != "" {
			t.Fatalf("%s: code=%d stdout=%q", name, code, stdout)
		}
	}
	// The Kafka resource route is unchanged and refuses the new flags.
	code, stdout, _ := runCNCFCLI(t, append(strimziNativeArgs(kafka), "--strimzi-operator-env-complete")...)
	if code != ExitUsage || stdout != "" {
		t.Fatalf("code=%d stdout=%q", code, stdout)
	}
}

func TestStrimziOperatorGatesPrepare_Output(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "operator.json", []byte(strimziOperatorFile(strimziOperatorGates("-UseKRaft"))), 0o600)
	code, stdout, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "strimzi", "--strimzi-operator-deployment", path, "--strimzi-distribution", "official_upstream", "--from", "0.41.0", "--to", "0.44.0", "--format", "input")
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"id":"component.strimzi.cluster_operator_feature_gates_set"`) || !strings.Contains(stdout, `"members":["UseKRaft"]`) || !strings.Contains(stdout, `"complete":true`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	for _, leaked := range []string{strimziOperatorCanary, "private-", "registry.invalid", "STRIMZI_NAMESPACE"} {
		if strings.Contains(stdout, leaked) {
			t.Fatalf("input retained %q: %s", leaked, stdout)
		}
	}
	// Pin enforcement: a wrong digest is refused and nothing is printed.
	code, stdout, _ = runCNCFCLI(t, "prepare", "cncf", "--project", "strimzi", "--strimzi-operator-deployment", path, "--strimzi-operator-deployment-digest", "sha256:"+strings.Repeat("0", 64), "--strimzi-distribution", "official_upstream", "--from", "0.41.0", "--to", "0.44.0", "--format", "input")
	if code == ExitOK || stdout != "" {
		t.Fatalf("wrong pin accepted: code=%d stdout=%q", code, stdout)
	}
}
