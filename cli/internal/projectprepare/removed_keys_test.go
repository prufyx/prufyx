// SPDX-License-Identifier: AGPL-3.0-only

package projectprepare

import (
	"bytes"
	"strings"
	"testing"
)

func declared(t *testing.T, prepared Prepared, fact string) string {
	t.Helper()
	marker := `"id":"` + fact + `"`
	i := bytes.Index(prepared.CanonicalInputJSON, []byte(marker))
	if i < 0 {
		t.Fatalf("fact %s missing from %s", fact, prepared.CanonicalInputJSON)
	}
	rest := prepared.CanonicalInputJSON[i:]
	end := bytes.IndexByte(rest, '}')
	return string(rest[:end])
}

func TestScanAirflowCfg(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, raw string
		want      map[string]bool
		supported bool
		invalid   bool
	}{
		{"set-markup", "[webserver]\ninstance_name_has_markup = True\n", map[string]bool{"component.airflow.webserver_instance_name_has_markup_present": true}, true, false},
		{"set-colon-delimiter", "[webserver]\nwarn_deployment_exposure: False\n", map[string]bool{"component.airflow.webserver_warn_deployment_exposure_present": true}, true, false},
		{"set-empty-value", "[api]\nenable_xcom_deserialize_support =\n", map[string]bool{"component.airflow.api_enable_xcom_deserialize_support_present": true}, true, false},
		{"set-scheduler", "[core]\nexecutor = LocalExecutor\n[scheduler]\ndag_stale_not_seen_duration = 600\n", map[string]bool{"component.airflow.scheduler_dag_stale_not_seen_duration_present": true}, true, false},
		{"absent", "[core]\nexecutor = LocalExecutor\n[webserver]\nbase_url = http://localhost\n", map[string]bool{}, true, false},
		{"unrelated-key-same-section", "[webserver]\ninstance_name = prod\n", map[string]bool{}, true, false},
		{"same-key-other-section", "[core]\ninstance_name_has_markup = True\n", map[string]bool{}, true, false},
		{"commented-out", "[webserver]\n# instance_name_has_markup = True\n; warn_deployment_exposure = True\n", map[string]bool{}, true, false},
		{"continuation-line-is-not-an-option", "[core]\nplugins_folder = a\n  instance_name_has_markup = True\n", map[string]bool{}, true, false},
		{"comments-only", "# nothing\n", map[string]bool{}, true, false},
		{"case-variant-key", "[webserver]\nInstance_Name_Has_Markup = True\n", nil, false, false},
		{"cmd-variant", "[webserver]\ninstance_name_has_markup_cmd = echo True\n", nil, false, false},
		{"secret-variant", "[webserver]\nwarn_deployment_exposure_secret = x\n", nil, false, false},
		{"case-variant-section", "[WebServer]\ninstance_name_has_markup = True\n", nil, false, false},
		{"duplicate-section", "[webserver]\nbase_url = a\n[webserver]\ninstance_name_has_markup = True\n", nil, false, false},
		{"duplicate-key", "[webserver]\ninstance_name_has_markup = True\ninstance_name_has_markup = False\n", nil, false, false},
		{"default-section-key", "[DEFAULT]\ninstance_name_has_markup = True\n", nil, false, false},
		{"default-section-unrelated", "[DEFAULT]\nfoo = bar\n[core]\nexecutor = LocalExecutor\n", map[string]bool{}, true, false},
		{"indented-header", "[core]\nexecutor = a\n  [webserver]\n", map[string]bool{}, true, false},
		{"malformed-header", "[webserver\ninstance_name_has_markup = True\n", nil, false, false},
		{"option-before-section", "instance_name_has_markup = True\n", nil, false, true},
		{"option-without-delimiter", "[webserver]\ninstance_name_has_markup\n", nil, false, true},
		{"configmap-wrapper", "apiVersion: v1\nkind: ConfigMap\ndata:\n  airflow.cfg: |\n    [webserver]\n    base_url = x\n", nil, false, true},
		{"helm-values-wrapper", "config:\n  webserver:\n    base_url: x\n", nil, false, true},
		{"yaml-document-marker", "---\ndata:\n  airflow.cfg: |\n    [core]\n", nil, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, supported, err := scanAirflowCfg([]byte(tc.raw), airflowRemovedKeys)
			if (err != nil) != tc.invalid || supported != tc.supported {
				t.Fatalf("supported=%t err=%v", supported, err)
			}
			if tc.supported && !sameSet(got, tc.want) {
				t.Fatalf("found=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestScanOpenSearchYAML(t *testing.T) {
	t.Parallel()
	const expected = "component.opensearch.gateway_expected_nodes_present"
	const afterMaster = "component.opensearch.gateway_recover_after_master_nodes_present"
	for _, tc := range []struct {
		name, raw string
		want      map[string]bool
		supported bool
		invalid   bool
	}{
		{"dotted", "gateway.expected_nodes: 3\n", map[string]bool{expected: true}, true, false},
		{"nested", "gateway:\n  expected_nodes: 3\n", map[string]bool{expected: true}, true, false},
		{"flow-mapping", "gateway: {expected_nodes: 3}\n", map[string]bool{expected: true}, true, false},
		{"two-keys", "gateway:\n  expected_nodes: 3\n  recover_after_master_nodes: 2\n", map[string]bool{expected: true, afterMaster: true}, true, false},
		{"null-value-still-set", "gateway.expected_nodes:\n", map[string]bool{expected: true}, true, false},
		{"absent", "cluster.name: demo\nnode.name: n1\n", map[string]bool{}, true, false},
		{"empty-yaml", "# only a comment\n", map[string]bool{}, true, false},
		{"retained-sibling-settings", "gateway:\n  expected_data_nodes: 3\n  recover_after_data_nodes: 2\n  recover_after_time: 5m\n", map[string]bool{}, true, false},
		{"unrelated-prefix-sibling", "gateway.expected_nodes_total: 3\n", map[string]bool{}, true, false},
		{"sequence-value-elsewhere", "discovery.seed_hosts:\n  - a\n  - b\n", map[string]bool{}, true, false},
		{"same-text-in-value", "node.attr.note: gateway.expected_nodes\n", map[string]bool{}, true, false},
		{"case-variant-dotted", "Gateway.Expected_Nodes: 3\n", nil, false, false},
		{"case-variant-nested", "Gateway:\n  expected_nodes: 3\n", nil, false, false},
		{"both-forms-repeat", "gateway.expected_nodes: 3\ngateway:\n  expected_nodes: 4\n", nil, false, false},
		{"mapping-on-key", "gateway.expected_nodes:\n  a: 1\n", nil, false, false},
		{"key-below-key", "gateway.expected_nodes.x: 1\n", nil, false, false},
		{"scalar-on-prefix", "gateway: 3\n", nil, false, false},
		{"anchor", "base: &a\n  x: 1\ngateway:\n  expected_nodes: 3\n", nil, false, false},
		{"alias", "base: &a 1\ngateway.expected_nodes: *a\n", nil, false, false},
		{"tag", "gateway.expected_nodes: !!str 3\n", nil, false, false},
		{"merge-key", "base:\n  x: 1\n<<: {gateway.expected_nodes: 3}\n", nil, false, false},
		{"two-documents", "a: 1\n---\ngateway.expected_nodes: 3\n", nil, false, false},
		{"root-sequence", "- gateway.expected_nodes\n", nil, false, false},
		{"malformed", "gateway: [\n", nil, false, true},
		{"helm-values-wrapper", "config:\n  opensearch.yml: |\n    cluster.name: demo\n", nil, false, false},
		{"helm-values-wrapper-nested", "opensearchConfig:\n  cluster.name: demo\nreplicas: 3\n", nil, false, false},
		{"configmap-wrapper", "apiVersion: v1\nkind: ConfigMap\ndata:\n  opensearch.yml: |\n    cluster.name: demo\n", nil, false, false},
		{"one-unknown-top-level-key", "cluster.name: demo\nreplicas: 3\n", nil, false, false},
		{"umbrella-values-opensearch-block-scalar", "opensearch:\n  config:\n    opensearch.yml: |\n      gateway.expected_nodes: 3\n", nil, false, false},
		{"umbrella-values-cluster-key", "cluster:\n  config:\n    opensearch.yml: |\n      cluster.name: x\n", nil, false, false},
		{"umbrella-values-nested-mapping", "opensearch:\n  config:\n    gateway.expected_nodes: 3\n", nil, false, false},
		{"quoted-multiline-embedded-file", "node:\n  conf: \"gateway.expected_nodes: 3\\nnode.name: x\"\n", nil, false, false},
		{"file-name-key-under-known-namespace", "path:\n  opensearch.yml: x\n", nil, false, false},
		{"known-namespaces-only", "cluster.name: demo\npath.data: /d\nplugins.security.ssl.http.enabled: true\n", map[string]bool{}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, supported, err := scanOpenSearchYAML([]byte(tc.raw), openSearchRemovedKeys)
			if (err != nil) != tc.invalid || supported != tc.supported {
				t.Fatalf("supported=%t err=%v", supported, err)
			}
			if tc.supported && !sameSet(got, tc.want) {
				t.Fatalf("found=%v want=%v", got, tc.want)
			}
		})
	}
}

func sameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func TestPrepareAirflowConfigDeclarations(t *testing.T) {
	t.Parallel()
	set := "[webserver]\ninstance_name_has_markup = secret-marker\n"
	prepared, err := prepareAirflowConfig([]byte(set), "3.0.6", "3.1.0", true, true)
	if err != nil || prepared.State != "PREPARED" {
		t.Fatalf("prepared=%+v err=%v", prepared, err)
	}
	if got := declared(t, prepared, "component.airflow.webserver_instance_name_has_markup_present"); !strings.Contains(got, `"boolValue":true`) {
		t.Fatalf("set fact=%s", got)
	}
	for _, other := range []string{"component.airflow.api_enable_xcom_deserialize_support_present", "component.airflow.scheduler_dag_stale_not_seen_duration_present", "component.airflow.webserver_warn_deployment_exposure_present"} {
		if got := declared(t, prepared, other); !strings.Contains(got, `"boolValue":false`) {
			t.Fatalf("%s fact=%s", other, got)
		}
	}
	if bytes.Contains(prepared.CanonicalInputJSON, []byte("secret-marker")) {
		t.Fatal("raw config value leaked into canonical input")
	}
	for _, tc := range []struct {
		name               string
		complete, resolved bool
		from, to           string
		raw, reason        string
	}{
		{"incomplete", false, true, "3.0.6", "3.1.0", set, "EFFECTIVE_CONFIG_INCOMPLETE_OR_PRECEDENCE_UNRESOLVED"},
		{"unresolved", true, false, "3.0.6", "3.1.0", set, "EFFECTIVE_CONFIG_INCOMPLETE_OR_PRECEDENCE_UNRESOLVED"},
		{"unsupported-shape", true, true, "3.0.6", "3.1.0", "[webserver]\nInstance_Name_Has_Markup = x\n", "AIRFLOW_CFG_SHAPE_UNSUPPORTED"},
	} {
		got, err := prepareAirflowConfig([]byte(tc.raw), tc.from, tc.to, tc.complete, tc.resolved)
		if err != nil || got.State != "UNKNOWN" || got.Reason != tc.reason || bytes.Contains(got.CanonicalInputJSON, []byte(`"boolValue"`)) {
			t.Fatalf("%s: %+v err=%v input=%s", tc.name, got, err, got.CanonicalInputJSON)
		}
	}
	for _, bad := range []struct{ raw, from, to string }{{"", "3.0.6", "3.1.0"}, {set, "x", "3.1.0"}, {"[webserver]\x00\n", "3.0.6", "3.1.0"}} {
		if _, err := prepareAirflowConfig([]byte(bad.raw), bad.from, bad.to, true, true); err == nil {
			t.Fatalf("accepted %q", bad.raw)
		}
	}
	if _, err := PrepareEffectiveConfig(AirflowProject, []byte(set), "3.0.6", "3.1.0", true, true); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareOpenSearchConfigDeclarations(t *testing.T) {
	t.Parallel()
	set := "cluster.name: secret-marker\ngateway:\n  recover_after_nodes: 2\n"
	prepared, err := prepareOpenSearchConfig([]byte(set), "2.19.7", "3.0.0", true, true)
	if err != nil || prepared.State != "PREPARED" {
		t.Fatalf("prepared=%+v err=%v", prepared, err)
	}
	if got := declared(t, prepared, "component.opensearch.gateway_recover_after_nodes_present"); !strings.Contains(got, `"boolValue":true`) {
		t.Fatalf("set fact=%s", got)
	}
	for _, other := range []string{"component.opensearch.gateway_expected_nodes_present", "component.opensearch.gateway_expected_master_nodes_present", "component.opensearch.gateway_recover_after_master_nodes_present"} {
		if got := declared(t, prepared, other); !strings.Contains(got, `"boolValue":false`) {
			t.Fatalf("%s fact=%s", other, got)
		}
	}
	if bytes.Contains(prepared.CanonicalInputJSON, []byte("secret-marker")) {
		t.Fatal("raw config value leaked into canonical input")
	}
	for _, tc := range []struct {
		name               string
		complete, resolved bool
		from, to           string
		raw, reason        string
	}{
		{"incomplete", false, true, "2.19.7", "3.0.0", set, "EFFECTIVE_CONFIG_INCOMPLETE_OR_PRECEDENCE_UNRESOLVED"},
		{"unresolved", true, false, "2.19.7", "3.0.0", set, "EFFECTIVE_CONFIG_INCOMPLETE_OR_PRECEDENCE_UNRESOLVED"},
		{"unsupported-shape", true, true, "2.19.7", "3.0.0", "base: &a 1\ngateway.expected_nodes: *a\n", "OPENSEARCH_YML_SHAPE_UNSUPPORTED"},
	} {
		got, err := prepareOpenSearchConfig([]byte(tc.raw), tc.from, tc.to, tc.complete, tc.resolved)
		if err != nil || got.State != "UNKNOWN" || got.Reason != tc.reason || bytes.Contains(got.CanonicalInputJSON, []byte(`"boolValue"`)) {
			t.Fatalf("%s: %+v err=%v input=%s", tc.name, got, err, got.CanonicalInputJSON)
		}
	}
	if _, err := PrepareEffectiveConfig(OpenSearchProject, []byte(set), "2.19.7", "3.0.0", true, true); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareOpenSearchConfig([]byte("gateway: [\n"), "2.19.7", "3.0.0", true, true); err == nil {
		t.Fatal("malformed YAML accepted")
	}
}

// TestRemovedKeysFailClosed pins that a removed key's name, or a wrapped file,
// never yields a PASS-capable preparation unless the file is the plain bare
// config in which the scanner saw the setting itself.
func TestRemovedKeysFailClosed(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, project, raw string
		prepared           bool
	}{
		{"os-umbrella-block-scalar", OpenSearchProject, "opensearch:\n  config:\n    opensearch.yml: |\n      gateway.expected_nodes: 3\n", false},
		{"os-file-name-key", OpenSearchProject, "opensearch.yml: \"gateway.expected_nodes: 3\"\n", false},
		{"os-nested-config-mapping", OpenSearchProject, "opensearch:\n  config:\n    gateway.expected_nodes: 3\n", false},
		{"os-list-of-mappings", OpenSearchProject, "plugins:\n  - gateway.expected_nodes: 3\n", false},
		{"os-extra-envs", OpenSearchProject, "extraEnvs:\n  - name: gateway.recover_after_nodes\n    value: \"2\"\n", false},
		{"os-name-in-value", OpenSearchProject, "node.attr.note: gateway.expected_nodes\n", false},
		{"os-name-in-sibling", OpenSearchProject, "gateway.expected_nodes_total: 3\n", false},
		{"os-name-under-other-path", OpenSearchProject, "cluster.routing:\n  gateway:\n    expected_nodes: 3\n", false},
		{"os-widened-namespaces", OpenSearchProject, "search_backpressure.mode: enforced\ngrpc.port: 9400\nknn.memory.circuit_breaker.limit: 50%\ncluster_manager.throttling.thresholds.x: 1\nshard_indexing_pressure.enabled: true\ntcp.no_delay: true\n", true},
		{"os-plain-absent", OpenSearchProject, "cluster.name: demo\nnode.name: n1\npath.data: /d\ndiscovery.seed_hosts:\n  - a\n  - b\n", true},
		{"af-name-in-other-section", AirflowProject, "[core]\ninstance_name_has_markup = True\n", false},
		{"af-name-commented-out", AirflowProject, "[webserver]\n# instance_name_has_markup = True\n", false},
		{"af-name-in-value", AirflowProject, "[core]\nnote = warn_deployment_exposure\n", false},
		{"af-plain-absent", AirflowProject, "[core]\nexecutor = LocalExecutor\n[webserver]\nbase_url = x\n", true},
	} {
		got, err := PrepareEffectiveConfig(tc.project, []byte(tc.raw), map[string]string{OpenSearchProject: "2.19.7", AirflowProject: "3.0.6"}[tc.project], map[string]string{OpenSearchProject: "3.0.0", AirflowProject: "3.1.0"}[tc.project], true, true)
		if err != nil {
			t.Fatalf("%s: err=%v", tc.name, err)
		}
		if tc.prepared != (got.State == "PREPARED") {
			t.Fatalf("%s: state=%s reason=%s", tc.name, got.State, got.Reason)
		}
		if !tc.prepared && bytes.Contains(got.CanonicalInputJSON, []byte(`"boolValue"`)) {
			t.Fatalf("%s: declared a value: %s", tc.name, got.CanonicalInputJSON)
		}
	}
}
