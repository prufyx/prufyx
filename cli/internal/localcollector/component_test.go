// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const prometheusV3Image = "prom/prometheus:v3.1.0@sha256:0ea5254abf85f87901e8cfbd18fd243c59162c338ce0acd86aa2b0153d83dce2"

func workload(kind string, containers, init []any) any {
	return map[string]any{"items": []any{map[string]any{"kind": kind, "spec": map[string]any{"template": map[string]any{"spec": map[string]any{"containers": containers, "initContainers": init}}}}}}
}

func TestEmbeddedAdapterRegistriesMatchShippedDataContracts(t *testing.T) {
	for _, name := range []string{"component-configuration-adapters.json", "component-configuration-adapters-v3.json"} {
		embedded, err := assets.ReadFile("assets/" + name)
		if err != nil {
			t.Fatal(err)
		}
		shipped, err := os.ReadFile(filepath.Join("..", "..", "scripts", name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(embedded, shipped) {
			t.Fatalf("embedded and shipped adapter registries differ: %s", name)
		}
	}
}

func TestProjectWorkloadV2AndPrivacy(t *testing.T) {
	adapter, err := loadAdapterAssets("v2")
	if err != nil {
		t.Fatal(err)
	}
	root := workload("Deployment", []any{
		map[string]any{"image": "docker.io/prom/prometheus:v2.55.1", "args": []any{"--web.enable-admin-api", "--log.level=warn"}},
		map[string]any{"image": "private.invalid/team/private:secret", "args": []any{"--private=secret"}},
	}, nil)
	result, err := projectWorkload(root, adapter, "v2", testNow)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(result)
	for _, private := range []string{"private.invalid", "team/private", "--private", "secret"} {
		if strings.Contains(string(raw), private) {
			t.Fatalf("private input %q escaped: %s", private, raw)
		}
	}
	images, _ := array(result["publicImages"])
	if len(images) != 1 || at(images[0], "componentId") != "pkg:oci/prometheus/prometheus" {
		t.Fatalf("public images=%#v", images)
	}
	rows, _ := array(result["configuration"])
	if len(rows) != 1 || at(rows[0], "predicates", "component.prometheus.web_admin_api_enabled") != true || at(rows[0], "predicates", "component.prometheus.log_level") != "warn" {
		t.Fatalf("configuration=%#v", rows)
	}
	omissions, _ := array(result["omissions"])
	if len(omissions) != 1 || at(omissions[0], "code") != "COMPONENT_CONFIGURATION_IDENTITY_UNRESOLVED" {
		t.Fatalf("omissions=%#v", omissions)
	}
}

func TestProjectWorkloadV3SourceBoundPrometheus(t *testing.T) {
	adapter, err := loadAdapterAssets("v3")
	if err != nil {
		t.Fatal(err)
	}
	image := "prom/prometheus:v2.55.1@sha256:f4def6b3b61109a6eeea59945d578bb7e926c36cb0e036a23e3ceb8b6de024ad"
	result, err := projectWorkload(workload("Deployment", []any{map[string]any{"image": image, "args": []any{"--enable-feature=agent"}}}, nil), adapter, "v3", testNow)
	if err != nil {
		t.Fatal(err)
	}
	rows, _ := array(result["configuration"])
	if len(rows) != 1 {
		t.Fatalf("configuration=%#v omissions=%#v", rows, result["omissions"])
	}
	if at(rows[0], "observedVersion") != "2.55.1" || at(rows[0], "predicates", "component.prometheus.agent_mode") != true || at(rows[0], "predicates", "component.prometheus.image_digest") != "sha256:f4def6b3b61109a6eeea59945d578bb7e926c36cb0e036a23e3ceb8b6de024ad" {
		t.Fatalf("row=%#v", rows[0])
	}
}

func TestProjectWorkloadV3PrometheusArgumentBoundaries(t *testing.T) {
	type testCase struct {
		name                string
		commandSet, argsSet bool
		command, args       any
		extraRegularImage   string
		initImage           string
		want                string
	}
	wide := strings.Repeat("é", 257)
	cases := []testCase{
		{name: "absent command and args", want: "false"},
		{name: "null command", commandSet: true, command: nil, want: "unknown"},
		{name: "empty command", commandSet: true, command: []string{}, want: "unknown"},
		{name: "exact command absent args", commandSet: true, command: []string{"/bin/prometheus"}, want: "false"},
		{name: "null args", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: nil, want: "unknown"},
		{name: "empty args", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{}, want: "false"},
		{name: "empty token", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{""}, want: "unknown"},
		{name: "empty split value", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{"--config.file", "", "--agent"}, want: "unknown"},
		{name: "utf8 over 512 bytes", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{wide}, want: "unknown"},
		{name: "duplicate agent", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{"--agent", "--agent"}, want: "unknown"},
		{name: "legacy and agent", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{"--enable-feature=agent", "--agent"}, want: "true"},
		{name: "interpolation", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{"$(MODE)"}, want: "unknown"},
		{name: "terminator", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{"--", "--agent"}, want: "unknown"},
		{name: "split value", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{"--config.file", "/path", "--agent"}, want: "true"},
		{name: "leading positional", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{"unexpected-positional", "--agent"}, want: "unknown"},
		{name: "consecutive positional", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{"--config.file", "/path", "extra", "--agent"}, want: "unknown"},
		{name: "split agent", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{"--agent", "true"}, want: "unknown"},
		{name: "assigned agent", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{"--agent=true"}, want: "unknown"},
		{name: "no agent", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{"--no-agent"}, want: "unknown"},
		{name: "inline unrelated", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{"--web.listen-address=:9090", "--agent"}, want: "true"},
		{name: "regular public host alias", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{"--agent"}, extraRegularImage: "index.docker.io/" + prometheusV3Image, want: "unknown"},
		{name: "regular public unsupported tag", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{"--agent"}, extraRegularImage: "prom/prometheus:latest", want: "unknown"},
		{name: "init public host alias", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{"--agent"}, initImage: "index.docker.io/" + prometheusV3Image, want: "unknown"},
		{name: "init public unprefixed tag", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{"--agent"}, initImage: strings.Replace(prometheusV3Image, ":v3.1.0", ":3.1.0", 1), want: "unknown"},
	}
	assets, err := loadAdapterAssets("v3")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			container := map[string]any{"image": prometheusV3Image}
			if tc.commandSet {
				container["command"] = tc.command
			}
			if tc.argsSet {
				container["args"] = tc.args
			}
			containers := []any{container}
			if tc.extraRegularImage != "" {
				containers = append(containers, map[string]any{"image": tc.extraRegularImage})
			}
			initContainers := []any{}
			if tc.initImage != "" {
				initContainers = append(initContainers, map[string]any{"image": tc.initImage})
			}
			raw, err := json.Marshal(workload("Deployment", containers, initContainers))
			if err != nil {
				t.Fatal(err)
			}
			normalized, err := DecodeStrict(raw)
			if err != nil {
				t.Fatal(err)
			}
			result, err := projectWorkload(normalized, assets, "v3", testNow)
			if err != nil {
				t.Fatal(err)
			}
			got := "unknown"
			rows, _ := array(result["configuration"])
			if len(rows) == 1 {
				if value, ok := at(rows[0], "predicates", "component.prometheus.agent_mode").(bool); ok {
					got = "false"
					if value {
						got = "true"
					}
				}
			}
			if got != tc.want {
				t.Fatalf("agent mode=%s want=%s; configuration=%#v omissions=%#v", got, tc.want, rows, result["omissions"])
			}
		})
	}
}

func TestProjectWorkloadV3RejectsAliasAndAmbiguousRole(t *testing.T) {
	adapter, err := loadAdapterAssets("v3")
	if err != nil {
		t.Fatal(err)
	}
	alias := "index.docker.io/prom/prometheus:v2.55.1@sha256:f4def6b3b61109a6eeea59945d578bb7e926c36cb0e036a23e3ceb8b6de024ad"
	result, err := projectWorkload(workload("Deployment", []any{map[string]any{"image": alias, "args": []any{}}}, nil), adapter, "v3", testNow)
	if err != nil {
		t.Fatal(err)
	}
	rows, _ := array(result["configuration"])
	if len(rows) != 0 {
		t.Fatalf("alias gained authority: %#v", rows)
	}
	image := "prom/prometheus:v2.55.1@sha256:f4def6b3b61109a6eeea59945d578bb7e926c36cb0e036a23e3ceb8b6de024ad"
	result, err = projectWorkload(workload("Deployment", []any{map[string]any{"image": image, "args": []any{}}, map[string]any{"image": image, "args": []any{}}}, nil), adapter, "v3", testNow)
	if err != nil {
		t.Fatal(err)
	}
	rows, _ = array(result["configuration"])
	if len(rows) != 0 {
		t.Fatalf("ambiguous role retained: %#v", rows)
	}
	omissions, _ := array(result["omissions"])
	found := false
	for _, o := range omissions {
		found = found || at(o, "code") == "COMPONENT_CONFIGURATION_DECLARED_ROLE_AMBIGUOUS"
	}
	if !found {
		t.Fatalf("missing ambiguity omission: %#v", omissions)
	}
}

func TestAggregateComponentConflictDropsPredicates(t *testing.T) {
	adapter, _ := loadAdapterAssets("v2")
	rows := []any{
		map[string]any{"componentId": "pkg:oci/test/test", "observedVersion": "1.0.0", "versionScheme": "tag", "observationCount": 1, "predicates": map[string]any{"x": true}},
		map[string]any{"componentId": "pkg:oci/test/test", "observedVersion": "2.0.0", "versionScheme": "tag", "observationCount": 1, "predicates": map[string]any{"x": false}},
	}
	result := aggregateComponents(adapter, "v2", rows, nil)
	components, _ := array(at(result, "components"))
	if len(components) != 1 || at(components[0], "versionConflict") != true {
		t.Fatalf("components=%#v", components)
	}
	predicates, _ := object(at(components[0], "predicates"))
	if len(predicates) != 0 {
		t.Fatalf("conflicting predicates retained: %#v", predicates)
	}
}

func TestAggregateV3DropsPrometheusWhenRequiredControllerReadFailed(t *testing.T) {
	adapter, _ := loadAdapterAssets("v3")
	rows := []any{
		map[string]any{"componentId": "pkg:oci/prometheus/prometheus", "observedVersion": "2.55.1", "versionScheme": "tag", "observationCount": 1, "predicates": map[string]any{"component.prometheus.agent_mode": false}},
		map[string]any{"componentId": "pkg:oci/argoproj/workflow-controller", "observedVersion": "3.7.3", "versionScheme": "tag", "observationCount": 1, "predicates": map[string]any{"component.argo_workflows.managed_namespace_configured": true}},
	}
	omissions := []any{componentFailure("deployment-images.json", "kubernetes_api_read_failed")}
	result := aggregateComponents(adapter, "v3", rows, omissions)
	components, _ := array(at(result, "components"))
	if len(components) != 1 || at(components[0], "componentId") != "pkg:oci/argoproj/workflow-controller" {
		t.Fatalf("components=%#v", components)
	}
	if !containsOmission(at(result, "omissions"), "COMPONENT_CONFIGURATION_DECLARED_ROLE_AMBIGUOUS") {
		t.Fatalf("missing aggregate ambiguity: %#v", at(result, "omissions"))
	}
}

func containsOmission(value any, code string) bool {
	rows, _ := array(value)
	for _, row := range rows {
		if at(row, "code") == code {
			return true
		}
	}
	return false
}
