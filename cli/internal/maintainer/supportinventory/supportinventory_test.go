// SPDX-License-Identifier: AGPL-3.0-only

package supportinventory

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func repositoryConfig(t *testing.T) (Config, string) {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return Config{
		Rules: filepath.Join(root, "internal/cncfcheck/data/rules.json"), Landscape: filepath.Join(root, "internal/cncfcheck/data/landscape-projects.json"),
		CertContract: filepath.Join(root, "internal/certmanagervalues/source-contract-v1.json"), PrometheusContract: filepath.Join(root, "internal/prometheusmode/source-contract-v1.json"),
		SPIFFEProfile: filepath.Join(root, "internal/spiffex509svid/data/profile.json"), CloudEventsProfile: filepath.Join(root, "internal/cloudeventsstructuredjson/data/profile.json"),
		TiKVProfile: filepath.Join(root, "internal/tikvgcpv2/data/profile.json"), CNCFPrepareSource: filepath.Join(root, "internal/communityapp/cncf_prepare.go"),
		ProjectRules: filepath.Join(root, "internal/projectcheck/data/rules.json"), ProjectRegistry: filepath.Join(root, "internal/projectcheck/data/projects.json"),
		SelectedSourceManifest: filepath.Join(root, "docs/data/selected-source-records-v1.json"),
	}, root
}

func TestSupportInventory_ArgoWorkflowsUsesWorkloadPreparerMetadata(t *testing.T) {
	cfg, _ := repositoryConfig(t)
	raw, _, err := Generate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Projects []struct {
			ProjectID    string `json:"projectID"`
			Capabilities []struct {
				Command []string `json:"command"`
				Rules   []struct {
					Limit string `json:"limit"`
				} `json:"rules"`
				LocalPreparer struct {
					MetadataState string `json:"metadataState"`
					Limit         string `json:"limit"`
				} `json:"localPreparer"`
			} `json:"capabilities"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	for _, project := range document.Projects {
		if project.ProjectID != "argo-workflows" {
			continue
		}
		if len(project.Capabilities) != 1 || len(project.Capabilities[0].Rules) != 6 || project.Capabilities[0].LocalPreparer.MetadataState != "implemented_native_kubernetes_workload_minimizer" || strings.Contains(project.Capabilities[0].LocalPreparer.Limit, "precedence") || !strings.Contains(project.Capabilities[0].Rules[0].Limit, "workload") {
			t.Fatalf("incorrect Argo Workflows inventory metadata: %#v", project.Capabilities)
		}
		return
	}
	t.Fatal("Argo Workflows inventory entry missing")
}

func TestSupportInventory_FluentBitUsesDeclaredClassicConfigurationMetadata(t *testing.T) {
	cfg, _ := repositoryConfig(t)
	raw, _, err := Generate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Projects []struct {
			ProjectID    string `json:"projectID"`
			Capabilities []struct {
				LocalPreparer struct {
					Command       []string `json:"command"`
					MetadataState string   `json:"metadataState"`
					Limit         string   `json:"limit"`
				} `json:"localPreparer"`
			} `json:"capabilities"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	for _, project := range document.Projects {
		if project.ProjectID != "fluent-bit" {
			continue
		}
		if len(project.Capabilities) != 1 {
			t.Fatalf("incorrect Fluent Bit capability count: %#v", project.Capabilities)
		}
		preparer := project.Capabilities[0].LocalPreparer
		for _, flag := range []string{"--effective-config-complete", "--current-default-was-used", "--preserve-http2-enabled"} {
			if !slices.Contains(preparer.Command, flag) {
				t.Fatalf("Fluent Bit declaration flag missing from discovery command %q: %#v", flag, preparer.Command)
			}
		}
		if preparer.MetadataState != "implemented_native_classic_configuration_minimizer" || strings.Contains(preparer.Limit, "environment and CLI precedence") || !strings.Contains(preparer.Limit, "only that setting") {
			t.Fatalf("incorrect Fluent Bit inventory metadata: %#v", preparer)
		}
		return
	}
	t.Fatal("Fluent Bit inventory entry missing")
}

func TestSupportInventory_MariaDBOperatorUsesResourcePreparerMetadata(t *testing.T) {
	cfg, _ := repositoryConfig(t)
	raw, _, err := Generate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Projects []struct {
			ProjectID    string `json:"projectID"`
			Capabilities []struct {
				Rules []struct {
					Limit string `json:"limit"`
				} `json:"rules"`
				LocalPreparer struct {
					Command       []string `json:"command"`
					MetadataState string   `json:"metadataState"`
					Limit         string   `json:"limit"`
				} `json:"localPreparer"`
			} `json:"capabilities"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	for _, project := range document.Projects {
		if project.ProjectID != "mariadb-operator" {
			continue
		}
		if len(project.Capabilities) != 1 || len(project.Capabilities[0].Rules) != 1 {
			t.Fatalf("incorrect MariaDB Operator capability shape: %#v", project.Capabilities)
		}
		preparer := project.Capabilities[0].LocalPreparer
		for _, flag := range []string{"--mariadb-resource", "--resource-complete", "--pre-operator-update", "--from", "26.3.0", "--to", "26.6.0"} {
			if !slices.Contains(preparer.Command, flag) {
				t.Fatalf("MariaDB Operator declaration flag missing from discovery command %q: %#v", flag, preparer.Command)
			}
		}
		if preparer.MetadataState != "implemented_native_mariadb_operator_resource_minimizer" || strings.Contains(preparer.Limit, "effective-configuration") || !strings.Contains(preparer.Limit, "data-plane completion") || !strings.Contains(project.Capabilities[0].Rules[0].Limit, "Galera-only") {
			t.Fatalf("incorrect MariaDB Operator inventory metadata: %#v", project.Capabilities)
		}
		return
	}
	t.Fatal("MariaDB Operator inventory entry missing")
}

func TestSupportInventory_NativeCNCFRoutesDescribeDirectInputs(t *testing.T) {
	cfg, _ := repositoryConfig(t)
	raw, _, err := Generate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Projects []struct {
			ProjectID    string `json:"projectID"`
			Capabilities []struct {
				LocalPreparer struct {
					Command       []string `json:"command"`
					MetadataState string   `json:"metadataState"`
					Limit         string   `json:"limit"`
				} `json:"localPreparer"`
			} `json:"capabilities"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		flag  string
		state string
	}{
		"thanos":     {"--native-resource", "implemented_native_kubernetes_workload_minimizer"},
		"cortex":     {"--native-resource", "implemented_native_kubernetes_workload_minimizer"},
		"nats":       {"--nats-config", "implemented_native_json_configuration_minimizer"},
		"flux":       {"--native-resource", "implemented_native_rendered_resource_minimizer"},
		"kubernetes": {"--target-api-apply-required", "implemented_native_rendered_resource_minimizer"},
		"cilium":     {"--cilium-config-map", "implemented_native_selected_configmap_minimizer"},
		"coredns":    {"--coredns-corefile", "implemented_native_selected_coredns_corefile_minimizer"},
		"envoy":      {"--envoy-bootstrap", "implemented_native_selected_envoy_bootstrap_minimizer"},
		"prometheus": {"--scrape-config", "implemented_native_selected_scrape_config_minimizer"},
	}
	for _, project := range document.Projects {
		expected, ok := want[project.ProjectID]
		if !ok {
			continue
		}
		matched := 0
		for _, capability := range project.Capabilities {
			if capability.LocalPreparer.MetadataState == expected.state && slices.Contains(capability.LocalPreparer.Command, expected.flag) && !strings.Contains(strings.Join(capability.LocalPreparer.Command, " "), "prepare") {
				matched++
			}
		}
		if matched != 1 {
			t.Fatalf("incorrect native route metadata for %s: %#v", project.ProjectID, project.Capabilities)
		}
		delete(want, project.ProjectID)
	}
	if len(want) != 0 {
		t.Fatalf("missing native route metadata: %#v", want)
	}
}

func TestSupportInventory_CoreDNSAndEnvoyNativeRouteScope(t *testing.T) {
	cfg, _ := repositoryConfig(t)
	raw, _, err := Generate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Projects []struct {
			ProjectID    string `json:"projectID"`
			Capabilities []struct {
				LocalPreparer struct {
					Command       []string `json:"command"`
					MetadataState string   `json:"metadataState"`
					Limit         string   `json:"limit"`
				} `json:"localPreparer"`
			} `json:"capabilities"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, project := range document.Projects {
		if project.ProjectID != "coredns" && project.ProjectID != "envoy" {
			continue
		}
		if len(project.Capabilities) != 1 {
			t.Fatalf("%s capability shape = %#v", project.ProjectID, project.Capabilities)
		}
		preparer := project.Capabilities[0].LocalPreparer
		switch project.ProjectID {
		case "coredns":
			for _, value := range []string{"--coredns-corefile", "--coredns-corefile-complete", "--coredns-distribution", "official", "1.13.2", "1.14.7"} {
				if !slices.Contains(preparer.Command, value) {
					t.Fatalf("CoreDNS route command missing %q: %#v", value, preparer)
				}
			}
			for _, text := range []string{"1.6.9 to 1.7.0", "1.9.4", "1.10.1", "1.11.4", "1.12.4", "1.13.2", "Imports", "custom distributions", "DNS behavior"} {
				if !strings.Contains(preparer.Limit, text) {
					t.Fatalf("CoreDNS route limit missing %q: %#v", text, preparer)
				}
			}
			if preparer.MetadataState != "implemented_native_selected_coredns_corefile_minimizer" {
				t.Fatalf("CoreDNS metadata state = %#v", preparer)
			}
		case "envoy":
			for _, value := range []string{"--envoy-bootstrap", "--envoy-bootstrap-selected", "1.38.4", "1.39.1"} {
				if !slices.Contains(preparer.Command, value) {
					t.Fatalf("Envoy route command missing %q: %#v", value, preparer)
				}
			}
			for _, text := range []string{"Blocker-only", "ADS, LDS, or CDS", "1.34.14", "1.35.13", "1.36.10", "1.37.6", "1.38.4", "V3", "AUTO", "no native PASS", "1.18 native route"} {
				if !strings.Contains(preparer.Limit, text) {
					t.Fatalf("Envoy route limit missing %q: %#v", text, preparer)
				}
			}
			if preparer.MetadataState != "implemented_native_selected_envoy_bootstrap_minimizer" {
				t.Fatalf("Envoy metadata state = %#v", preparer)
			}
		}
		found[project.ProjectID] = true
	}
	if !found["coredns"] || !found["envoy"] {
		t.Fatalf("missing CoreDNS or Envoy route: %#v", found)
	}
}

func TestSupportInventory_PrometheusListsIndependentNativeRoutes(t *testing.T) {
	cfg, _ := repositoryConfig(t)
	raw, _, err := Generate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Projects []struct {
			ProjectID    string `json:"projectID"`
			Capabilities []struct {
				LocalPreparer struct {
					Command       []string `json:"command"`
					MetadataState string   `json:"metadataState"`
					Limit         string   `json:"limit"`
				} `json:"localPreparer"`
				LocalPreparers []struct {
					Command       []string `json:"command"`
					MetadataState string   `json:"metadataState"`
					Limit         string   `json:"limit"`
				} `json:"localPreparers"`
			} `json:"capabilities"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	for _, project := range document.Projects {
		if project.ProjectID != "prometheus" {
			continue
		}
		if len(project.Capabilities) != 2 || project.Capabilities[0].LocalPreparer.MetadataState != "implemented_native_selected_scrape_config_minimizer" || len(project.Capabilities[0].LocalPreparers) != 3 {
			t.Fatalf("Prometheus native route inventory = %#v", project.Capabilities)
		}
		routes := map[string]struct {
			command []string
			limit   string
		}{}
		for _, route := range project.Capabilities[0].LocalPreparers {
			routes[route.MetadataState] = struct {
				command []string
				limit   string
			}{route.Command, route.Limit}
		}
		alertmanager, ok := routes["implemented_native_selected_alertmanager_config_minimizer"]
		if !ok || !slices.Contains(alertmanager.command, "--alertmanager-config") || !slices.Contains(alertmanager.command, "--alertmanager-config-complete") || !slices.Contains(alertmanager.command, "--alertmanager-config-precedence-resolved") || !slices.Contains(alertmanager.command, "--from") || !slices.Contains(alertmanager.command, "--to") || strings.Contains(strings.Join(alertmanager.command, " "), "--scrape-config") || !strings.Contains(alertmanager.limit, "api_version") || !strings.Contains(alertmanager.limit, "Alertmanager compatibility") {
			t.Fatalf("Alertmanager native route missing or overclaimed: %#v", alertmanager)
		}
		scrape, ok := routes["implemented_native_selected_scrape_config_minimizer"]
		legacy := project.Capabilities[0].LocalPreparer
		if !ok || !slices.Contains(scrape.command, "--scrape-config") || !slices.Contains(scrape.command, "--scrape-job") || !slices.Contains(scrape.command, "--scrape-config-complete") || !slices.Contains(scrape.command, "--scrape-config-precedence-resolved") || strings.Contains(strings.Join(scrape.command, " "), "--alertmanager-config") || !strings.Contains(scrape.limit, "scrape_config") || !slices.Equal(scrape.command, legacy.Command) || scrape.limit != legacy.Limit {
			t.Fatalf("scrape native route missing or overclaimed: %#v", scrape)
		}
		remoteWrite, ok := routes["implemented_native_selected_remote_write_http2_minimizer"]
		if !ok || !slices.Contains(remoteWrite.command, "--prometheus-config") || !slices.Contains(remoteWrite.command, "--prometheus-rule") || !slices.Contains(remoteWrite.command, "remote-write-http2-default") || !slices.Contains(remoteWrite.command, "--prometheus-remote-write-name") || !slices.Contains(remoteWrite.command, "--prometheus-remote-write-http2-required=true|false") || !strings.Contains(remoteWrite.limit, "direct inline enable_http2") || !strings.Contains(remoteWrite.limit, "protocol negotiation") {
			t.Fatalf("remote-write native route missing or overclaimed: %#v", remoteWrite)
		}
		return
	}
	t.Fatal("Prometheus inventory entry missing")
}

func TestSupportInventory_LokiListsIndependentNativeRoutes(t *testing.T) {
	cfg, _ := repositoryConfig(t)
	raw, _, err := Generate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Projects []struct {
			ProjectID    string `json:"projectID"`
			Capabilities []struct {
				LocalPreparer struct {
					Command       []string `json:"command"`
					MetadataState string   `json:"metadataState"`
					Limit         string   `json:"limit"`
				} `json:"localPreparer"`
				LocalPreparers []struct {
					Command       []string `json:"command"`
					MetadataState string   `json:"metadataState"`
					Limit         string   `json:"limit"`
				} `json:"localPreparers"`
			} `json:"capabilities"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	for _, project := range document.Projects {
		if project.ProjectID != "loki" {
			continue
		}
		if len(project.Capabilities) != 1 || project.Capabilities[0].LocalPreparer.MetadataState != "implemented_native_effective_config_minimizer" || len(project.Capabilities[0].LocalPreparers) != 2 {
			t.Fatalf("Loki native route inventory = %#v", project.Capabilities)
		}
		legacy := project.Capabilities[0].LocalPreparer
		routes := map[string]struct {
			command []string
			limit   string
		}{}
		for _, route := range project.Capabilities[0].LocalPreparers {
			routes[route.MetadataState] = struct {
				command []string
				limit   string
			}{route.Command, route.Limit}
		}
		compactor, ok := routes[legacy.MetadataState]
		if !ok || !slices.Equal(compactor.command, legacy.Command) || compactor.limit != legacy.Limit {
			t.Fatalf("legacy Loki compactor route not retained: %#v", legacy)
		}
		structured, ok := routes["implemented_native_selected_loki_schema_config_minimizer"]
		if !ok || !slices.Contains(structured.command, "--loki-schema-config") || !slices.Contains(structured.command, "--effective-config-complete") || !slices.Contains(structured.command, "--precedence-resolved") || strings.Contains(strings.Join(structured.command, " "), "--effective-config FILE") || !strings.Contains(structured.limit, "allow_structured_metadata") || !strings.Contains(structured.limit, "Multiple periods") {
			t.Fatalf("Loki structured-metadata route missing or overclaimed: %#v", structured)
		}
		return
	}
	t.Fatal("Loki inventory entry missing")
}

func TestSupportInventory_ArgoCDListsIndependentNativeRoutes(t *testing.T) {
	cfg, _ := repositoryConfig(t)
	raw, _, err := Generate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Projects []struct {
			ProjectID    string `json:"projectID"`
			Capabilities []struct {
				LocalPreparer struct {
					Command       []string `json:"command"`
					MetadataState string   `json:"metadataState"`
					Limit         string   `json:"limit"`
				} `json:"localPreparer"`
				LocalPreparers []struct {
					Command       []string `json:"command"`
					MetadataState string   `json:"metadataState"`
					Limit         string   `json:"limit"`
				} `json:"localPreparers"`
			} `json:"capabilities"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	for _, project := range document.Projects {
		if project.ProjectID != "argo-cd" {
			continue
		}
		if len(project.Capabilities) != 1 || len(project.Capabilities[0].LocalPreparers) != 3 {
			t.Fatalf("Argo CD native route inventory = %#v", project.Capabilities)
		}
		legacy := project.Capabilities[0].LocalPreparer
		if legacy.MetadataState != "implemented_local_minimizing_adapter" || !slices.Equal(legacy.Command, []string{"prepare", "cncf", "--project", "argo-cd"}) {
			t.Fatalf("legacy Argo CD preparer changed: %#v", legacy)
		}
		routes := map[string]struct {
			command []string
			limit   string
		}{}
		for _, route := range project.Capabilities[0].LocalPreparers {
			routes[route.MetadataState] = struct {
				command []string
				limit   string
			}{route.Command, route.Limit}
		}
		legacyRoute, ok := routes[legacy.MetadataState]
		if !ok || !slices.Equal(legacyRoute.command, legacy.Command) || legacyRoute.limit != legacy.Limit {
			t.Fatalf("legacy Argo CD route not retained: %#v", legacy)
		}
		rbac, ok := routes["implemented_native_selected_argocd_rbac_config_map_minimizer"]
		if !ok || !slices.Contains(rbac.command, "--config-map") || slices.Contains(rbac.command, "--resource-exclusions-config-map") || !strings.Contains(rbac.limit, "explicit RBAC intent") {
			t.Fatalf("Argo CD RBAC route missing or overclaimed: %#v", rbac)
		}
		exclusions, ok := routes["implemented_native_selected_argocd_resource_exclusions_minimizer"]
		if !ok || !slices.Contains(exclusions.command, "--resource-exclusions-config-map") || !slices.Contains(exclusions.command, "--resource-exclusions-config-complete") || !slices.Contains(exclusions.command, "--resource-exclusions-precedence-resolved") || !slices.Contains(exclusions.command, "--requires-v2-visibility-of-v3-default-excluded-resources") || strings.Contains(strings.Join(exclusions.command, " "), "--config-map") || !strings.Contains(exclusions.limit, "explicit v2-visibility-preservation intent") {
			t.Fatalf("Argo CD resource-exclusions route missing or overclaimed: %#v", exclusions)
		}
		return
	}
	t.Fatal("Argo CD inventory entry missing")
}

func TestSupportInventory_PrometheusNamedAndCNCFRuleCapabilitiesCoexist(t *testing.T) {
	cfg, _ := repositoryConfig(t)
	raw, _, err := Generate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Projects []struct {
			ProjectID    string `json:"projectID"`
			Capabilities []struct {
				Kind string `json:"kind"`
			} `json:"capabilities"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	for _, project := range document.Projects {
		if project.ProjectID != "prometheus" {
			continue
		}
		seen := map[string]bool{}
		for _, capability := range project.Capabilities {
			seen[capability.Kind] = true
		}
		if !seen["embedded_cncf_source_rule"] || !seen["named_local_check"] || len(project.Capabilities) != 2 {
			t.Fatalf("Prometheus capability union = %#v", project.Capabilities)
		}
		return
	}
	t.Fatal("Prometheus inventory entry missing")
}

func TestSupportInventory_CephUsesSelectedCurrentMetadata(t *testing.T) {
	cfg, _ := repositoryConfig(t)
	raw, _, err := Generate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Projects []struct {
			ProjectID    string `json:"projectID"`
			Capabilities []struct {
				Rules []struct {
					Limit string `json:"limit"`
				} `json:"rules"`
				LocalPreparer struct {
					Command       []string `json:"command"`
					MetadataState string   `json:"metadataState"`
					Limit         string   `json:"limit"`
				} `json:"localPreparer"`
			} `json:"capabilities"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	for _, project := range document.Projects {
		if project.ProjectID != "ceph" {
			continue
		}
		if len(project.Capabilities) != 1 || len(project.Capabilities[0].Rules) != 6 || project.Capabilities[0].LocalPreparer.MetadataState != "implemented_native_selected_current_osd_metadata_minimizer" || !slices.Contains(project.Capabilities[0].LocalPreparer.Command, "prepare") || !strings.Contains(project.Capabilities[0].Rules[0].Limit, "current-backend") || !strings.Contains(project.Capabilities[0].LocalPreparer.Limit, "selected current OSD") {
			t.Fatalf("incorrect Ceph inventory metadata: %#v", project.Capabilities)
		}
		return
	}
	t.Fatal("Ceph inventory entry missing")
}

// TestSupportInventory_WithdrawnRuleIsExcludedButListed exercises the real
// embedded corpus, where cri-o.artifact-short-name-rejected.1-35 is the
// project's only CNCF rule and has withdrawn evidence (unverifiable vendored
// distribution/reference citations). It establishes no executable claim, so
// the generator must not silently drop it: it excludes it from the
// project's executable capability (cri-o has no other CNCF rule, so cri-o
// itself carries no "executable" cncf_embedded_source_rule capability) while
// still reporting it explicitly in withdrawnRules and the withdrawn counts.
func TestSupportInventory_WithdrawnRuleIsExcludedButListed(t *testing.T) {
	cfg, _ := repositoryConfig(t)
	raw, markdown, err := Generate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Counts struct {
			CNCFSourceRules          int `json:"cncfSourceRules"`
			CNCFSourceRulesWithdrawn int `json:"cncfSourceRulesWithdrawn"`
		} `json:"counts"`
		WithdrawnRules []struct {
			RuleID     string `json:"ruleID"`
			Project    string `json:"project"`
			Family     string `json:"family"`
			ReasonCode string `json:"reasonCode"`
		} `json:"withdrawnRules"`
		Projects []struct {
			ProjectID    string `json:"projectID"`
			Capabilities []struct {
				Kind string `json:"kind"`
			} `json:"capabilities"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if document.Counts.CNCFSourceRulesWithdrawn != 1 {
		t.Fatalf("expected exactly one withdrawn CNCF rule, got %d", document.Counts.CNCFSourceRulesWithdrawn)
	}
	if len(document.WithdrawnRules) != 1 || document.WithdrawnRules[0].RuleID != "cri-o.artifact-short-name-rejected.1-35" || document.WithdrawnRules[0].Project != "cri-o" || document.WithdrawnRules[0].Family != "cncf_embedded_source_rule" || document.WithdrawnRules[0].ReasonCode != "RULE_EVIDENCE_WITHDRAWN" {
		t.Fatalf("unexpected withdrawnRules entry: %#v", document.WithdrawnRules)
	}
	for _, project := range document.Projects {
		if project.ProjectID != "cri-o" {
			continue
		}
		for _, cap := range project.Capabilities {
			if cap.Kind == "embedded_cncf_source_rule" {
				t.Fatalf("cri-o still carries an executable cncf_embedded_source_rule capability despite its only rule being withdrawn: %#v", project.Capabilities)
			}
		}
	}
	if !strings.Contains(markdown, "## Withdrawn rules") || !strings.Contains(markdown, "cri-o.artifact-short-name-rejected.1-35") || !strings.Contains(markdown, "RULE_EVIDENCE_WITHDRAWN") {
		t.Fatalf("expected markdown to list the withdrawn cri-o rule explicitly")
	}
}

func TestSupportInventory_Generate_MatchesAcceptedInventory(t *testing.T) {
	cfg, root := repositoryConfig(t)
	jsonOutput, markdownOutput, err := Generate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	wantJSON, err := os.ReadFile(filepath.Join(root, "docs/generated/community-support-inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(jsonOutput, wantJSON) {
		t.Fatalf("generated JSON differs: got %d bytes want %d", len(jsonOutput), len(wantJSON))
	}
	wantMarkdown, err := os.ReadFile(filepath.Join(root, "docs/generated/community-support-inventory.md"))
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(string(wantMarkdown), "Generated by `scripts/generate_support_inventory.py`; do not edit by hand.", "Generated by `cmd/prufyx-maintainer`; do not edit by hand.", 1)
	if markdownOutput != want {
		t.Fatalf("generated Markdown differs: got %d bytes want %d", len(markdownOutput), len(want))
	}
}

func TestSupportInventory_Generate_RejectsMalformedPresentLatestCertContract(t *testing.T) {
	for name, latest := range map[string]string{"malformed": "{", "empty object": "{}"} {
		t.Run(name, func(t *testing.T) {
			cfg, root := repositoryConfig(t)
			tmp := t.TempDir()
			legacy, err := os.ReadFile(filepath.Join(root, "internal/certmanagervalues/source-contract-v1.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(tmp, "source-contract-v1.json"), legacy, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(tmp, "source-contract-v1-latest.json"), []byte(latest), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg.CertContract = filepath.Join(tmp, "source-contract-v1.json")
			if _, _, err := Generate(cfg); err == nil || !strings.Contains(err.Error(), "invalid") {
				t.Fatalf("present latest contract was not rejected: %v", err)
			}
		})
	}
}

func TestSupportInventory_Generate_PreservesLegacyWhenLatestCertContractIsAbsent(t *testing.T) {
	cfg, root := repositoryConfig(t)
	tmp := t.TempDir()
	legacy, err := os.ReadFile(filepath.Join(root, "internal/certmanagervalues/source-contract-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	legacyPath := filepath.Join(tmp, "source-contract-v1.json")
	if err := os.WriteFile(legacyPath, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.CertContract = legacyPath
	raw, _, err := Generate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "certManagerLatestSourceContract") {
		t.Fatal("absent latest contract changed legacy inventory")
	}
}

func TestSupportInventory_Generate_ExposesLatestCertProvenanceAndEvidence(t *testing.T) {
	cfg, _ := repositoryConfig(t)
	raw, _, err := Generate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{"certManagerLatestSourceContract", "c45dfe0ea426db2b7f2d938f19bd80ae08f0e97817d780554b9614c5401835a6", "latest-target-values-schema", "target-values-schema"} {
		if !strings.Contains(text, want) {
			t.Fatalf("generated inventory missing %q", want)
		}
	}
}

func TestSupportInventory_DecodeStrict_RejectsDuplicateFields(t *testing.T) {
	if _, err := decodeStrict([]byte(`{"schema":"one","schema":"two"}`)); err == nil {
		t.Fatal("expected duplicate field rejection")
	}
}

func TestSupportInventory_PreparerProjects_ReadsCallableDispatchOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cncf_prepare.go")
	raw := "package communityapp\nfunc prepare(project *string, raw []byte) {\n\tswitch *project {\n\tcase \"validation-only\":\n\t}\n\tvar prepared cncfprepare.Prepared\n\tswitch *project {\n\tcase \"callable\", \"grouped\":\n\t\tprepared, err = cncfprepare.PrepareCallable(raw)\n\t}\n}\n"
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	projects, err := preparerProjects([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(projects) != 2 || !projects["callable"] || !projects["grouped"] {
		t.Fatalf("unexpected projects: %#v", projects)
	}
}

func TestSupportInventory_Generate_BindsPreparerSourceDigest(t *testing.T) {
	cfg, _ := repositoryConfig(t)
	raw, _, err := Generate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var baseline struct {
		InputDigests map[string]string `json:"inputDigests"`
	}
	if err := json.Unmarshal(raw, &baseline); err != nil {
		t.Fatal(err)
	}
	if baseline.InputDigests["cncfPreparerDispatchSource"] == "" {
		t.Fatal("preparer source digest missing")
	}

	source, err := os.ReadFile(cfg.CNCFPrepareSource)
	if err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(t.TempDir(), "cncf_prepare.go")
	if err := os.WriteFile(copyPath, append(source, []byte("\n// digest regression fixture\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.CNCFPrepareSource = copyPath
	changed, _, err := Generate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var modified struct {
		InputDigests map[string]string `json:"inputDigests"`
	}
	if err := json.Unmarshal(changed, &modified); err != nil {
		t.Fatal(err)
	}
	if modified.InputDigests["cncfPreparerDispatchSource"] == baseline.InputDigests["cncfPreparerDispatchSource"] {
		t.Fatal("preparer source change did not change provenance digest")
	}
}

func TestSupportInventory_ConformanceProfile_RejectsMalformedRuleWithoutPanic(t *testing.T) {
	profile := map[string]any{"rules": []any{"not-an-object"}}
	if err := requireSingleRule(profile, "expected"); err == nil {
		t.Fatal("expected malformed rule rejection")
	}
}
