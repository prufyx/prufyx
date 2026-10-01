// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProjectCertManagerRBACRedactsIdentity(t *testing.T) {
	root := map[string]any{"items": []any{
		map[string]any{
			"metadata": map[string]any{"name": "cert-manager-controller"},
			"rules": []any{map[string]any{
				"apiGroups": []any{"cert-manager.io"}, "resources": []any{"certificates"}, "verbs": []any{"get"},
			}},
		},
	}}
	projected, err := projectCertManager("cert-manager-rbac-surface.json", root)
	if err != nil {
		t.Fatal(err)
	}
	if at(projected, "controller", "certManagerAPIGroups") != true {
		t.Fatalf("projection=%#v", projected)
	}
	raw, _ := json.Marshal(projected)
	if strings.Contains(string(raw), "cert-manager-controller") {
		t.Fatalf("raw role escaped: %s", raw)
	}
}

func TestDeriveCertManagerPreservesUnknownDimensions(t *testing.T) {
	configuration := []any{map[string]any{
		"componentId": "pkg:oci/cert-manager/cert-manager", "observedVersion": "v1.17.2", "versionScheme": "tag",
	}}
	surfaces := map[string]any{
		"cert-manager-health.json": map[string]any{"desiredCount": 3, "readyCount": 2, "availableCount": 2},
	}
	row, omissions := deriveCertManager(configuration, surfaces, map[string]bool{"cert-manager-health.json": true})
	if row == nil || at(row, "predicates", "component.cert_manager.health_ready_count") != 2 {
		t.Fatalf("row=%#v", row)
	}
	if len(omissions) != 4 {
		t.Fatalf("omissions=%#v", omissions)
	}
	for _, key := range []string{
		"component.cert_manager.rbac_serviceaccounts_token_create",
		"component.cert_manager.metrics_scrape_path_present",
		"component.cert_manager.admission_webhook_v1",
	} {
		if at(row, "predicates", key) != nil {
			t.Fatalf("unavailable predicate %s synthesized", key)
		}
	}
}

func TestProjectCertManagerMonitorRequiresTargetIdentity(t *testing.T) {
	root := map[string]any{"items": []any{
		map[string]any{"spec": map[string]any{
			"selector":          map[string]any{"matchLabels": map[string]any{"app.kubernetes.io/name": "private"}},
			"namespaceSelector": map[string]any{"matchNames": []any{"cert-manager"}},
			"endpoints":         []any{map[string]any{"port": "http-metrics", "path": "/metrics"}},
		}},
	}}
	projected, err := projectCertManager("cert-manager-servicemonitors.json", root)
	if err != nil {
		t.Fatal(err)
	}
	if at(projected, "serviceMonitorPresent") != false {
		t.Fatalf("unbound monitor admitted: %#v", projected)
	}
}

func TestProjectCertManagerRejectsMalformedMonitorAndNamespaceTypes(t *testing.T) {
	monitor := map[string]any{"items": []any{map[string]any{"spec": map[string]any{
		"selector": map[string]any{"matchLabels": map[string]any{}}, "namespaceSelector": map[string]any{"matchNames": []any{}},
		"endpoints": []any{map[string]any{"path": true}},
	}}}}
	if _, err := projectCertManager("cert-manager-servicemonitors.json", monitor); err == nil {
		t.Fatal("non-string monitor path accepted")
	}
	targets := map[string]any{"items": []any{map[string]any{"kind": "Pod", "metadata": map[string]any{"namespace": 7}}}}
	if _, err := projectCertManager("cert-manager-monitor-targets.json", targets); err == nil {
		t.Fatal("non-string target namespace accepted")
	}
}
