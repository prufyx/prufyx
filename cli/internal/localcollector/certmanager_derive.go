// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

func deriveCertManager(configuration []any, surfaces map[string]any, available map[string]bool) (any, []any) {
	versions := map[string]bool{}
	hasComponent := false
	for _, value := range configuration {
		if at(value, "componentId") != "pkg:oci/cert-manager/cert-manager" {
			continue
		}
		hasComponent = true
		if version, ok := at(value, "observedVersion").(string); ok {
			versions[version] = true
		}
	}
	if !hasComponent {
		return nil, nil
	}
	predicates := map[string]any{"component.cert_manager.install_mode": "unknown"}
	omissions := []any{}

	crdAvailable := available["crd-api-surface.json"]
	validCRDs := 0
	if crdAvailable {
		items, _ := array(surfaces["crd-api-surface.json"])
		for _, wanted := range []struct{ group, plural, stem string }{
			{"cert-manager.io", "certificates", "component.cert_manager.crd_certificates_v1"},
			{"cert-manager.io", "certificaterequests", "component.cert_manager.crd_certificaterequests_v1"},
			{"cert-manager.io", "issuers", "component.cert_manager.crd_issuers_v1"},
			{"cert-manager.io", "clusterissuers", "component.cert_manager.crd_clusterissuers_v1"},
			{"acme.cert-manager.io", "challenges", "component.cert_manager.crd_challenges_v1"},
			{"acme.cert-manager.io", "orders", "component.cert_manager.crd_orders_v1"},
		} {
			matches := []any{}
			for _, item := range items {
				if at(item, "group") == wanted.group && at(item, "plural") == wanted.plural {
					matches = append(matches, item)
				}
			}
			if len(matches) != 1 {
				continue
			}
			versions, _ := array(at(matches[0], "versions"))
			for _, version := range versions {
				if at(version, "name") == "v1" && at(version, "served") == true {
					if storage, ok := at(version, "storage").(bool); ok {
						predicates[wanted.stem+"_served"] = true
						predicates[wanted.stem+"_storage"] = storage
						validCRDs++
					}
				}
			}
		}
	}
	if !crdAvailable || validCRDs != 6 {
		omissions = append(omissions, newProjectionOmission("COMPONENT_CONFIGURATION_CRD_SURFACE_UNAVAILABLE", "The exact six cert-manager CRD served/storage surface was unavailable or incomplete."))
	}

	webhookAvailable := available["validating-webhooks.json"] && available["mutating-webhooks.json"]
	if webhookAvailable {
		v1, fail, identity := false, false, false
		for _, name := range []string{"validating-webhooks.json", "mutating-webhooks.json"} {
			lists, _ := array(surfaces[name])
			for _, item := range lists {
				hooks, _ := array(at(item, "webhooks"))
				for _, hook := range hooks {
					if at(hook, "identityPresent") != true || !webhookTargetsCertManager(hook) {
						continue
					}
					identity = true
					if at(hook, "failurePolicy") == "Fail" {
						fail = true
					}
					versions, _ := array(at(hook, "admissionReviewVersions"))
					if contains(versions, any("v1")) {
						v1 = true
					}
				}
			}
		}
		predicates["component.cert_manager.admission_webhook_v1"] = v1
		predicates["component.cert_manager.admission_webhook_failure_policy_fail"] = fail
		predicates["component.cert_manager.admission_webhook_identity_present"] = identity
	} else {
		omissions = append(omissions, newProjectionOmission("COMPONENT_CONFIGURATION_API_UNAVAILABLE", "The cert-manager admission webhook API surface was unavailable."))
	}

	rbacAvailable := available["cert-manager-rbac-surface.json"] && available["cert-manager-role-surface.json"] && available["cert-manager-rolebindings.json"] && available["cert-manager-clusterrolebindings.json"]
	if rbacAvailable {
		for _, check := range []struct{ id, key string }{{"component.cert_manager.rbac_serviceaccounts_token_create", "serviceaccountsTokenCreate"}, {"component.cert_manager.rbac_cert_manager_api_groups", "certManagerAPIGroups"}, {"component.cert_manager.rbac_acme_api_group", "acmeAPIGroup"}} {
			found := false
			for _, class := range certManagerClasses {
				bound := at(surfaces["cert-manager-rolebindings.json"], class) == true || at(surfaces["cert-manager-clusterrolebindings.json"], class) == true
				rule := at(surfaces["cert-manager-rbac-surface.json"], class, check.key) == true || at(surfaces["cert-manager-role-surface.json"], class, check.key) == true
				if bound && rule {
					found = true
				}
			}
			predicates[check.id] = found
		}
	} else {
		omissions = append(omissions, newProjectionOmission("COMPONENT_CONFIGURATION_RBAC_FORBIDDEN", "Scoped cert-manager RBAC predicates were unavailable or forbidden."))
	}

	metricsAvailable := available["cert-manager-servicemonitors.json"] && available["cert-manager-podmonitors.json"] && available["cert-manager-monitor-targets.json"]
	if metricsAvailable {
		targets := surfaces["cert-manager-monitor-targets.json"]
		serviceTarget := at(targets, "serviceTargetProven") == true
		podTarget := at(targets, "podTargetProven") == true
		if serviceTarget || podTarget {
			sm := surfaces["cert-manager-servicemonitors.json"]
			pm := surfaces["cert-manager-podmonitors.json"]
			predicates["component.cert_manager.metrics_servicemonitor_present"] = serviceTarget && at(sm, "serviceMonitorPresent") == true
			predicates["component.cert_manager.metrics_podmonitor_present"] = podTarget && at(pm, "podMonitorPresent") == true
			predicates["component.cert_manager.metrics_scrape_port_present"] = (serviceTarget && at(sm, "scrapePortPresent") == true) || (podTarget && at(pm, "scrapePortPresent") == true)
			predicates["component.cert_manager.metrics_scrape_path_present"] = (serviceTarget && at(sm, "scrapePathPresent") == true) || (podTarget && at(pm, "scrapePathPresent") == true)
		} else {
			metricsAvailable = false
		}
	}
	if !metricsAvailable {
		omissions = append(omissions, newProjectionOmission("COMPONENT_CONFIGURATION_API_UNAVAILABLE", "ServiceMonitor/PodMonitor APIs or a cert-manager target workload identity were unavailable; scrape predicates remain UNKNOWN."))
	}
	if available["cert-manager-health.json"] {
		health := surfaces["cert-manager-health.json"]
		predicates["component.cert_manager.health_desired_count"] = at(health, "desiredCount")
		predicates["component.cert_manager.health_ready_count"] = at(health, "readyCount")
		predicates["component.cert_manager.health_available_count"] = at(health, "availableCount")
	} else {
		omissions = append(omissions, newProjectionOmission("COMPONENT_CONFIGURATION_HEALTH_UNAVAILABLE", "Aggregated cert-manager desired/ready/available health counts were unavailable."))
	}
	var version any
	scheme := "unknown"
	conflict := len(versions) > 1
	if len(versions) == 1 {
		for value := range versions {
			version = value
		}
		scheme = "tag"
	}
	return map[string]any{"componentId": "pkg:oci/cert-manager/cert-manager", "observedVersion": version, "versionScheme": scheme, "versionConflict": conflict, "observationState": "observed", "observationCount": 1, "predicates": predicates}, omissions
}

func webhookTargetsCertManager(hook any) bool {
	rules, _ := array(at(hook, "rules"))
	for _, rule := range rules {
		groups, _ := array(at(rule, "apiGroups"))
		if contains(groups, any("cert-manager.io")) || contains(groups, any("acme.cert-manager.io")) {
			return true
		}
	}
	return false
}
