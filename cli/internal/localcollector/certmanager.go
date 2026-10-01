// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

import (
	"encoding/json"
	"regexp"
)

var certManagerImageRE = regexp.MustCompile(`^(docker\.io/jetstack|quay\.io/jetstack|jetstack)/cert-manager-(controller|webhook|cainjector|startupapicheck)(:|@)`)

var certManagerClasses = []string{"controller", "webhook", "cainjector", "startupapicheck"}

func projectCertManager(name string, root any) (any, error) {
	switch name {
	case "cert-manager-rbac-surface.json":
		return projectCertManagerRules(root, false)
	case "cert-manager-role-surface.json":
		return projectCertManagerRules(root, true)
	case "cert-manager-rolebindings.json":
		return projectCertManagerBindings(root, false)
	case "cert-manager-clusterrolebindings.json":
		return projectCertManagerBindings(root, true)
	case "cert-manager-health.json":
		return projectCertManagerHealth(root)
	case "cert-manager-monitor-targets.json":
		return projectCertManagerTargets(root)
	case "cert-manager-servicemonitors.json":
		return projectCertManagerMonitor(root, false)
	case "cert-manager-podmonitors.json":
		return projectCertManagerMonitor(root, true)
	default:
		return nil, errProjection
	}
}

func projectCertManagerRules(root any, namespaced bool) (any, error) {
	items, err := listRoot(root, 10000)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	for _, class := range certManagerClasses {
		out[class] = map[string]any{"serviceaccountsTokenCreate": false, "certManagerAPIGroups": false, "acmeAPIGroup": false}
	}
	for _, item := range items {
		name, ok := stringValue(at(item, "metadata", "name"))
		if !ok {
			return nil, errProjection
		}
		class := certManagerClass(name)
		rulesValue := nullDefault(at(item, "rules"), []any{})
		rules, ok := array(rulesValue)
		if !ok {
			return nil, errProjection
		}
		if namespaced {
			namespace, ok := at(item, "metadata", "namespace").(string)
			if !ok {
				return nil, errProjection
			}
			if namespace != "cert-manager" {
				continue
			}
		}
		if class == "" {
			continue
		}
		summary := out[class].(map[string]any)
		for _, rule := range rules {
			groups, ok1 := stringsFrom(rule, "apiGroups")
			resources, ok2 := stringsFrom(rule, "resources")
			verbs, ok3 := stringsFrom(rule, "verbs")
			if !ok1 || !ok2 || !ok3 {
				return nil, errProjection
			}
			if contains(groups, "") && contains(resources, "serviceaccounts/token") && contains(verbs, "create") {
				summary["serviceaccountsTokenCreate"] = true
			}
			if contains(groups, "cert-manager.io") && intersects(resources, []string{"certificates", "certificaterequests", "issuers", "clusterissuers"}) && intersects(verbs, []string{"get", "list", "watch"}) {
				summary["certManagerAPIGroups"] = true
			}
			if contains(groups, "acme.cert-manager.io") && intersects(resources, []string{"challenges", "orders"}) && intersects(verbs, []string{"get", "list", "watch"}) {
				summary["acmeAPIGroup"] = true
			}
		}
	}
	return out, nil
}

func projectCertManagerBindings(root any, cluster bool) (any, error) {
	items, err := listRoot(root, 10000)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	for _, class := range certManagerClasses {
		out[class] = false
	}
	for _, item := range items {
		subjectsValue := nullDefault(at(item, "subjects"), []any{})
		subjects, ok := array(subjectsValue)
		if !ok {
			return nil, errProjection
		}
		kind, ok1 := stringValue(at(item, "roleRef", "kind"))
		name, ok2 := stringValue(at(item, "roleRef", "name"))
		if !ok1 || !ok2 {
			return nil, errProjection
		}
		if cluster && kind != "ClusterRole" {
			return nil, errProjection
		}
		if !cluster && kind != "Role" && kind != "ClusterRole" {
			return nil, errProjection
		}
		class := certManagerClass(name)
		if class == "" {
			continue
		}
		namespace, _ := at(item, "metadata", "namespace").(string)
		if !cluster && namespace != "cert-manager" {
			continue
		}
		wanted := certManagerSubject(class)
		for _, subject := range subjects {
			if at(subject, "kind") == "ServiceAccount" && at(subject, "namespace") == "cert-manager" && at(subject, "name") == wanted {
				out[class] = true
			}
		}
	}
	return out, nil
}

func projectCertManagerHealth(root any) (any, error) {
	items, err := listRoot(root, 10000)
	if err != nil {
		return nil, err
	}
	desired, ready, available := 0, 0, 0
	for _, item := range items {
		containers, ok := array(at(item, "spec", "template", "spec", "containers"))
		if !ok {
			return nil, errProjection
		}
		matched := false
		for _, container := range containers {
			image, ok := stringValue(at(container, "image"))
			if !ok {
				return nil, errProjection
			}
			if certManagerImageRE.MatchString(image) {
				matched = true
			}
		}
		if !matched {
			continue
		}
		d, ok := boundedCount(nullDefault(at(item, "spec", "replicas"), json.Number("1")))
		if !ok {
			return nil, errProjection
		}
		r, ok := boundedCount(nullDefault(at(item, "status", "readyReplicas"), json.Number("0")))
		if !ok {
			return nil, errProjection
		}
		a, ok := boundedCount(nullDefault(at(item, "status", "availableReplicas"), json.Number("0")))
		if !ok {
			return nil, errProjection
		}
		desired += d
		ready += r
		available += a
	}
	if desired > 1000000 || ready > 1000000 || available > 1000000 {
		return nil, errProjection
	}
	return map[string]any{"desiredCount": desired, "readyCount": ready, "availableCount": available}, nil
}

func projectCertManagerTargets(root any) (any, error) {
	items, err := listRoot(root, 20000)
	if err != nil {
		return nil, err
	}
	podLabels := []map[string]any{}
	serviceSelectors := []map[string]any{}
	for _, item := range items {
		kind, ok := stringValue(at(item, "kind"))
		if !ok {
			return nil, errProjection
		}
		namespaceValue := at(item, "metadata", "namespace")
		namespace, namespaceOK := namespaceValue.(string)
		if namespaceValue != nil && !namespaceOK {
			return nil, errProjection
		}
		if namespace != "cert-manager" {
			continue
		}
		if kind == "Pod" && targetLabels(at(item, "metadata", "labels")) {
			containers, ok := array(at(item, "spec", "containers"))
			if !ok {
				continue
			}
			imageMatch := false
			for _, container := range containers {
				if image, ok := stringValue(at(container, "image")); ok && certManagerImageRE.MatchString(image) {
					imageMatch = true
				}
			}
			owners, _ := array(nullDefault(at(item, "metadata", "ownerReferences"), []any{}))
			ownerMatch := false
			for _, owner := range owners {
				k := asString(at(owner, "kind"))
				n := asString(at(owner, "name"))
				if (k == "ReplicaSet" || k == "Deployment") && (n == "cert-manager" || regexp.MustCompile(`^cert-manager-`).MatchString(n)) {
					ownerMatch = true
				}
			}
			if imageMatch && ownerMatch {
				if labels, ok := object(at(item, "metadata", "labels")); ok {
					podLabels = append(podLabels, labels)
				}
			}
		}
		if kind == "Service" {
			name := asString(at(item, "metadata", "name"))
			selector, ok := object(at(item, "spec", "selector"))
			if ok && (name == "cert-manager" || name == "cert-manager-webhook") && targetLabels(selector) {
				serviceSelectors = append(serviceSelectors, selector)
			}
		}
	}
	serviceProven := false
	for _, selector := range serviceSelectors {
		for _, labels := range podLabels {
			if subset(selector, labels) {
				serviceProven = true
			}
		}
	}
	return map[string]any{"podTargetProven": len(podLabels) > 0, "serviceTargetProven": serviceProven}, nil
}

func projectCertManagerMonitor(root any, pod bool) (any, error) {
	items, err := listRoot(root, 10000)
	if err != nil {
		return nil, err
	}
	present, port, path := false, false, false
	endpointKey := "endpoints"
	if pod {
		endpointKey = "podMetricsEndpoints"
	}
	for _, item := range items {
		endpoints, ok := array(at(item, "spec", endpointKey))
		if !ok {
			return nil, errProjection
		}
		labels, ok := object(nullDefault(at(item, "spec", "selector", "matchLabels"), map[string]any{}))
		if !ok {
			return nil, errProjection
		}
		names, ok := array(nullDefault(at(item, "spec", "namespaceSelector", "matchNames"), []any{}))
		if !ok {
			return nil, errProjection
		}
		for _, endpoint := range endpoints {
			if !validCertManagerEndpoint(endpoint) {
				return nil, errProjection
			}
		}
		identity := labels["app.kubernetes.io/instance"] == "cert-manager" && labels["app.kubernetes.io/name"] == "cert-manager" && len(names) == 1 && names[0] == "cert-manager"
		if !identity {
			continue
		}
		for _, endpoint := range endpoints {
			p := at(endpoint, "port")
			target := at(endpoint, "targetPort")
			endpointPath := at(endpoint, "path")
			pOK := p == "http-metrics" || target == "http-metrics" || numberEquals(target, 9402)
			pathOK := endpointPath == "/metrics"
			if pOK {
				port = true
			}
			if pathOK {
				path = true
			}
			if pOK && pathOK {
				present = true
			}
		}
	}
	prefix := "serviceMonitor"
	if pod {
		prefix = "podMonitor"
	}
	return map[string]any{prefix + "Present": present, "scrapePortPresent": port, "scrapePathPresent": path}, nil
}

func validCertManagerEndpoint(endpoint any) bool {
	if _, ok := object(endpoint); !ok {
		return false
	}
	if value := at(endpoint, "path"); value != nil {
		if _, ok := value.(string); !ok {
			return false
		}
	}
	if value := at(endpoint, "port"); value != nil {
		if _, ok := value.(string); !ok {
			return false
		}
	}
	if value := at(endpoint, "targetPort"); value != nil {
		if _, stringOK := value.(string); !stringOK {
			if !isJSONNumber(value) {
				return false
			}
		}
	}
	return true
}

func isJSONNumber(value any) bool {
	switch value.(type) {
	case json.Number, float64, float32, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return true
	default:
		return false
	}
}

func boundedCount(value any) (int, bool) {
	switch n := value.(type) {
	case json.Number:
		i, e := n.Int64()
		return int(i), e == nil && i >= 0 && i <= 1000000
	case int:
		return n, n >= 0 && n <= 1000000
	case float64:
		i := int(n)
		return i, n == float64(i) && i >= 0 && i <= 1000000
	}
	return 0, false
}
func stringsFrom(value any, key string) ([]string, bool) {
	items, ok := array(at(value, key))
	if !ok {
		return nil, false
	}
	out := []string{}
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, false
		}
		out = append(out, text)
	}
	return out, true
}
func intersects(a, b []string) bool {
	for _, x := range a {
		if contains(b, x) {
			return true
		}
	}
	return false
}
func certManagerClass(name string) string {
	for _, class := range certManagerClasses {
		if name == "cert-manager-"+class {
			return class
		}
	}
	return ""
}
func certManagerSubject(class string) string {
	if class == "controller" {
		return "cert-manager"
	}
	return "cert-manager-" + class
}
func targetLabels(value any) bool {
	m, ok := object(value)
	return ok && m["app.kubernetes.io/name"] == "cert-manager" && m["app.kubernetes.io/instance"] == "cert-manager"
}
func subset(needle, haystack map[string]any) bool {
	for key, value := range needle {
		if haystack[key] != value {
			return false
		}
	}
	return true
}
func numberEquals(value any, wanted int) bool { n, ok := boundedCount(value); return ok && n == wanted }
