// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

var errProjection = errors.New("projection rejected")

func object(v any) (map[string]any, bool) { x, ok := v.(map[string]any); return x, ok }
func array(v any) ([]any, bool)           { x, ok := v.([]any); return x, ok }
func stringValue(v any) (string, bool)    { x, ok := v.(string); return x, ok && x != "" }
func at(v any, path ...string) any {
	for _, key := range path {
		m, ok := object(v)
		if !ok {
			return nil
		}
		v = m[key]
	}
	return v
}
func nullDefault(v any, fallback any) any {
	if v == nil {
		return fallback
	}
	return v
}
func sortedValues(in []any) []any {
	sort.SliceStable(in, func(i, j int) bool {
		a, _ := json.Marshal(in[i])
		b, _ := json.Marshal(in[j])
		return string(a) < string(b)
	})
	return in
}

func project(name string, root any) (any, error) {
	switch name {
	case "server-version.json":
		return projectServer(root)
	case "node-profiles.json":
		return projectNodes(root)
	case "aggregated-apis.json":
		return projectAggregated(root)
	case "mutating-webhooks.json", "validating-webhooks.json":
		return projectWebhooks(root)
	case "admission-policy-surface.json":
		return projectAdmissionPolicies(root)
	case "admission-policy-bindings.json":
		return projectAdmissionBindings(root)
	case "storage-surface.json":
		return projectStorage(root)
	case "csi-driver-surface.json":
		return projectCSI(root)
	case "runtime-classes.json":
		return projectRuntime(root)
	case "core-api-versions.json":
		return projectCoreVersions(root)
	case "grouped-api-versions.json":
		return projectGroupedVersions(root)
	default:
		return nil, fmt.Errorf("%w: unknown projection", errProjection)
	}
}

func listRoot(root any, max int) ([]any, error) {
	m, ok := object(root)
	if !ok {
		return nil, errProjection
	}
	items, ok := array(m["items"])
	if !ok || len(items) > max {
		return nil, errProjection
	}
	return items, nil
}

func projectServer(root any) (any, error) {
	m, ok := object(root)
	if !ok {
		return nil, errProjection
	}
	version, ok := stringValue(m["gitVersion"])
	if !ok {
		return nil, errProjection
	}
	return map[string]any{"gitVersion": version, "gitCommit": nullDefault(m["gitCommit"], nil), "gitTreeState": nullDefault(m["gitTreeState"], nil), "buildDate": nullDefault(m["buildDate"], nil), "goVersion": nullDefault(m["goVersion"], nil), "compiler": nullDefault(m["compiler"], nil), "platform": nullDefault(m["platform"], nil)}, nil
}

func projectNodes(root any) (any, error) {
	items, err := listRoot(root, 20000)
	if err != nil {
		return nil, err
	}
	counts := map[string]int{}
	values := map[string]any{}
	for _, item := range items {
		ni, ok := object(at(item, "status", "nodeInfo"))
		if !ok {
			return nil, errProjection
		}
		required := []string{"kubeletVersion", "containerRuntimeVersion", "osImage", "kernelVersion", "architecture", "operatingSystem"}
		for _, k := range required {
			if _, ok := stringValue(ni[k]); !ok {
				return nil, errProjection
			}
		}
		provider := "unknown"
		if s, ok := at(item, "spec", "providerID").(string); ok && s != "" {
			provider = strings.SplitN(s, ":", 2)[0]
		}
		p := map[string]any{"kubeletVersion": ni["kubeletVersion"], "kubeProxyVersion": nullDefault(ni["kubeProxyVersion"], "unknown"), "containerRuntimeVersion": ni["containerRuntimeVersion"], "osImage": ni["osImage"], "kernelVersion": ni["kernelVersion"], "architecture": ni["architecture"], "operatingSystem": ni["operatingSystem"], "providerScheme": provider}
		raw, _ := json.Marshal(p)
		key := string(raw)
		counts[key]++
		values[key] = p
	}
	profiles := make([]any, 0, len(counts))
	for k, n := range counts {
		profiles = append(profiles, map[string]any{"profile": values[k], "count": n})
	}
	sortedValues(profiles)
	return map[string]any{"nodeCount": len(items), "profiles": profiles}, nil
}

func projectAggregated(root any) (any, error) {
	items, err := listRoot(root, 20000)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, it := range items {
		m, _ := object(it)
		name, ok1 := stringValue(at(m, "metadata", "name"))
		_ = name
		version, ok2 := stringValue(at(m, "spec", "version"))
		if !ok1 || !ok2 {
			return nil, errProjection
		}
		group := "core"
		if g, ok := stringValue(at(m, "spec", "group")); ok {
			group = g
		}
		available := any(nil)
		if cs, ok := array(at(m, "status", "conditions")); ok {
			for _, c := range cs {
				if at(c, "type") == "Available" {
					available = at(c, "status")
					break
				}
			}
		}
		out = append(out, map[string]any{"group": group, "version": version, "serviceConfigured": at(m, "spec", "service") != nil, "available": available})
	}
	return sortedValues(out), nil
}

func projectWebhooks(root any) (any, error) {
	items, err := listRoot(root, 10000)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, it := range items {
		kind, ok := stringValue(at(it, "kind"))
		hooks, ok2 := array(at(it, "webhooks"))
		if !ok || !ok2 {
			return nil, errProjection
		}
		ph := make([]any, 0, len(hooks))
		for _, h := range hooks {
			versions, vok := array(at(h, "admissionReviewVersions"))
			rules, rok := array(at(h, "rules"))
			if !vok || !rok {
				return nil, errProjection
			}
			pr := make([]any, 0, len(rules))
			for _, r := range rules {
				groups, g := array(at(r, "apiGroups"))
				vers, v := array(at(r, "apiVersions"))
				ops, o := array(at(r, "operations"))
				res, q := array(at(r, "resources"))
				if !g || !v || !o || !q {
					return nil, errProjection
				}
				pr = append(pr, map[string]any{"apiGroups": groups, "apiVersions": vers, "operations": ops, "resources": res, "scope": nullDefault(at(r, "scope"), nil)})
			}
			clientType := "unknown"
			identity := false
			if at(h, "clientConfig", "service") != nil {
				clientType = "service"
				identity = at(h, "clientConfig", "service", "name") == "cert-manager-webhook" && nullDefault(at(h, "clientConfig", "service", "namespace"), "cert-manager") == "cert-manager"
			} else if at(h, "clientConfig", "url") != nil {
				clientType = "url"
			}
			ph = append(ph, map[string]any{"failurePolicy": nullDefault(at(h, "failurePolicy"), nil), "matchPolicy": nullDefault(at(h, "matchPolicy"), nil), "sideEffects": nullDefault(at(h, "sideEffects"), nil), "timeoutSeconds": nullDefault(at(h, "timeoutSeconds"), nil), "admissionReviewVersions": versions, "rules": pr, "clientType": clientType, "identityPresent": identity})
		}
		out = append(out, map[string]any{"kind": kind, "webhooks": ph})
	}
	return sortedValues(out), nil
}

func projectAdmissionPolicies(root any) (any, error) {
	items, err := listRoot(root, 10000)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, it := range items {
		validations := at(it, "spec", "validations")
		if validations == nil {
			validations = []any{}
		}
		va, ok := array(validations)
		if !ok {
			return nil, errProjection
		}
		variables := at(it, "spec", "variables")
		if variables == nil {
			variables = []any{}
		}
		vv, ok := array(variables)
		if !ok {
			return nil, errProjection
		}
		rules := at(it, "spec", "matchConstraints", "resourceRules")
		if rules == nil {
			rules = []any{}
		}
		ra, ok := array(rules)
		if !ok {
			return nil, errProjection
		}
		projected := make([]any, 0, len(ra))
		for _, r := range ra {
			groups, g := array(nullDefault(at(r, "apiGroups"), []any{}))
			vers, v := array(nullDefault(at(r, "apiVersions"), []any{}))
			ops, o := array(nullDefault(at(r, "operations"), []any{}))
			res, q := array(nullDefault(at(r, "resources"), []any{}))
			if !g || !v || !o || !q {
				return nil, errProjection
			}
			projected = append(projected, map[string]any{"apiGroups": groups, "apiVersions": vers, "operations": ops, "resources": res, "scope": nullDefault(at(r, "scope"), nil)})
		}
		out = append(out, map[string]any{"failurePolicy": nullDefault(at(it, "spec", "failurePolicy"), nil), "validationCount": len(va), "variableCount": len(vv), "resourceRules": projected})
	}
	return out, nil
}

func projectAdmissionBindings(root any) (any, error) {
	items, err := listRoot(root, 10000)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, it := range items {
		actions := nullDefault(at(it, "spec", "validationActions"), []any{})
		a, ok := array(actions)
		if !ok {
			return nil, errProjection
		}
		for _, v := range a {
			if _, ok := stringValue(v); !ok {
				return nil, errProjection
			}
		}
		out = append(out, map[string]any{"matchResourcesConfigured": at(it, "spec", "matchResources") != nil, "paramRefConfigured": at(it, "spec", "paramRef") != nil, "parameterNotFoundAction": nullDefault(at(it, "spec", "paramRef", "parameterNotFoundAction"), nil), "validationActions": a})
	}
	return sortedValues(out), nil
}

func projectStorage(root any) (any, error) {
	items, err := listRoot(root, 10000)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, it := range items {
		p, ok := stringValue(at(it, "provisioner"))
		if !ok {
			return nil, errProjection
		}
		params := nullDefault(at(it, "parameters"), map[string]any{})
		pm, ok := object(params)
		if !ok {
			return nil, errProjection
		}
		keys := make([]string, 0, len(pm))
		for k := range pm {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out = append(out, map[string]any{"provisioner": p, "reclaimPolicy": nullDefault(at(it, "reclaimPolicy"), nil), "volumeBindingMode": nullDefault(at(it, "volumeBindingMode"), nil), "allowVolumeExpansion": nullDefault(at(it, "allowVolumeExpansion"), nil), "parameterKeys": keys})
	}
	return sortedValues(out), nil
}

func projectCSI(root any) (any, error) {
	items, err := listRoot(root, 10000)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, it := range items {
		driver, ok := stringValue(at(it, "metadata", "name"))
		if !ok {
			return nil, errProjection
		}
		trs := nullDefault(at(it, "spec", "tokenRequests"), []any{})
		ta, ok := array(trs)
		if !ok {
			return nil, errProjection
		}
		out = append(out, map[string]any{"driver": driver, "attachRequired": nullDefault(at(it, "spec", "attachRequired"), nil), "podInfoOnMount": nullDefault(at(it, "spec", "podInfoOnMount"), nil), "storageCapacity": nullDefault(at(it, "spec", "storageCapacity"), nil), "fsGroupPolicy": nullDefault(at(it, "spec", "fsGroupPolicy"), nil), "requiresRepublish": nullDefault(at(it, "spec", "requiresRepublish"), nil), "seLinuxMount": nullDefault(at(it, "spec", "seLinuxMount"), nil), "tokenRequestsConfigured": len(ta) > 0, "tokenRequestCount": len(ta)})
	}
	return sortedValues(out), nil
}

func projectRuntime(root any) (any, error) {
	items, err := listRoot(root, 10000)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, it := range items {
		handler, ok := stringValue(at(it, "handler"))
		if !ok {
			return nil, errProjection
		}
		out = append(out, map[string]any{"handler": handler, "overheadConfigured": at(it, "overhead") != nil, "schedulingConfigured": at(it, "scheduling") != nil})
	}
	return sortedValues(out), nil
}

func projectCoreVersions(root any) (any, error) {
	m, ok := object(root)
	if !ok {
		return nil, errProjection
	}
	versions, ok := array(m["versions"])
	if !ok {
		return nil, errProjection
	}
	ss := make([]string, 0, len(versions))
	for _, v := range versions {
		s, ok := stringValue(v)
		if !ok {
			return nil, errProjection
		}
		ss = append(ss, s)
	}
	sort.Strings(ss)
	return map[string]any{"versions": ss}, nil
}

func projectGroupedVersions(root any) (any, error) {
	m, ok := object(root)
	if !ok {
		return nil, errProjection
	}
	groups, ok := array(m["groups"])
	if !ok || len(groups) > 10000 {
		return nil, errProjection
	}
	out := make([]any, 0, len(groups))
	for _, g := range groups {
		name, ok := stringValue(at(g, "name"))
		versions, ok2 := array(at(g, "versions"))
		if !ok || !ok2 {
			return nil, errProjection
		}
		ss := make([]string, 0, len(versions))
		for _, v := range versions {
			s, ok := stringValue(at(v, "version"))
			if !ok {
				return nil, errProjection
			}
			ss = append(ss, s)
		}
		sort.Strings(ss)
		out = append(out, map[string]any{"name": name, "preferredVersion": nullDefault(at(g, "preferredVersion", "version"), nil), "versions": ss})
	}
	return sortedValues(out), nil
}
