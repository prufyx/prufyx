// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

import (
	"encoding/json"
	"sort"
)

func aggregateComponents(adapter adapterAssets, profile string, configuration, inputOmissions []any) any {
	if profile == "v3" && prometheusSourceIncomplete(inputOmissions) {
		kept := configuration[:0]
		removed := false
		for _, value := range configuration {
			if at(value, "componentId") == "pkg:oci/prometheus/prometheus" {
				removed = true
				continue
			}
			kept = append(kept, value)
		}
		configuration = kept
		if removed {
			inputOmissions = append(inputOmissions, map[string]any{
				"code":                  "COMPONENT_CONFIGURATION_DECLARED_ROLE_AMBIGUOUS",
				"reason":                "A required Prometheus controller read was unavailable; no subset of the declared role is retained.",
				"requiredForEvaluation": true, "sourceFile": "component-configuration-aggregate", "count": 1,
			})
		}
	}
	byComponent := map[string][]map[string]any{}
	for _, value := range configuration {
		row, ok := object(value)
		if !ok {
			continue
		}
		componentID, ok := stringValue(row["componentId"])
		if !ok {
			continue
		}
		byComponent[componentID] = append(byComponent[componentID], row)
	}
	components := []any{}
	omissions := append([]any{}, inputOmissions...)
	for componentID, rows := range byComponent {
		component, conflicts := mergeComponent(componentID, rows)
		if component != nil {
			components = append(components, component)
		}
		for range conflicts {
			omissions = append(omissions, map[string]any{
				"code":                  "COMPONENT_CONFIGURATION_DECLARED_ROLE_AMBIGUOUS",
				"reason":                "Declared-container role evidence was missing, mixed, or contradictory; collect one exact unshared image role and evidence class for the predicate.",
				"requiredForEvaluation": true, "sourceFile": "component-configuration-aggregate", "count": 1,
			})
		}
	}
	sortAny(components)
	return map[string]any{
		"apiVersion": "prufyx.io/configuration-surface/v1alpha1", "kind": "ComponentConfigurationSurface",
		"metadata": map[string]any{
			"schemaVersion":  map[bool]string{true: "1.1.0", false: "1.0.0"}[profile == "v3"],
			"adapterVersion": "component-configuration-adapter-" + profile, "registryVersion": profile,
			"registryDigest": adapter.RegistryDigest, "filterDigest": adapter.FilterDigest, "aggregateDigest": adapter.AggregateDigest,
			"strictJsonDigest":                       digest(strictJSONContract),
			"kubectlStderrClassifierDigest":          digest(stderrClassifierContract),
			"kubectlBoundedRunnerDigest":             digest(boundedRunnerContract),
			"kubectlStderrClassifierTaxonomyVersion": "kubectl-stderr-taxonomy-v1",
			"kubectlStderrClassifierAuthority":       "heuristic_local_diagnostic_not_proof",
			"certManagerProjectionDigest":            digest(certManagerProjectorContract),
		},
		"components": components, "omissions": groupOmissions(omissions),
		"licenseCopyrightDisposition": "metadata_only_derived_predicates",
	}
}

func prometheusSourceIncomplete(omissions []any) bool {
	for _, value := range omissions {
		source := asString(at(value, "sourceFile"))
		if source == "deployment-images.json" || source == "statefulset-images.json" {
			return true
		}
	}
	return false
}

func mergeComponent(componentID string, rows []map[string]any) (any, []string) {
	versions, schemes := map[string]bool{}, map[string]bool{}
	predicateValues := map[string]map[string]any{}
	evidenceValues := map[string]map[string]any{}
	roles := map[string]bool{}
	count := 0
	for _, row := range rows {
		if value, ok := row["observedVersion"].(string); ok {
			versions[value] = true
		}
		if value, ok := row["versionScheme"].(string); ok {
			schemes[value] = true
		}
		if value, ok := row["observationCount"].(float64); ok {
			count += int(value)
		} else if value, ok := row["observationCount"].(int); ok {
			count += value
		}
		predicates, _ := object(row["predicates"])
		for id, value := range predicates {
			raw, _ := json.Marshal(value)
			if predicateValues[id] == nil {
				predicateValues[id] = map[string]any{}
			}
			predicateValues[id][string(raw)] = value
		}
		if evidence, ok := array(row["predicateEvidence"]); ok {
			for _, item := range evidence {
				id, _ := at(item, "predicateId").(string)
				raw, _ := json.Marshal(item)
				if evidenceValues[id] == nil {
					evidenceValues[id] = map[string]any{}
				}
				evidenceValues[id][string(raw)] = item
				if role, ok := at(item, "sourceRole").(string); ok {
					roles[role] = true
				}
			}
		}
	}
	conflict := len(versions) != 1 || len(schemes) != 1
	merged := map[string]any{}
	mergedEvidence := []any{}
	conflicts := []string{}
	for id, values := range predicateValues {
		if len(values) != 1 {
			conflict = true
			continue
		}
		if ev := evidenceValues[id]; len(ev) > 1 {
			conflicts = append(conflicts, id)
			continue
		}
		for _, value := range values {
			merged[id] = value
		}
		for _, value := range evidenceValues[id] {
			mergedEvidence = append(mergedEvidence, value)
		}
	}
	version, scheme := any(nil), "unknown"
	state := "conflict"
	if !conflict {
		for value := range versions {
			version = value
		}
		for value := range schemes {
			scheme = value
		}
		state = "observed"
	} else {
		merged = map[string]any{}
		mergedEvidence = nil
	}
	component := map[string]any{
		"componentId": componentID, "observedVersion": version, "versionScheme": scheme,
		"versionConflict": conflict, "observationState": state, "observationCount": count, "predicates": merged,
	}
	if len(mergedEvidence) > 0 {
		sortAny(mergedEvidence)
		roleList := make([]string, 0, len(roles))
		for role := range roles {
			roleList = append(roleList, role)
		}
		sort.Strings(roleList)
		component["roles"], component["predicateEvidence"] = roleList, mergedEvidence
	}
	return component, conflicts
}

func groupOmissions(values []any) []any {
	type key struct{ code, source string }
	grouped := map[key]map[string]any{}
	for _, value := range values {
		row, ok := object(value)
		if !ok {
			continue
		}
		k := key{asString(row["code"]), asString(row["sourceFile"])}
		if grouped[k] == nil {
			grouped[k] = map[string]any{"code": k.code, "reason": row["reason"], "requiredForEvaluation": row["requiredForEvaluation"] == true, "sourceFile": k.source, "count": 0}
		}
		count := 1
		if n, ok := row["count"].(int); ok {
			count = n
		}
		grouped[k]["count"] = grouped[k]["count"].(int) + count
	}
	out := []any{}
	for _, value := range grouped {
		out = append(out, value)
	}
	sortAny(out)
	return out
}
