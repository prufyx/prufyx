// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

import (
	"sort"
	"strings"
)

type crdPage struct {
	ResourceVersion string
	Continue        string
	Items           []any
}

func projectCRDPage(root any, pageLimit int) (crdPage, error) {
	m, ok := object(root)
	if !ok || m["apiVersion"] != "apiextensions.k8s.io/v1" || m["kind"] != "CustomResourceDefinitionList" {
		return crdPage{}, errProjection
	}
	metadata, ok := object(m["metadata"])
	if !ok {
		return crdPage{}, errProjection
	}
	rv, ok := stringValue(metadata["resourceVersion"])
	if !ok || len(rv) > 256 {
		return crdPage{}, errProjection
	}
	next := ""
	if value := metadata["continue"]; value != nil {
		var ok bool
		next, ok = value.(string)
		if !ok || len(next) > 4096 || strings.ContainsAny(next, "\x00\r\n") {
			return crdPage{}, errProjection
		}
	}
	items, ok := array(m["items"])
	if !ok || len(items) > pageLimit {
		return crdPage{}, errProjection
	}
	projected := []any{}
	identities := map[string]bool{}
	for _, item := range items {
		group, ok1 := boundedString(at(item, "spec", "group"), 256)
		kind, ok2 := boundedString(at(item, "spec", "names", "kind"), 256)
		plural, ok3 := boundedString(at(item, "spec", "names", "plural"), 256)
		scope, ok4 := boundedString(at(item, "spec", "scope"), 64)
		versions, ok5 := array(at(item, "spec", "versions"))
		if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || len(versions) == 0 || len(versions) > 32 {
			return crdPage{}, errProjection
		}
		identity := group + "/" + plural
		if identities[identity] {
			return crdPage{}, errProjection
		}
		identities[identity] = true
		seenVersions := map[string]bool{}
		projectedVersions := []any{}
		for _, version := range versions {
			name, ok := boundedString(at(version, "name"), 128)
			if !ok || seenVersions[name] {
				return crdPage{}, errProjection
			}
			seenVersions[name] = true
			served, ok1 := at(version, "served").(bool)
			storage, ok2 := at(version, "storage").(bool)
			if !ok1 || !ok2 {
				return crdPage{}, errProjection
			}
			deprecated := false
			if value := at(version, "deprecated"); value != nil {
				var ok bool
				deprecated, ok = value.(bool)
				if !ok {
					return crdPage{}, errProjection
				}
			}
			projectedVersions = append(projectedVersions, map[string]any{
				"name": name, "served": served, "storage": storage, "deprecated": deprecated,
				"schemaPresent":     at(version, "schema", "openAPIV3Schema") != nil,
				"statusSubresource": at(version, "subresources", "status") != nil,
				"scaleSubresource":  at(version, "subresources", "scale") != nil,
			})
		}
		conversion := "None"
		if value := at(item, "spec", "conversion", "strategy"); value != nil {
			var ok bool
			conversion, ok = value.(string)
			if !ok || len(conversion) > 64 {
				return crdPage{}, errProjection
			}
		}
		preserve := false
		if value := at(item, "spec", "preserveUnknownFields"); value != nil {
			var ok bool
			preserve, ok = value.(bool)
			if !ok {
				return crdPage{}, errProjection
			}
		}
		projected = append(projected, map[string]any{
			"group": group, "kind": kind, "plural": plural, "scope": scope, "versions": projectedVersions,
			"conversionStrategy": conversion, "conversionWebhookConfigured": at(item, "spec", "conversion", "webhook") != nil,
			"preserveUnknownFields": preserve,
		})
	}
	return crdPage{rv, next, projected}, nil
}

func mergeCRDPages(items []any) ([]any, error) {
	identities := map[string]bool{}
	for _, item := range items {
		identity := asString(at(item, "group")) + "/" + asString(at(item, "plural"))
		if identities[identity] {
			return nil, errProjection
		}
		identities[identity] = true
		versions, ok := array(at(item, "versions"))
		if !ok {
			return nil, errProjection
		}
		seen := map[string]bool{}
		for _, version := range versions {
			name := asString(at(version, "name"))
			if name == "" || seen[name] {
				return nil, errProjection
			}
			seen[name] = true
		}
		sort.SliceStable(versions, func(i, j int) bool { return asString(at(versions[i], "name")) < asString(at(versions[j], "name")) })
	}
	sort.SliceStable(items, func(i, j int) bool {
		a := asString(at(items[i], "group")) + "/" + asString(at(items[i], "plural"))
		b := asString(at(items[j], "group")) + "/" + asString(at(items[j], "plural"))
		return a < b
	})
	return items, nil
}

func boundedString(value any, max int) (string, bool) {
	text, ok := value.(string)
	return text, ok && text != "" && len(text) <= max
}
