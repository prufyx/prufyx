// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (c Collector) capturePodStatus(ctx context.Context, env []string, opts Options, contextName, dir string, adapter adapterAssets, omissions *[]omission, histogram map[string]int) bool {
	root, _, code := c.read(ctx, env, opts, contextName, []string{"get", "pods", "--all-namespaces", "--chunk-size=200", "-o", "json"})
	if code != "" {
		addOmission(omissions, "pod-status-images.json", code)
		histogram[code]++
		return true
	}
	projected, err := projectPodStatus(root, adapter)
	if err != nil {
		addOmission(omissions, "pod-status-images.json", "projection_filter_rejected")
		histogram["projection_filter_rejected"]++
		return false
	}
	if err := writeJSON(filepath.Join(dir, "pod-status-images.json"), projected); err != nil {
		addOmission(omissions, "pod-status-images.json", "pipeline_failed")
		histogram["pipeline_failed"]++
	}
	return false
}

func (c Collector) captureCRDs(ctx context.Context, env []string, opts Options, contextName, dir string, omissions *[]omission, histogram map[string]int) bool {
	paginationCtx, cancel := context.WithTimeout(ctx, crdPageBudget)
	defer cancel()
	deadline, ok := paginationCtx.Deadline()
	if !ok {
		addOmission(omissions, "crd-api-surface.json", "pipeline_failed")
		histogram["pipeline_failed"]++
		return true
	}
	continueToken, resourceVersion := "", ""
	seen := map[string]bool{}
	items := []any{}
	versionCount := 0
	projectedBytes := 0
	complete := false
	for pageNumber := 0; pageNumber < 64; pageNumber++ {
		timeout, ok := remainingRequestTimeout(time.Now(), deadline, requestTimeout)
		if !ok {
			addOmission(omissions, "crd-api-surface.json", "pipeline_failed")
			histogram["pipeline_failed"]++
			return true
		}
		path := "/apis/apiextensions.k8s.io/v1/customresourcedefinitions?limit=50"
		if continueToken != "" {
			path += "&continue=" + url.QueryEscape(continueToken)
		}
		root, _, code := c.readWithTimeout(paginationCtx, env, opts, contextName, []string{"get", "--raw=" + path}, timeout)
		if code != "" {
			addOmission(omissions, "crd-api-surface.json", code)
			histogram[code]++
			return true
		}
		page, err := projectCRDPage(root, 50)
		if err != nil {
			addOmission(omissions, "crd-api-surface.json", "projection_filter_rejected")
			histogram["projection_filter_rejected"]++
			return false
		}
		if resourceVersion == "" {
			resourceVersion = page.ResourceVersion
		} else if resourceVersion != page.ResourceVersion {
			addOmission(omissions, "crd-api-surface.json", "pipeline_failed")
			histogram["pipeline_failed"]++
			return false
		}
		items = append(items, page.Items...)
		for _, item := range page.Items {
			projectedItem, err := json.Marshal(item)
			if err != nil {
				addOmission(omissions, "crd-api-surface.json", "projection_filter_rejected")
				histogram["projection_filter_rejected"]++
				return false
			}
			projectedBytes += len(projectedItem) + 1 // compact NDJSON, matching the prior bounded stage
		}
		for _, row := range page.Items {
			if versions, ok := array(at(row, "versions")); ok {
				versionCount += len(versions)
			}
		}
		if len(items) > 10000 || versionCount > 100000 || projectedBytes > 4<<20 {
			addOmission(omissions, "crd-api-surface.json", "projection_filter_rejected")
			histogram["projection_filter_rejected"]++
			return false
		}
		if page.Continue == "" {
			complete = true
			break
		}
		tokenHash := digest([]byte(page.Continue))
		if seen[tokenHash] {
			addOmission(omissions, "crd-api-surface.json", "pipeline_failed")
			histogram["pipeline_failed"]++
			return false
		}
		seen[tokenHash] = true
		continueToken = page.Continue
	}
	if !complete {
		addOmission(omissions, "crd-api-surface.json", "pipeline_failed")
		histogram["pipeline_failed"]++
		return false
	}
	merged, err := mergeCRDPages(items)
	if err != nil {
		addOmission(omissions, "crd-api-surface.json", "projection_filter_rejected")
		histogram["projection_filter_rejected"]++
		return false
	}
	if err := writeJSON(filepath.Join(dir, "crd-api-surface.json"), merged); err != nil {
		addOmission(omissions, "crd-api-surface.json", "pipeline_failed")
		histogram["pipeline_failed"]++
	}
	return false
}

func remainingRequestTimeout(now, deadline time.Time, maximum time.Duration) (time.Duration, bool) {
	remaining := deadline.Sub(now)
	if remaining <= 0 {
		return 0, false
	}
	if remaining < maximum {
		return remaining, true
	}
	return maximum, true
}

func (c Collector) captureCertManager(ctx context.Context, env []string, opts Options, contextName, dir string, discoveredGroups map[string]bool, omissions *[]omission, histogram map[string]int, configuration, componentOmissions *[]any) (int, int) {
	reads, failures := 0, 0
	surfaces := map[string]any{}
	available := map[string]bool{}
	for _, q := range certManagerQueries {
		reads++
		root, _, code := c.read(ctx, env, opts, contextName, q.args)
		if code != "" && code == "kubernetes_api_read_failed_unsupported_not_found_api" && apiGroupConfirmedAbsent(q.args, discoveredGroups) {
			// Observed absence: the read reported an unserved resource type AND
			// successful group discovery lacks the API group. This is evidence
			// that the API is not installed, not a failed read.
			absent := absentMonitorSurface(q.name)
			surfaces[q.name] = absent
			available[q.name] = true
			if err := writeJSON(filepath.Join(dir, q.name), absent); err != nil {
				addOmission(omissions, q.name, "pipeline_failed")
				histogram["pipeline_failed"]++
			}
			continue
		}
		if code != "" {
			failures++
			addOmission(omissions, q.name, code)
			histogram[code]++
			*componentOmissions = append(*componentOmissions, componentFailure(q.name, code))
			continue
		}
		projected, err := projectCertManager(q.name, root)
		if err != nil {
			addOmission(omissions, q.name, "projection_filter_rejected")
			histogram["projection_filter_rejected"]++
			*componentOmissions = append(*componentOmissions, componentFailure(q.name, "projection_filter_rejected"))
			continue
		}
		surfaces[q.name] = projected
		available[q.name] = true
		if err := writeJSON(filepath.Join(dir, q.name), projected); err != nil {
			addOmission(omissions, q.name, "pipeline_failed")
			histogram["pipeline_failed"]++
			continue
		}
	}
	for _, name := range []string{"crd-api-surface.json", "validating-webhooks.json", "mutating-webhooks.json"} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		value, err := DecodeStrict(raw)
		if err == nil {
			surfaces[name] = value
			available[name] = true
		}
	}
	row, derivedOmissions := deriveCertManager(*configuration, surfaces, available)
	if row != nil {
		*configuration = append(*configuration, row)
	}
	for _, value := range derivedOmissions {
		if m, ok := object(value); ok {
			m["sourceFile"] = "cert-manager-derived-predicates"
			*componentOmissions = append(*componentOmissions, m)
		}
	}
	return reads, failures
}

var certManagerQueries = []query{
	{"cert-manager-rbac-surface.json", []string{"get", "clusterroles.rbac.authorization.k8s.io", "--chunk-size=200", "-o", "json"}},
	{"cert-manager-role-surface.json", []string{"get", "roles.rbac.authorization.k8s.io", "--all-namespaces", "--chunk-size=200", "-o", "json"}},
	{"cert-manager-rolebindings.json", []string{"get", "rolebindings.rbac.authorization.k8s.io", "--all-namespaces", "--chunk-size=200", "-o", "json"}},
	{"cert-manager-clusterrolebindings.json", []string{"get", "clusterrolebindings.rbac.authorization.k8s.io", "--chunk-size=200", "-o", "json"}},
	{"cert-manager-health.json", []string{"get", "deployments.apps", "--all-namespaces", "--chunk-size=200", "-o", "json"}},
	{"cert-manager-monitor-targets.json", []string{"get", "services,pods", "--all-namespaces", "--chunk-size=200", "-o", "json"}},
	{"cert-manager-servicemonitors.json", []string{"get", "servicemonitors.monitoring.coreos.com", "--all-namespaces", "--chunk-size=200", "-o", "json"}},
	{"cert-manager-podmonitors.json", []string{"get", "podmonitors.monitoring.coreos.com", "--all-namespaces", "--chunk-size=200", "-o", "json"}},
}

// groupSet returns the API group names of a projected grouped-api-versions
// document, or nil when the document is not the expected shape (fail-closed:
// nil never confirms an absence).
func groupSet(projected any) map[string]bool {
	rows, ok := projected.([]any)
	if !ok {
		return nil
	}
	set := make(map[string]bool, len(rows))
	for _, row := range rows {
		name, ok := stringValue(at(row, "name"))
		if !ok {
			return nil
		}
		set[name] = true
	}
	return set
}

// apiGroupConfirmedAbsent reports whether the group of a "get <resource>.<group>"
// query is absent from successfully read API group discovery.
func apiGroupConfirmedAbsent(args []string, discoveredGroups map[string]bool) bool {
	if discoveredGroups == nil || len(args) < 2 || args[0] != "get" {
		return false
	}
	_, group, found := strings.Cut(args[1], ".")
	if !found || group == "" || strings.ContainsAny(group, ",/ ") {
		return false
	}
	return !discoveredGroups[group]
}

func absentMonitorSurface(name string) map[string]any {
	prefix := "serviceMonitor"
	if name == "cert-manager-podmonitors.json" {
		prefix = "podMonitor"
	}
	return map[string]any{"apiServed": false, prefix + "Present": false, "scrapePortPresent": false, "scrapePathPresent": false}
}
