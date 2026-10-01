// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func isWorkload(name string) bool {
	return strings.HasSuffix(name, "-images.json") && name != "pod-status-images.json"
}

func failureFromResult(result CommandResult, err error) string {
	if result.Exit == 125 || result.Exit == 130 {
		return "pipeline_failed"
	}
	if result.Exit != 0 || err != nil {
		if result.Class != "" && result.Class != "generic_api_read_failure" {
			return "kubernetes_api_read_failed_" + result.Class
		}
		return "kubernetes_api_read_failed"
	}
	return "success"
}

func reason(code string) string {
	switch code {
	case "strict_json_rejected":
		return "The API response failed bounded strict JSON validation."
	case "projection_filter_rejected":
		return "The allow-listed local projection rejected the API JSON."
	case "pipeline_failed":
		return "The collector pipeline failed without a classified stage."
	}
	for needle, message := range map[string]string{
		"authentication_exec_plugin_failure": "Heuristic local classification matched an authentication or exec-plugin diagnostic; this is not authorization proof.",
		"unauthorized":                       "Heuristic local classification matched an unauthorized diagnostic; this is not authorization proof.",
		"authorization_rbac_forbidden":       "Heuristic local classification matched a forbidden or RBAC diagnostic; this is not authorization proof.",
		"invalid_kubeconfig_context":         "Heuristic local classification matched an invalid kubeconfig or context diagnostic; this is not proof of configuration state.",
		"tls_certificate":                    "Heuristic local classification matched a TLS or certificate diagnostic; this is not proof of endpoint identity.",
		"dns":                                "Heuristic local classification matched a DNS diagnostic; this is not proof of endpoint identity.",
		"transport_timeout_unreachable":      "Heuristic local classification matched a timeout or unreachable transport diagnostic; this is not proof of availability.",
		"unsupported_not_found_api":          "Heuristic local classification matched an unsupported or not-found API diagnostic; this is not proof of API capability.",
	} {
		if strings.Contains(code, needle) {
			return message
		}
	}
	return "kubectl API read failed before JSON reached local validation; cause remains unknown and this is not proof of authorization state."
}

func addOmission(out *[]omission, name, code string) {
	*out = append(*out, omission{name, code, reason(code)})
}

func componentFailure(name, code string) map[string]any {
	return map[string]any{
		"code":                  "COMPONENT_CONFIGURATION_" + strings.ToUpper(code),
		"reason":                reason(code),
		"requiredForEvaluation": true,
		"sourceFile":            name,
	}
}

func writeJSON(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writePrivate(path, append(raw, '\n'))
}

func writePrivate(path string, raw []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := f.Write(raw); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

func writeOmissions(path string, rows []omission) error {
	var out strings.Builder
	for _, row := range rows {
		fmt.Fprintf(&out, "%s\t%s\t%s\n", row.Name, row.Code, row.Reason)
	}
	return writePrivate(path, []byte(out.String()))
}

func writeManifest(dir string) error {
	paths := []string{}
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		if entry.Name() == "MANIFEST.sha256" {
			return nil
		}
		paths = append(paths, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(paths)
	var out strings.Builder
	for _, rel := range paths {
		raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			return err
		}
		sum := sha256.Sum256(raw)
		fmt.Fprintf(&out, "%x  ./%s\n", sum, rel)
	}
	return writePrivate(filepath.Join(dir, "MANIFEST.sha256"), []byte(out.String()))
}

func observationMetadata(now time.Time, ctxHash, status string, omissionCount int, opts Options, adapter adapterAssets) map[string]any {
	var adapterVersion, registryVersion, registryDigest, filterDigest, aggregateDigest, strictDigest any
	if opts.IncludeComponentConfiguration {
		adapterVersion = "component-configuration-adapter-" + opts.ComponentConfigurationProfile
		registryVersion = opts.ComponentConfigurationProfile
		registryDigest = adapter.RegistryDigest
		filterDigest = adapter.FilterDigest
		aggregateDigest = adapter.AggregateDigest
		strictDigest = digest(strictJSONContract)
	}
	return map[string]any{
		"schema": collectorSchema, "format": "KubeconfigAPIObservation", "generatedAt": now.Format(time.RFC3339),
		"contextHash": ctxHash, "collectionStatus": status, "includePodStatusImages": opts.IncludePodStatusImages,
		"includeComponentConfiguration":        opts.IncludeComponentConfiguration,
		"componentConfigurationAdapterVersion": adapterVersion, "componentConfigurationRegistryVersion": registryVersion,
		"componentConfigurationRegistryDigest": registryDigest, "componentConfigurationFilterDigest": filterDigest,
		"componentConfigurationAggregateDigest": aggregateDigest, "componentConfigurationStrictJsonDigest": strictDigest,
		"kubectlStderrClassifierDigest":          digest(stderrClassifierContract),
		"kubectlStderrClassifierTaxonomyVersion": "kubectl-stderr-taxonomy-v1",
		"kubectlStderrClassifierAuthority":       "heuristic_local_diagnostic_not_proof",
		"kubectlBoundedRunnerDigest":             digest(boundedRunnerContract),
		"crdPaginationPolicy": map[string]any{
			"version": "crd-pagination-policy-v2-go", "endpoint": "/apis/apiextensions.k8s.io/v1/customresourcedefinitions",
			"profile": "raw-v1-continue", "pageLimit": 50, "maxPages": 64, "maxItems": 10000,
			"maxVersions": 100000, "maxProjectedBytes": 4 << 20, "overallTimeoutSeconds": 120,
			"localJsonStageDigest": digest(strictJSONContract),
			"pageProjectionDigest": digest([]byte(`{"kind":"prufyx.io/collector-behavior-contract","name":"crd-page-projector","version":"v2-go"}`)),
			"finalMergeDigest":     digest([]byte(`{"kind":"prufyx.io/collector-behavior-contract","name":"crd-page-merge","version":"v2-go"}`)),
		},
		"omissionCount":      omissionCount,
		"dataClassification": "confidential local inventory", "authority": "local unsigned API observation",
		"evaluationEligible": false, "notACompatibilitySnapshot": true,
		"retained": []string{
			"Kubernetes server and node component versions",
			"canonical public component identities and bounded versions from approved workload projections",
			"optional reviewed public component configuration predicates from workload arguments",
			"CRD, aggregated API, admission policy/webhook, storage, CSI, and RuntimeClass signals",
			"core and grouped API discovery versions",
		},
		"omittedByPolicy": []string{
			"Secrets and Secret payloads", "ConfigMaps and ConfigMap payloads", "logs, events, metrics, and traces",
			"raw Kubernetes manifests", "object, namespace, workload, Pod, and node names", "labels, annotations, environment values, and command arguments",
			"unrecognized or private workload and Pod image identities and image IDs", "credentials, endpoints, provider instance IDs, and business data",
			"Helm release metadata, rendered values, and component configuration values",
		},
		"disclosure": []string{
			"workload projections exclude raw image references, image IDs, private registry paths, and workload identity; only exact registry-bound public component summaries are retained",
			"CRD, CSI, storage, webhook, and API names may expose platform architecture",
			"contextHash is a randomized per-run pseudonym; the key is discarded and cross-run linking is intentionally unavailable",
			"kubectl may execute an authentication plugin configured by the explicit kubeconfig",
			"kubectl and its exec plugin receive only the closed documented environment",
			"complete API responses remain in memory and are discarded after strict validation and allow-listed projection",
		},
	}
}
