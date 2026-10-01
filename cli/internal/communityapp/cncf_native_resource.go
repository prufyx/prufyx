// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfknowledge"
	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
)

const (
	prometheusScrapeRuleID       = "prometheus.scrape-classic-histograms-key-renamed.3-1"
	prometheusAlertmanagerRuleID = "prometheus.alertmanager-api-v1-removed.3-1"
	opentelemetryLoggingRuleID   = "opentelemetry.logging-exporter-removed.0-111"
)

func prometheusNativeRuleID(from, to string, alertmanager bool) string {
	if from == cncfprepare.PrometheusFrom && to == cncfprepare.PrometheusTo {
		if alertmanager {
			return prometheusAlertmanagerRuleID
		}
		return prometheusScrapeRuleID
	}
	if to != cncfprepare.PrometheusLatestTo {
		return ""
	}
	var origin string
	switch from {
	case "3.9.1":
		origin = "3-9-1"
	case "3.10.0":
		origin = "3-10-0"
	case "3.11.3":
		origin = "3-11-3"
	case "3.12.0":
		origin = "3-12-0"
	case "3.13.3":
		origin = "3-13-3"
	default:
		return ""
	}
	if alertmanager {
		return "prometheus.alertmanager-api-v1.target-config." + origin + "-to-3-14-0"
	}
	return "prometheus.scrape-classic-histograms.target-config." + origin + "-to-3-14-0"
}

// cncfNativeResourceCheck makes the native-resource adapters useful without
// making an operator save a canonical Prufyx envelope. The supplied resources
// remain private source data; only their minimized canonical observation is
// evaluated or persisted in a report.
func (r runtime) cncfNativeResourceCheck(project, nativePath, nativePin, currentPath, currentPin, proposedPath, proposedPin, selectedJob string, complete, precedenceResolved bool, from, to, nowText, storeRoot, revision, bundle, receipt, replayPath, format string, resourceScopeComplete bool, kubernetesDistribution string, targetAPIApplyRequired bool, ciliumDistribution, requestedRuleID, otelGate, otelRemote string, args []string, prometheusHTTP2Required *bool, kyvernoContainer string) int {
	allowed := []string{"native-resource", "native-resource-digest"}
	prometheusAlertmanagerMode := project == "prometheus" && anyFlagProvided(args, "alertmanager-config", "alertmanager-config-digest", "alertmanager-config-complete", "alertmanager-config-precedence-resolved")
	prometheusRemoteWriteMode := project == "prometheus" && anyFlagProvided(args, "prometheus-config", "prometheus-config-digest", "prometheus-config-complete", "prometheus-config-precedence-resolved", "prometheus-rule", "prometheus-remote-write-name", "prometheus-remote-write-http2-required")
	if project == "cloudnativepg" {
		allowed = []string{"current-resource", "current-resource-digest", "resource", "resource-digest"}
	} else if project == "nats" {
		allowed = []string{"nats-config", "nats-config-digest"}
	} else if project == "strimzi" {
		allowed = []string{"kafka-resource", "kafka-resource-digest", "strimzi-distribution", "target-kafka-crd-admission-required"}
	} else if project == "falco" {
		allowed = []string{"falco-argv", "falco-argv-digest", "falco-distribution"}
	} else if project == "kuma" {
		allowed = []string{"kumactl-argv", "kumactl-argv-digest", "kuma-distribution"}
	} else if project == "crossplane" {
		allowed = []string{"composition", "composition-digest", "crossplane-distribution", "crossplane-schema-validation-required"}
	} else if project == "velero" {
		allowed = []string{"upgrade-plan", "upgrade-plan-digest", "velero-server-deployment", "velero-plan-order-declared"}
	} else if project == "spire" {
		allowed = []string{"spire-entry-argv", "spire-entry-argv-digest", "spire-distribution"}
	} else if project == "keda" {
		allowed = []string{"keda-scaled-object", "keda-scaled-object-digest", "keda-scaled-object-complete", "keda-legacy-tls-transport-required"}
	} else if project == "flux" {
		allowed = []string{"native-resource", "native-resource-digest", "resource-scope-complete"}
	} else if project == "kubernetes" {
		allowed = []string{"native-resource", "native-resource-digest", "resource-scope-complete", "distribution", "target-api-apply-required"}
	} else if project == "cilium" {
		allowed = []string{"cilium-config-map", "cilium-config-map-digest", "cilium-config-complete", "cilium-config-precedence-resolved", "cilium-distribution"}
	} else if project == "coredns" {
		allowed = []string{"coredns-corefile", "coredns-corefile-digest", "coredns-corefile-complete", "coredns-distribution"}
	} else if project == "envoy" {
		allowed = []string{"envoy-bootstrap", "envoy-bootstrap-digest", "envoy-bootstrap-selected"}
	} else if project == "prometheus" {
		if prometheusRemoteWriteMode {
			allowed = []string{"prometheus-config", "prometheus-config-digest", "prometheus-config-complete", "prometheus-config-precedence-resolved", "prometheus-rule", "prometheus-remote-write-name", "prometheus-remote-write-http2-required"}
		} else if prometheusAlertmanagerMode {
			allowed = []string{"alertmanager-config", "alertmanager-config-digest", "alertmanager-config-complete", "alertmanager-config-precedence-resolved"}
		} else {
			allowed = []string{"scrape-config", "scrape-config-digest", "scrape-job", "scrape-config-complete", "scrape-config-precedence-resolved"}
		}
	} else if project == "opentelemetry" {
		allowed = []string{"otel-collector-config", "otel-collector-config-digest", "otel-distribution", "otel-config-complete", "otel-config-precedence-resolved", "otel-rule", "otel-metrics-localhost-default", "otel-metrics-remote-scrape-required"}
	} else if project == "kyverno" {
		allowed = []string{"kyverno-resource", "kyverno-resource-digest", "container", "kyverno-distribution"}
	}
	if from == "" || to == "" || cncfUnexpectedModeFlag(args, allowed...) {
		return r.usage("invalid native CNCF resource check arguments; use --help")
	}
	var prepared cncfprepare.Prepared
	var rawDigests []string
	var expectedSourceDigest string
	selectedRuleID := requestedRuleID
	var err error
	switch project {
	case "metallb", "contour", "kubevirt", "thanos", "cortex", "coredns", "envoy", "nats", "strimzi", "falco", "kuma", "crossplane", "velero", "spire", "keda", "flux", "kubernetes", "cilium", "prometheus", "opentelemetry", "etcd", "kyverno", "harbor", "fluentd", "opencost", "cloud-custodian":
		if nativePath == "" || anyFlagProvided(args, "current-resource", "current-resource-digest", "resource", "resource-digest") {
			return r.usage("invalid native CNCF resource check arguments; use --help")
		}
		if project == "prometheus" && !prometheusAlertmanagerMode && !prometheusRemoteWriteMode && selectedJob == "" {
			return r.usage("invalid Prometheus selected scrape configuration arguments; use --help")
		}
		if project == "kyverno" && kyvernoContainer == "" {
			return r.usage("invalid Kyverno selected container arguments; use --help")
		}
		raw, readErr := readCNCFPrivate(nativePath, 1<<20)
		if readErr != nil {
			return r.fail(withPermissionHint("NATIVE_CNCF_RESOURCE_INPUT_INVALID", readErr), ExitUsage)
		}
		digest := digestCommunityBytes(raw)
		if nativePin != "" && nativePin != digest {
			return r.fail("NATIVE_CNCF_RESOURCE_INTEGRITY_FAILURE", ExitIntegrity)
		}
		if project == "kubevirt" {
			prepared, err = cncfprepare.PrepareKubeVirt(raw, from, to)
		} else if project == "thanos" {
			prepared, err = cncfprepare.PrepareThanos(raw, from, to)
		} else if project == "cortex" {
			prepared, err = cncfprepare.PrepareCortex(raw, from, to)
		} else if project == "nats" {
			prepared, err = cncfprepare.PrepareNATS(raw, from, to)
		} else if project == "strimzi" {
			if selectedJob != "" && selectedJob != cncfprepare.StrimziDistributionOfficial && selectedJob != cncfprepare.StrimziDistributionCustom {
				return r.usage("invalid Strimzi distribution; use --help")
			}
			prepared, err = cncfprepare.PrepareStrimziKafkaResource(raw, from, to, selectedJob, complete)
		} else if project == "falco" {
			if selectedJob != "" && selectedJob != cncfprepare.FalcoDistributionOfficial && selectedJob != cncfprepare.FalcoDistributionCustom {
				return r.usage("invalid Falco distribution; use --help")
			}
			prepared, err = cncfprepare.PrepareFalcoArgv(raw, from, to, selectedJob)
		} else if project == "kuma" {
			if selectedJob != "" && selectedJob != cncfprepare.KumaDistributionOfficial && selectedJob != cncfprepare.KumaDistributionCustom {
				return r.usage("invalid Kuma distribution; use --help")
			}
			prepared, err = cncfprepare.PrepareKumaInstallTransparentProxyArgv(raw, from, to, selectedJob)
		} else if project == "crossplane" {
			if selectedJob != "" && selectedJob != cncfprepare.CrossplaneDistributionOfficial && selectedJob != cncfprepare.CrossplaneDistributionCustom {
				return r.usage("invalid Crossplane distribution; use --help")
			}
			prepared, err = cncfprepare.PrepareCrossplaneComposition(raw, from, to, selectedJob, complete)
		} else if project == "velero" {
			prepared, err = cncfprepare.PrepareVeleroUpgradePlan(raw, from, to, selectedJob, complete)
		} else if project == "spire" {
			if selectedJob != "" && selectedJob != cncfprepare.SpireDistributionOfficial && selectedJob != cncfprepare.SpireDistributionCustom {
				return r.usage("invalid SPIRE distribution; use --help")
			}
			prepared, err = cncfprepare.PrepareSpireEntryCreateArgv(raw, from, to, selectedJob)
		} else if project == "keda" {
			if selectedJob != "" && selectedJob != cncfprepare.KEDADeclarationRequired && selectedJob != cncfprepare.KEDADeclarationNotRequired {
				return r.usage("invalid KEDA legacy TLS transport declaration; use --help")
			}
			prepared, err = cncfprepare.PrepareKEDAScaledObject(raw, from, to, selectedJob, complete)
		} else if project == "opentelemetry" {
			if selectedRuleID == cncfprepare.OpenTelemetryInternalMetricsRuleID {
				prepared, err = cncfprepare.PrepareOpenTelemetryInternalMetrics(raw, from, to, selectedJob, otelGate, otelRemote, complete, precedenceResolved)
			} else {
				prepared, err = cncfprepare.PrepareOpenTelemetryCollector(raw, from, to, selectedJob, complete, precedenceResolved)
				selectedRuleID = opentelemetryLoggingRuleID
			}
		} else if project == "flux" {
			prepared, err = cncfprepare.PrepareFlux(raw, from, to, resourceScopeComplete)
		} else if project == "kubernetes" {
			if kubernetesDistribution != "" && kubernetesDistribution != "official_upstream" && kubernetesDistribution != "custom_build" {
				return r.usage("invalid Kubernetes distribution; use --help")
			}
			prepared, err = cncfprepare.PrepareKubernetesRemovedAPIs(raw, from, to, kubernetesDistribution, targetAPIApplyRequired, resourceScopeComplete)
		} else if project == "cilium" {
			if ciliumDistribution != "" && ciliumDistribution != "official_upstream" && ciliumDistribution != "custom_build" {
				return r.usage("invalid Cilium distribution; use --help")
			}
			prepared, err = cncfprepare.PrepareCiliumClusterName(raw, from, to, ciliumDistribution, complete, precedenceResolved)
		} else if project == "coredns" {
			prepared, err = cncfprepare.PrepareCoreDNSCorefile(raw, from, to, selectedJob, complete)
		} else if project == "envoy" {
			prepared, err = cncfprepare.PrepareEnvoyBootstrap(raw, from, to, complete)
		} else if project == "etcd" {
			prepared, err = cncfprepare.PrepareEtcd(raw, from, to)
		} else if project == "harbor" {
			prepared, err = cncfprepare.PrepareHarbor(raw, from, to)
		} else if project == "fluentd" {
			prepared, err = cncfprepare.PrepareFluentD(raw, from, to)
		} else if project == "opencost" {
			prepared, err = cncfprepare.PrepareOpenCostCloudSource(raw, from, to)
		} else if project == "cloud-custodian" {
			prepared, err = cncfprepare.PrepareCloudCustodian(raw, from, to)
		} else if project == "kyverno" {
			if selectedJob != "" && selectedJob != cncfprepare.KyvernoDistributionOfficial && selectedJob != cncfprepare.KyvernoDistributionCustom {
				return r.usage("invalid Kyverno distribution; use --help")
			}
			prepared, err = cncfprepare.PrepareKyvernoScoped(raw, kyvernoContainer, from, to, selectedJob)
		} else if prometheusRemoteWriteMode {
			prepared, err = cncfprepare.PreparePrometheusRemoteWriteConfig(raw, selectedJob, from, to, complete, precedenceResolved, prometheusHTTP2Required)
			selectedRuleID = cncfprepare.PrometheusRemoteWriteHTTP2RuleID
		} else if prometheusAlertmanagerMode {
			prepared, err = cncfprepare.PreparePrometheusAlertmanagerConfig(raw, from, to, complete, precedenceResolved)
			selectedRuleID = prometheusNativeRuleID(from, to, true)
		} else if project == "prometheus" {
			prepared, err = cncfprepare.PreparePrometheusScrapeConfig(raw, selectedJob, from, to, complete, precedenceResolved)
			selectedRuleID = prometheusNativeRuleID(from, to, false)
		} else {
			prepared, err = cncfprepare.PrepareNativeMigration(raw, project, from, to)
		}
		rawDigests = []string{digest}
		expectedSourceDigest = digest
	case "cloudnativepg":
		if anyFlagProvided(args, "native-resource", "native-resource-digest") || nativePath != "" || currentPath == "" || proposedPath == "" {
			return r.usage("invalid CloudNativePG resource check arguments; use --help")
		}
		current, currentErr := readCNCFPrivate(currentPath, 1<<20)
		proposed, proposedErr := readCNCFPrivate(proposedPath, 1<<20)
		if currentErr != nil || proposedErr != nil {
			hintErr := currentErr
			if hintErr == nil {
				hintErr = proposedErr
			}
			return r.fail(withPermissionHint("CLOUDNATIVEPG_RESOURCE_INPUT_INVALID", hintErr), ExitUsage)
		}
		currentDigest, proposedDigest := digestCommunityBytes(current), digestCommunityBytes(proposed)
		if (currentPin != "" && currentPin != currentDigest) || (proposedPin != "" && proposedPin != proposedDigest) {
			return r.fail("CLOUDNATIVEPG_RESOURCE_INTEGRITY_FAILURE", ExitIntegrity)
		}
		envelope, marshalErr := json.Marshal(struct {
			Current  json.RawMessage `json:"current"`
			Proposed json.RawMessage `json:"proposed"`
		}{Current: current, Proposed: proposed})
		if marshalErr != nil {
			return r.fail("CLOUDNATIVEPG_RESOURCE_INPUT_INVALID", ExitUsage)
		}
		prepared, err = cncfprepare.PrepareCloudNativePG(envelope, from, to)
		rawDigests = []string{currentDigest, proposedDigest}
		expectedSourceDigest = digestCommunityBytes(envelope)
	default:
		return r.usage("invalid native CNCF project; use --help")
	}
	if err != nil || prepared.SourceDigest != expectedSourceDigest || prepared.InputDigest != digestCommunityBytes(prepared.CanonicalInputJSON) || !json.Valid(prepared.CanonicalInputJSON) {
		return r.fail("NATIVE_CNCF_RESOURCE_INPUT_INVALID", ExitUsage)
	}
	if _, err := cncfcheck.Catalog(false, project); err != nil {
		return r.cncfError("CNCF project selection failed", err)
	}
	if storeRoot != "" {
		if nowText != "" || (replayPath != "" && (revision == "" || bundle == "" || receipt == "" || (project != "cloudnativepg" && nativePin == "") || (project == "cloudnativepg" && (currentPin == "" || proposedPin == "")))) {
			return r.usage("external native CNCF replay requires every raw resource digest and all knowledge pins")
		}
		return r.externalCNCF(cncfknowledge.Request{Selection: knowledge.SelectionRequest{StoreRoot: storeRoot, ExpectedRevision: revision, ExpectedBundleDigest: bundle, ExpectedTrustReceiptDigest: receipt}, Project: project, SelectedRuleID: selectedRuleID, Input: prepared.CanonicalInputJSON, InputDigest: prepared.InputDigest}, replayPath, format)
	}
	if revision != "" || bundle != "" || receipt != "" || nowText == "" || replayPath != "" {
		return r.usage("native CNCF resource checks require canonical --now or an explicit signed knowledge selection")
	}
	now, err := parseUTC(nowText)
	if err != nil || now.Nanosecond() != 0 || now.Format(time.RFC3339) != nowText {
		return r.usage("CNCF check time must be explicit canonical UTC with whole seconds")
	}
	var report cncfcheck.Report
	if selectedRuleID != "" {
		report, err = cncfcheck.CheckRule(project, selectedRuleID, prepared.CanonicalInputJSON, now)
	} else if project == "kubernetes" {
		// The rendered apply-set adapter decides only removed-API rules; other
		// Kubernetes rules on the same transition need other evidence.
		report, err = cncfcheck.CheckFacts(project, cncfprepare.KubernetesRemovedAPIAllFacts(), prepared.CanonicalInputJSON, now)
	} else {
		report, err = cncfcheck.Check(project, prepared.CanonicalInputJSON, now)
	}
	if err != nil {
		return r.cncfError("CNCF source-constraint check failed", err)
	}
	encoded, err := cncfcheck.MarshalReport(report)
	if err != nil {
		return r.fail("CNCF report integrity failure", ExitIntegrity)
	}
	if format == "json" {
		if _, err := fmt.Fprintln(r.stdout, string(encoded)); err != nil {
			return ExitIntegrity
		}
	} else {
		if _, err := fmt.Fprintf(r.stdout, "%s native input review\nraw input digests: %s\nprepared input digest: %s\naggregate: UNKNOWN\nnetwork used: false\nwhole-upgrade compatibility: UNKNOWN\n", project, joinNativeDigests(rawDigests), prepared.InputDigest); err != nil {
			return ExitIntegrity
		}
		if prometheusRemoteWriteMode {
			if _, err := fmt.Fprintln(r.stdout, "selected input: one literal-name remote_write entry from the caller-supplied full configuration\nscope: direct enable_http2 and declared endpoint requirement only; negotiation, delivery, runtime flags, includes, and whole-config validity remain unverified"); err != nil {
				return ExitIntegrity
			}
		} else if prometheusAlertmanagerMode {
			selection := "literal api_version from the caller-selected mapping"
			if prepared.Reason == cncfprepare.ReasonPrometheusAlertmanagerAPIDefaultV2 {
				selection = "api_version omitted; exact target source-derived default v2"
			}
			if _, err := fmt.Fprintf(r.stdout, "selected API-version input: %s\ninput authority: caller-selected mapping; not observed running configuration\nscope: Alertmanager API-version selection only; v2 support, reachability and alert delivery remain unverified\n", selection); err != nil {
				return ExitIntegrity
			}
		}
		for _, claim := range report.Check.Claims {
			if _, err := fmt.Fprintf(r.stdout, "%s: %s (%s)\nnext action: %s\n", claim.RuleID, claim.Status, claim.ReasonCode, claim.NextAction); err != nil {
				return ExitIntegrity
			}
			if _, err := fmt.Fprintln(r.stdout, claim.EvidenceBasisLine()); err != nil {
				return ExitIntegrity
			}
			for _, source := range claim.Sources {
				if _, err := fmt.Fprintf(r.stdout, "pinned source: %s lines %d-%d; revision %s; digest %s\n", source.URL, source.StartLine, source.EndLine, source.Revision, source.ContentDigest); err != nil {
					return ExitIntegrity
				}
			}
		}
	}
	return cncfcheck.ClaimExit(report)
}

func joinNativeDigests(values []string) string {
	if len(values) == 1 {
		return values[0]
	}
	return values[0] + "," + values[1]
}
