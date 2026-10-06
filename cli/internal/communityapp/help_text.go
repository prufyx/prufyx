// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

// Detailed per-command help. The overview lives in help.go; these blocks are
// printed by "prufyx <command> help" and "prufyx help <command>".

const prepareHelp = `Usage:
  prufyx prepare project --project grafana|kibana|loki --effective-config FILE --from VERSION --to VERSION --effective-config-complete --precedence-resolved [--effective-config-digest SHA256] [--format human|json|input]
  prufyx prepare project --project loki --loki-schema-config FILE --from 2.9.8 --to 3.0.0 --effective-config-complete --precedence-resolved [--use-reviewed-target-default] [--loki-schema-config-digest SHA256] [--format human|json|input]
  prufyx prepare project --project fluent-bit --effective-config FILE --from 3.2.0 --to 4.0.0 --effective-config-complete --current-default-was-used --preserve-http2-enabled [--effective-config-digest SHA256] [--format human|json|input]
  prufyx prepare project --project ceph --selected-osd-metadata FILE --selected-osd-id ID --from VERSION --to VERSION --selected-osd-metadata-complete [--selected-osd-metadata-digest SHA256] [--format human|json|input]
    note: Kibana 9.0.8|9.1.10|9.2.8|9.3.8|9.4.6 -> 9.5.3 additionally requires --full-status-without-monitor-required for the status-page scope.
  prufyx prepare project --project fluent-bit --effective-config FILE --from 3.2.10|4.0.14|4.1.2|4.2.8|5.0.10 --to 5.1.2 --effective-config-complete --require-http2 [--effective-config-digest SHA256] [--format human|json|input]
  prufyx prepare cncf --project kyverno --input FILE --container NAME --from VERSION --to VERSION [--distribution official_upstream|custom_build] [--format human|json|input]
  prufyx prepare cncf --project linkerd --input FILE --from 2.13.7 --to 2.14.0 [--distribution official_upstream|custom_build] [--schema-validation required|disabled] [--format human|json|input]
  prufyx prepare cncf --project karmada --input FILE --from 1.18.3 --to 1.19.0 [--distribution official_upstream|custom_build] [--target-policy-crd-admission required|disabled] [--input-digest SHA256] [--format human|json|input]
  prufyx prepare cncf --project argo-cd --input FILE --from 2.14.0 --to 3.0.0 [--requires-inherited-application-permissions true|false] [--input-digest SHA256] [--format human|json|input]
  prufyx prepare cncf --project jaeger --input FILE --from 1.76.0 --to 2.20.0 [--non-memory-storage-required true|false] [--official-jaeger-distribution true|false] [--input-digest SHA256] [--format human|json|input]
  prufyx prepare cncf --project opencost --input FILE --from 1.119.0 --to 1.120.0 [--input-digest SHA256] [--format human|json|input]
  prufyx prepare cncf --project harbor --input FILE --from 2.7.0 --to 2.8.0 [--input-digest SHA256] [--format human|json|input]
  prufyx prepare cncf --project harbor --input FILE --from 2.10.3|2.11.2|2.12.4|2.13.5|2.14.4 --to 2.15.2 [--input-digest SHA256] [--format human|json|input]
  prufyx prepare cncf --project containerd --input FILE --runtime-handler NAME --from 1.7.28 --to 2.0.0 --containerd-config-complete --containerd-config-precedence-resolved --containerd-official-upstream --containerd-official-bundled-runtimes-only [--input-digest SHA256] [--format human|json|input]`

const checkHelp = `Usage:
  prufyx check cncf --project argo-cd --config-map FILE --from 2.14.0 --to 3.0.0 [--requires-inherited-application-permissions true|false] --now RFC3339 [--config-map-digest SHA256] [--format human|json]
  prufyx check cncf --project argo-cd --resource-exclusions-config-map FILE --from 2.14.0 --to 3.0.0 --resource-exclusions-config-complete --resource-exclusions-precedence-resolved [--requires-v2-visibility-of-v3-default-excluded-resources true] --now RFC3339 [--resource-exclusions-config-map-digest SHA256] [--format human|json]
  prufyx check cncf --project knative --service FILE --from 1.22.0 --to 1.23.0 --now RFC3339 [--service-digest SHA256] [--format human|json]
  prufyx check cncf --project emissary-ingress --diagd-argv FILE --from 3.10.0 --to 4.0.1 --now RFC3339 [--diagd-argv-digest SHA256] [--format human|json]
  prufyx check cncf --project openfga --effective-config FILE --from 1.17.1 --to 1.18.0 [--effective-config-complete] --now RFC3339 [--effective-config-digest SHA256] [--format human|json]
  prufyx check cncf --project prometheus --scrape-config FILE --scrape-job NAME --from 2.55.1 --to 3.1.0 --scrape-config-complete --scrape-config-precedence-resolved --now RFC3339 [--scrape-config-digest SHA256] [--format human|json]
  prufyx check cncf --project prometheus --alertmanager-config FILE --from 2.55.1 --to 3.1.0 --alertmanager-config-complete --alertmanager-config-precedence-resolved --now RFC3339 [--alertmanager-config-digest SHA256] [--format human|json]
  prufyx check cncf --project prometheus --prometheus-config FILE --prometheus-config-complete --prometheus-config-precedence-resolved --prometheus-rule remote-write-http2-default --prometheus-remote-write-name NAME --prometheus-remote-write-http2-required=true|false --from 2.55.1 --to 3.14.0 --now RFC3339 [--prometheus-config-digest SHA256] [--format human|json]
  prufyx check cncf --project containerd --containerd-config FILE --runtime-handler NAME --from 1.7.28 --to 2.0.0 --containerd-config-complete --containerd-config-precedence-resolved --containerd-official-upstream --containerd-official-bundled-runtimes-only --now RFC3339 [--containerd-config-digest SHA256] [--format human|json]
  prufyx check cncf --project SLUG --input FILE --now RFC3339 [--input-digest SHA256] [--format human|json]
  prufyx check cncf --project SLUG --input FILE --knowledge-db DIR [--input-digest SHA256] [--format human|json]
  prufyx check project --project grafana|kibana|loki --effective-config FILE --from VERSION --to VERSION --effective-config-complete --precedence-resolved --now RFC3339 [--effective-config-digest SHA256] [--format human|json]
  prufyx check project --project loki --loki-schema-config FILE --from 2.9.8 --to 3.0.0 --effective-config-complete --precedence-resolved --now RFC3339 [--use-reviewed-target-default] [--loki-schema-config-digest SHA256] [--format human|json]
  prufyx check project --project fluent-bit --effective-config FILE --from 3.2.0 --to 4.0.0 --effective-config-complete --current-default-was-used --preserve-http2-enabled --now RFC3339 [--effective-config-digest SHA256] [--format human|json]
  prufyx check project --project ceph --selected-osd-metadata FILE --selected-osd-id ID --from VERSION --to VERSION --selected-osd-metadata-complete --now RFC3339 [--selected-osd-metadata-digest SHA256] [--format human|json]
    note: Kibana 9.0.8|9.1.10|9.2.8|9.3.8|9.4.6 -> 9.5.3 additionally requires --full-status-without-monitor-required for the status-page scope.
  prufyx check project --project fluent-bit --effective-config FILE --from 3.2.10|4.0.14|4.1.2|4.2.8|5.0.10 --to 5.1.2 --effective-config-complete --require-http2 --now RFC3339 [--effective-config-digest SHA256] [--format human|json]
  prufyx check cert-manager-values --from VERSION --to VERSION --values FILE [--schema-validation required|disabled] [--values-digest SHA256] [--format human|json]
  prufyx check batch --plan FILE --root DIR (--now RFC3339 | --knowledge-db DIR) [--format human|json] [--exit-mode legacy|detailed]
  prufyx check prometheus-mode --demo [--format human|json]
  prufyx check prometheus-mode --observation-root DIR --proposed-workload FILE --proposed-digest SHA256 --captured-at RFC3339 --now RFC3339 --max-age DURATION [--format human|json]
  prufyx check spiffe-x509-svid --certificate FILE --now RFC3339 [--certificate-digest SHA256] [--format human|json]
  prufyx check spiffe-x509-svid --certificate FILE --knowledge-db DIR [--certificate-digest SHA256] [--format human|json]
  prufyx check cloudevents-structured-json --event FILE --now RFC3339 [--event-digest SHA256] [--format human|json]
  prufyx check cloudevents-structured-json --event FILE --knowledge-db DIR [--event-digest SHA256] [--format human|json]
  prufyx check tikv-gcp-v2-wif-backup --config FILE --target-version VERSION --operation OPERATION --now RFC3339 [--config-digest SHA256] [--format human|json]
  prufyx check tikv-gcp-v2-wif-backup --config FILE --target-version VERSION --operation OPERATION --knowledge-db DIR [--config-digest SHA256] [--format human|json]

Exit status for check cncf and check project: 0 scoped PASS, 10 scoped BLOCKED, 11 UNKNOWN, 2 invalid input, 3 integrity failure. Exit 0 is not a whole-upgrade PASS: add --strict-exit to any check to exit 14 instead of 0 on a scoped PASS (see cli/docs/exit-codes.md).
Exit status for check cert-manager-values: 0 scoped PASS, 10 scoped BLOCKED, 11 UNKNOWN, 2 invalid input, 3 integrity failure.
Exit status for check prometheus-mode: 0 scoped PASS, 11 ATTENTION or UNKNOWN. The legacy alias always exits 11 because its aggregate remains UNKNOWN.
Exit status for check spiffe-x509-svid: 0 scoped PASS, 10 scoped FAIL, 11 UNKNOWN, 2 invalid input, 3 integrity failure.
Exit status for check cloudevents-structured-json: 0 scoped PASS, 10 scoped FAIL, 11 UNKNOWN, 2 invalid input, 3 integrity failure.
Exit status for check tikv-gcp-v2-wif-backup: 0 scoped PASS, 10 scoped BLOCKED, 11 UNKNOWN, 2 invalid input, 3 integrity failure.
Exit status for check batch: legacy mode preserves 0 PASS, 10 BLOCKED, 11 UNKNOWN or stale, 2 invalid input, 3 integrity failure; detailed mode uses 12 stale evidence and 13 evaluation clock before review.`

const catalogHelp = `Usage:
  prufyx catalog cncf [--priority] [--project SLUG] [--format human|json]
  prufyx catalog checks --project SLUG [--from VERSION --to VERSION] [--format human|json]`

const communityPreviewHelp = `Usage:
  prufyx community-preview example <cncf-coredns-latest|cncf-envoy-latest|cncf-etcd|cncf-nats-latest|cncf-opentelemetry|cncf-rook-latest|knowledge-cert-manager|knowledge-cncf|project-ceph-latest>
  prufyx community-preview validate-prometheus-mode ...`

const dbHelp = `Usage:
  prufyx db verify FILE --profile cert-manager|cncf|cncf-projects|spiffe-x509-svid|cloudevents-structured-json|tikv-gcp-v2-wif-backup --bootstrap-root FILE --bootstrap-root-digest SHA256 [--expected-package-digest SHA256] [--expected-revision REVISION] [--expected-bundle-digest SHA256] [--format human|json]
  prufyx db import FILE --db-root DIR [--profile cert-manager|cncf|cncf-projects|spiffe-x509-svid|cloudevents-structured-json|tikv-gcp-v2-wif-backup] [--bootstrap-root FILE --bootstrap-root-digest SHA256] [--expected-revision REVISION] [--expected-bundle-digest SHA256] [--format human|json]
  prufyx db update --source HTTPS_URL --package-out FILE --db-root DIR [--profile cert-manager|cncf|cncf-projects|spiffe-x509-svid|cloudevents-structured-json|tikv-gcp-v2-wif-backup] [--bootstrap-root FILE --bootstrap-root-digest SHA256] [--expected-revision REVISION] [--expected-bundle-digest SHA256] [--format human|json]
  prufyx db status --db-root DIR [--profile cert-manager|cncf|cncf-projects|spiffe-x509-svid|cloudevents-structured-json|tikv-gcp-v2-wif-backup] [--format human|json]
  prufyx db capabilities --profile cncf [--format human|json]

Verify, import and status are offline. Verify requires an independently trusted
bootstrap root and does not inspect a store or establish import eligibility.
Only explicit update fetches a complete package;
no configuration or report is uploaded. The default profile is cert-manager. Use a
separate private directory for each marked profile.
Profiles cannot share trust, selection or rollback state. This source capability
accepts operator-provisioned roots and reports synthetic test knowledge explicitly.`
