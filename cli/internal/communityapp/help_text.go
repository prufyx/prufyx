// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

// Detailed per-command help. The overview lives in help.go; these blocks are
// printed by "prufyx <command> help" and "prufyx help <command>".

const prepareHelp = `Usage:
  prufyx prepare <cncf|project> --project SLUG [flags]

Build a check input from a project's own configuration file. The prepared input can then
be passed to prufyx check; --format input writes it out.

Routes:
  cncf      one CNCF project (about 50), by --project SLUG
  project   airflow, grafana, kibana, loki, opensearch, fluent-bit, ceph

Examples:
  prufyx prepare cncf --project opencost --input opencost.json --from 1.119.0 --to 1.120.0
  prufyx prepare cncf --project linkerd --input linkerd.json --from 2.13.7 --to 2.14.0
  prufyx prepare project --project loki --loki-schema-config schema.yaml \
      --from 2.9.8 --to 3.0.0 --effective-config-complete --precedence-resolved

Per-project inputs and flags:
  prufyx prepare cncf --project SLUG --help
  ` + docsProjectsHint + `

Exit status: 0 prepared, 11 unresolved preparation, 2 invalid input, 3 integrity failure.`

const checkHelp = `Usage:
  prufyx check <route> [flags]

Evaluate one scoped rule route against the inputs you declare. To scan whole manifests, use
prufyx scan.

Routes:
  cncf                          one CNCF project (about 50), by --project SLUG
  project                       airflow, grafana, kibana, loki, opensearch, fluent-bit, ceph
  cert-manager-values           cert-manager Helm values
  batch                         run a plan file of checks
  prometheus-mode               Prometheus mode observation
  spiffe-x509-svid              a SPIFFE X.509 SVID certificate
  cloudevents-structured-json   a CloudEvents structured JSON event
  tikv-gcp-v2-wif-backup        a TiKV GCP v2 workload-identity backup config

Examples:
  prufyx check cncf --project knative --service service.json --from 1.22.0 --to 1.23.0 \
      --now 2026-10-18T00:00:00Z
  prufyx check cert-manager-values --from 1.20.3 --to 1.21.1 --values values.json
  prufyx check batch --plan plan.json --root . --now 2026-10-18T00:00:00Z

Flags shared by most routes:
  --from, --to VERSION     versions to compare
  --now RFC3339            evaluation time, or --knowledge-db DIR for a local store
  --format human|json      report format (default human)
  --strict-exit            exit 14 instead of 0 for a scoped PASS

Project inputs: prufyx check cncf --project SLUG --help (` + docsProjectsHint + `)
Exit: 0 scoped PASS (not a whole-upgrade PASS), 10 BLOCKED, 11 UNKNOWN, 2 invalid, 3 integrity.`

const checkCNCFHelp = `Usage:
  prufyx check cncf --project SLUG --input FILE (--now RFC3339 | --knowledge-db DIR) [flags]

Check one CNCF project's upgrade against the minimized declarations you supply.
The input flag differs per project: see the project's usage with --project SLUG --help.

Examples:
  prufyx check cncf --project knative --service service.json --from 1.22.0 --to 1.23.0 \
      --now 2026-10-18T00:00:00Z
  prufyx check cncf --project emissary-ingress --diagd-argv argv.json --from 3.10.0 --to 4.0.1 \
      --now 2026-10-18T00:00:00Z
  prufyx check cncf --project SLUG --input input.json --now 2026-10-18T00:00:00Z

Flags:
  --project SLUG           project to check (prufyx catalog cncf lists them)
  --input FILE             minimized declarations; per-project flags replace it
  --from, --to VERSION     versions to compare
  --now RFC3339            evaluate with the embedded knowledge at this time
  --knowledge-db DIR       use a local signed knowledge store instead
  --knowledge auto|embedded  choose the installed store or the embedded knowledge
  --require-basis LIST     only evaluate rules whose evidence basis is in LIST
  --show-passes            human output: list PASS claims instead of counting them
  --input-digest SHA256    pin the exact input file
  --via V1,V2,...          with --input: also check each hop of the upgrade through these
                           exact versions (ascending, between the input's versions); BLOCKED
                           if any hop is, PASS only if every hop passes, else UNKNOWN
  --replay-report FILE     re-check a prior JSON report
  --format human|json      report format (default human)

Per-project usage and prose: prufyx check cncf --project SLUG --help
Docs: ` + docsProjectsHint + `
Exit: 0 PASS, 10 BLOCKED, 2 invalid input, 3 integrity failure, and
  11 UNKNOWN, UNSUPPORTED, NO_KNOWN_ISSUE or no rules.`

const prepareCNCFHelp = `Usage:
  prufyx prepare cncf --project SLUG --input FILE [flags]

Build a check input from a CNCF project's own configuration. Writes nothing unless you ask
for --format input. Raw workload data is not kept in the report.

Examples:
  prufyx prepare cncf --project opencost --input opencost.json --from 1.119.0 --to 1.120.0
  prufyx prepare cncf --project linkerd --input linkerd.json --from 2.13.7 --to 2.14.0
  prufyx prepare cncf --project harbor --input harbor.json --from 2.7.0 --to 2.8.0 \
      --format input

Flags:
  --project SLUG           project to prepare (prufyx catalog cncf lists them)
  --input FILE             the project's own configuration; per-project flags replace it
  --from, --to VERSION     versions to compare
  --input-digest SHA256    pin the exact input file
  --format human|json|input  report, JSON, or the prepared input itself

Per-project usage and prose: prufyx prepare cncf --project SLUG --help
Docs: ` + docsProjectsHint + `
Exit: 0 prepared, 11 unresolved preparation, 2 invalid input, 3 integrity failure.`

const checkProjectHelp = `Usage:
  prufyx check project --project SLUG --effective-config FILE [flags]

Check one non-CNCF project's upgrade against its effective configuration. This preview is
embedded-only: --knowledge-db, --profile and replay flags are not supported.

Examples:
  prufyx check project --project loki --loki-schema-config schema.yaml --from 2.9.8 --to 3.0.0 \
      --effective-config-complete --precedence-resolved --now 2026-10-18T00:00:00Z
  prufyx check project --project grafana --effective-config grafana.ini --from VERSION \
      --to VERSION --effective-config-complete --precedence-resolved --now 2026-10-18T00:00:00Z

Flags:
  --project SLUG           airflow, grafana, kibana, loki, opensearch, fluent-bit or ceph
  --effective-config FILE  effective configuration; loki, fluent-bit and ceph name their own
                           input flag (see --project SLUG --help)
  --from, --to VERSION     versions to compare
  --now RFC3339            evaluation time
  --format human|json      report format (default human)

Per-project usage and prose: prufyx check project --project SLUG --help
Docs: ` + docsProjectsHint + `
Exit: 0 PASS, 10 BLOCKED, 11 UNKNOWN, 2 invalid input, 3 integrity failure.`

const prepareProjectHelp = `Usage:
  prufyx prepare project --project SLUG --effective-config FILE [flags]

Build a check input from a non-CNCF project's effective configuration.

Examples:
  prufyx prepare project --project loki --loki-schema-config schema.yaml --from 2.9.8 --to 3.0.0 \
      --effective-config-complete --precedence-resolved
  prufyx prepare project --project grafana --effective-config grafana.ini --from VERSION \
      --to VERSION --effective-config-complete --precedence-resolved

Flags:
  --project SLUG           airflow, grafana, kibana, loki, opensearch, fluent-bit or ceph
  --effective-config FILE  effective configuration; loki, fluent-bit and ceph name their own
                           input flag (see --project SLUG --help)
  --from, --to VERSION     versions to compare
  --format human|json|input  report, JSON, or the prepared input itself

Per-project usage and prose: prufyx prepare project --project SLUG --help
Docs: ` + docsProjectsHint + `
Exit: 0 prepared, 11 unresolved preparation, 2 invalid input, 3 integrity failure.`

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
  prufyx db status [--db-root DIR] [--profile cert-manager|cncf|cncf-projects|spiffe-x509-svid|cloudevents-structured-json|tikv-gcp-v2-wif-backup] [--format human|json]
  prufyx db capabilities --profile cncf [--format human|json]

Verify, import and status are offline. Without --db-root, status of the
cncf-projects profile reads the default store location that db update installs into. Verify requires an independently trusted
bootstrap root and does not inspect a store or establish import eligibility.
Only explicit update fetches a complete package;
no configuration or report is uploaded. The default profile is cert-manager. Use a
separate private directory for each marked profile.
Profiles cannot share trust, selection or rollback state. This source capability
accepts operator-provisioned roots and reports synthetic test knowledge explicitly.`
