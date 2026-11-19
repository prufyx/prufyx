### Fixed
- Do not report DOCUMENTS_TEMPLATED for PrometheusRule alert annotation and label values that hold Prometheus alert templates such as `{{ $labels.instance }}` or `{{ $value }}`. Rendered kube-prometheus-stack manifests no longer degrade Kubernetes hops to PARTIAL. Any other template syntax, including Helm values, control actions, includes, keys and every other field, is still reported.
