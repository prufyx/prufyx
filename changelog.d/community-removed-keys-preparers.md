### Added

- Effective-config preparers for the community projects Apache Airflow (`airflow.cfg`) and OpenSearch (`opensearch.yml`) that read the listed removed options and settings as a bool fact each. Input that wraps the file (Helm values, a ConfigMap) or whose spelling could change which key is meant is UNKNOWN, never PASS.
