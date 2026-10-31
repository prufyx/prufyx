### Fixed
- `check project` for opensearch no longer gives a scoped PASS when the file sets any `opensearch.experimental.*` setting: the 3.0.0 release removed experimental feature flags no rule names, so the answer is UNKNOWN with an omission naming the key.
- `check project` for airflow and opensearch now prints the preparation omissions (human preamble) and `preparationOmissions` (JSON).
- A continuation line led by `\v`, `\f` or another whitespace is no longer read as an airflow option; an empty or comments-only config is rejected for both projects (exit 2).
