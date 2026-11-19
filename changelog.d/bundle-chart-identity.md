### Added

- The bundle carries a new field, chart identity (chart name and chart version, with the object it was read from), taken only from your own `--chart-declaration` file or from the chart label of workloads the collector already reads. Release records, Secrets, ConfigMaps and values are never read. Conflicting evidence is marked ambiguous, and a missing identity names its next action: declare the chart name and version. Nothing decides on the field yet.
