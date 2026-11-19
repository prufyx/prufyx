### Fixed

- `assess` no longer reports a component as absent when a workload image matched a reviewed component identity but could not be verified (for example an `index.docker.io/...` reference under profile v3). The collection is marked partial with `COMPONENT_VERSION_UNBOUND` and the affected checks are indeterminate, with the next action named.
