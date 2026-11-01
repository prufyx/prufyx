### Fixed

- A falco upgrade to 0.37.0 is no longer a scoped PASS for the removed config keys `outputs.rate` and `outputs.max_burst` while the deployment declares a command-line option that release also removed (`-u`/`--userspace`, `-k`, `-K`, `--k8s-api`, `--k8s-api-cert`, `--k8s-node`): the config-key set is then treated as not complete and the rules stay UNKNOWN.
