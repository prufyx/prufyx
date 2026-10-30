### Fixed

- Release `.rpm` packages are now byte-reproducible across build hosts: the RPM build host header field is fixed to `prufyx-release` instead of the builder's hostname.
- The release packages step installs `cpio` next to `rpm2cpio` when either is missing, so the package check also runs on a runner without the `rpm` tools or with `rpm2cpio` but no `cpio`.
