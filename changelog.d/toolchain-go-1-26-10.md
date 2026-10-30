### Security

- Release builds now require Go 1.26.10 (was 1.26.8): the release workflow, the toolchain check, the shipping policy toolchain digests, the factory image and the build documentation move together. CI also runs `govulncheck` on the CLI module and fails on findings.
