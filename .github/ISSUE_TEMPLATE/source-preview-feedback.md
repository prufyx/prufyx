---
name: Development source-preview feedback
about: Report a focused technical-review observation from the development/source preview
labels: source-preview, feedback
---

## Five-minute path

- [ ] I used Go 1.26.8 with `GOTOOLCHAIN=local`, `GOPROXY=off`, `GOSUMDB=off`,
  and `GOFLAGS='-mod=vendor -buildvcs=false'`.
- [ ] I ran the MetalLB example from the README and observed the scoped
  `BLOCKED` result for the legacy ConfigMap before rechecking the reviewed CR
  resource.
- [ ] I understand that the example does not prove deployed configuration
  conversion, runtime, traffic safety, or whole-upgrade results.

## What helped or blocked review?

Describe only the build, report, source-link, or bounded correction experience.
Which exact configuration-aware, non-sensitive input would be most useful next?
Which result should remain `UNKNOWN` without more evidence?

## Data boundary

Do **not** include credentials, Secrets, customer configuration, Kubernetes
objects, private paths, logs, production snapshots, or proprietary source.
Use a synthetic minimal example instead.

## Contribution boundary

This feedback does not approve a compatibility rule or authorize publication.
Proposed source changes follow [CONTRIBUTING.md](https://github.com/prufyx/prufyx/blob/main/CONTRIBUTING.md);
the offline bundle includes `CONTRIBUTING.md` at its root.
Code contributions are licensed AGPL-3.0-only, knowledge data CC BY-SA 4.0, and both require a signed [CLA](https://github.com/prufyx/prufyx/blob/main/CLA.md).
