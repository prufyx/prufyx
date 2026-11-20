# v1.6 Changelog

## Table of Content

- [v1.6 Changelog](#v16-changelog)
  - [Table of Content](#table-of-content)
- [v1.6.2](#v162)
  - [Major Changes Since v1.6.1](#major-changes-since-v161)
    - [Bug or Regression](#bug-or-regression)
    - [Other (Cleanup or Flake)](#other-cleanup-or-flake)
- [v1.6.1](#v161)
  - [Major Changes Since v1.6.0](#major-changes-since-v160)
    - [Test \& Conformance](#test--conformance)
    - [Other (Cleanup or Flake)](#other-cleanup-or-flake)
- [v1.6.0](#v160)
  - [Major Changes Since v1.6.0-rc.2](#major-changes-since-v160-rc2)
    - [Bug or Regression](#bug-or-regression)
    - [Test \& Conformance](#test--conformance)
- [v1.6.0-rc.2](#v160-rc2)
  - [Major Changes Since v1.6.0-rc.1](#major-changes-since-v160-rc1)
    - [Bug or Regression](#bug-or-regression-1)
    - [Test \& Conformance](#test--conformance-1)
- [v1.6.0-rc.1](#v160-rc1)
  - [Major Changes Since v1.5.1](#major-changes-since-v151)
    - [Breaking Changes](#breaking-changes)
    - [GEP \& API Graduation](#gep--api-graduation)
    - [Feature](#feature)
    - [Documentation](#documentation)
    - [Bug or Regression](#bug-or-regression-2)
    - [Test \& Conformance](#test--conformance-2)
  - [Dependencies](#dependencies)
    - [Added](#added)
    - [Changed](#changed)
    - [Removed](#removed)

# v1.6.3

## Major Changes Since v1.6.2

- Conformance tests for stable features (notable TCPRoute and UDPRoute) are no longer marked as "provisional" (#5260, @rikatz)
- Force the timeout for the `ExpectMirroredRequest` conformance test to `MaxTimeToConsistency` (#5296, @kl52752)
- _Actually_ remove unused namespaces in Mesh conformance tests (#5251, @xtineskim)
- Add the `GatewayInvalidParametersRef` conformance test (#5236, @kl52752)
- Ensure the Go toolchain matches `go.work` (#5234, @snorwin)

# v1.6.2

## Major Changes Since v1.6.1

### Bug or Regression

- HTTPRequestRedirectFilter status codes 303, 307, and 308 are Extended conformance, not Core. (#5173, @kflynn)

### Other (Cleanup or Flake)

- Fix flaky `TCPRouteWeightedRouting` and `UDPRouteWeightedRouting` conformance tests by adding a data-plane readiness check before performing weighted routing assertions. (#5064, @arybolovlev)
- Fix `FailFast` not working as expected (#5204, @zirain)
- Allow disabling parallel tests at the suite level (#5184, @zirain)

