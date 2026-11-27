### Fixed

- The coverage report no longer counts a rule about a Helm chart line as deciding an upgrade between release lines of the project (A, B or S, or a complete-project pair) when the chart version numbers equal those lines. An attestation that lists such a rule decides nothing. Such a rule is also left out of the count of rules in a project's window.
