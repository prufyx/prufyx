### Fixed

- A rule about a Helm chart line is no longer treated as covering a release line of the project in line attestations, even when the chart version numbers equal that line. An attestation that lists such a rule is refused, and the line cannot be attested while the pack holds the rule in that line and family. The coverage report documentation now describes how chart rules are counted.
