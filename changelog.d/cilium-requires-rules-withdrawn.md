### Fixed

- The Cilium rules about nonempty fromRequires and toRequires lists for 1.18.6 to 1.19.0 and 1.18.13 to 1.19.7 are withdrawn. The upstream upgrade guide says to update to the latest patch release of the current version before attempting an upgrade, and neither origin is that release, so the scoped PASS these rules gave was incomplete. Those transitions now report UNKNOWN, including the case they used to report as blocked.
