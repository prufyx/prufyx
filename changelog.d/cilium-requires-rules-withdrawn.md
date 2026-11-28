### Fixed

- Three Cilium rules are withdrawn: the nonempty fromRequires and toRequires rules for 1.18.6 to 1.19.0 and 1.18.13 to 1.19.7, and the removed CiliumNodeConfig v2alpha1 rule for 1.19.0 to 1.20.0. The upstream upgrade notes say to update to the latest patch release of the current version before attempting an upgrade, and none of these origins is that release, so the answer these rules gave for a direct upgrade was incomplete. Those transitions now report UNKNOWN, including the cases they used to report as blocked.
