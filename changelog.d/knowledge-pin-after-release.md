### Added (workflows)

- The knowledge publish workflow refuses to advertise a new oldest-supported-client pin unless it names a published, immutable release whose tag points to the pinned commit on main and whose checksum file is attested by the release workflow; a lower pin than the last published one needs an explicit owner input. A client that cannot read the feed now also prints the release page.
