### Fixed

- `prufyx-maintainer project init`/`sync` now selects the newest releases by version instead of the first releases in GitHub's list order: backports on older lines no longer displace the newest line, and projects with more than 30 releases no longer miss the newest ones. The release list is read in bounded pages (up to 10 x 100), non-semver tags are skipped and counted in the snapshot window, and sync fails with RELEASE_LIST_CAP_REACHED when the cap ends the read before enough versions are found. Snapshots taken with the old window selection still verify.
