### Added

- An upgrade through several minor lines of a project whose change lists are in the knowledge now prints the per-hop table too: a hop with a valid, current change-list record shows ATTENTION and cites each release's change list (source, commit, digest, line span), a hop without one is undecided and says why, and no hop is ever a pass. The verdict and the exit code are unchanged. Nothing is shown until the knowledge carries change-list records.
