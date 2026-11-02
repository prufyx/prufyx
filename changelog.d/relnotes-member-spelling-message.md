### Changed

- `prufyx check cncf` on a project with release-note rules (cortex, falco, thanos) now says why it exits 2 when a declared flag name is not spelled as the project spells it (for example `Store.max-look-back-period`): the message names the spelling rule instead of only "check failed". The request is still refused; nothing about the verdict changes.
