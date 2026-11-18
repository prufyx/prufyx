### Changed

- The generated release notes of a release that is not tagged yet name the described tree by the sha256 of its coverage counts file instead of a commit id, so a rebase no longer invalidates them; `release-docs check` still refuses hand edits and counts that changed without regeneration. `release-notes --bind-counts` produces that label.
