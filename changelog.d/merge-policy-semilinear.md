### Changed

- The `Merge policy` check now refuses pull requests that contain merge commits or whose branch is not on the current `main` tip; update a branch with `git rebase origin/main`, never by merging `main` into it.
