### Fixed

- `prufyx scan DIR` no longer passes silently over hidden directories (for example `.deploy/`, `.git/`) and regular files without a `.yaml`, `.yml` or `.json` name (for example `manifest`, `*.tpl`). Each is now reported as not read (`DOCUMENTS_NOT_EVALUATED`, omitted reasons `HIDDEN_DIRECTORY_SKIPPED` and `NOT_MANIFEST_NAME`), so a declared-complete scope gives UNKNOWN (exit 11) instead of a false `PASS FOR THE DECLARED SCOPE`. A hidden symlink is now reported like any other symlink. Name the file or directory on the command line to read it.
