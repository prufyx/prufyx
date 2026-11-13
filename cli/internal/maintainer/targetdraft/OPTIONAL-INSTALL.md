# Optional installPaths entries

An `installPaths` entry of the rules file may carry `optional: true`. It names
one exact definition file (`.yaml`, `.yml` or `.json`, never a directory) that
a project added at some release line, so the oldest tags of the window do not
carry it.

```json
{"path": "deploy/operator/crds.yaml", "reason": "...", "evidence": "...",
 "optional": true, "absentTags": ["v1.0.0", "v1.1.0"]}
```

Rules, all fail-closed:

1. `reason`, `evidence` and a non-empty `absentTags` are required; every absent
   tag must be a plain tag name and a tag of the run (otherwise `bad-input`).
   `absentTags` without `optional: true` is a parse error.
2. At a tag listed in `absentTags` the entry is tolerated only on verified true
   tree absence: the path is absent from the full Git tree of the tag.
3. A file present at a tag that is not listed is read normally. A file present
   at a listed tag is the stop `optional-path-present-at-absent-tag`. A file
   absent at a tag that is not listed is the existing stop
   `install-path-matches-nothing` (the window shrinks past the tag exactly as for
   a mandatory entry).
4. Anything that is not a plain regular file or true absence ends the run:
   `optional-path-link` (symbolic link or submodule entry at the path or at a
   parent directory) and `optional-path-unverifiable` (any read error, a tree
   object that cannot be read, an opaque tree entry, a directory at the path, a
   regular file as a parent directory, a present file that is not a readable
   definition, a tree reader that cannot probe paths, a local-only environment
   that is missing).
5. The newest tag must read the file: absence there is
   `optional-absent-at-newest`, even when the tag is listed.
6. The identical-set check ignores an optional entry only at a tag where its
   absence is verified. A missing mandatory entry still stops that tag, and the
   duplicate-definition checks count the optional file's definitions wherever it
   is read.
7. Without an optional entry nothing changes. With one, `report.json` lists per
   window tag whether each optional entry was `read` or `verified-absent`
   (`optionalPaths`, window order then path) and the facts digest includes it.

## GitSource tree-entry contract

`GitSource` reads local Git only. Every command runs with a fixed environment:
no network protocol (`GIT_ALLOW_PROTOCOL=none`), no lazy fetch of missing
objects (`GIT_NO_LAZY_FETCH=1`), no prompts, no replace objects, no system
configuration. The optional-path probe refuses to run unless that environment is
in place; a partial clone with a missing object therefore fails instead of
fetching.

`GIT_NO_LAZY_FETCH` is honoured by git 2.44 and later only. With an older git
the variable is ignored and only `GIT_ALLOW_PROTOCOL=none` (together with
`HOME=/nonexistent`) stops a fetch of a missing object. No version floor is
enforced, so an older git still works; both variables are always set, and a
test checks that the spawned git receives them.

Two readers exist and they treat tree entries differently.

* `Open` lists the tag with a recursive listing and keeps only regular files
  (mode 100644 and 100755) and symbolic links (120000). It silently skips
  submodule entries (160000) and any blob with another mode. A skipped entry
  is never read as a source file, but its absence from the list is not proof
  that the path is absent. The listing is never used to prove absence.
* The path probe, used only for optional entries, walks the exact path one
  component at a time from the root tree of the commit and lists each tree
  object on the way. It accepts only the four defined kinds: tree (040000),
  regular file (100644, 100755), symbolic link (120000) and submodule (160000).
  It refuses the whole probe on any listed record that is not one of them
  (unknown mode, mode and type that do not match, unparseable record, a name
  that is empty or contains a slash, a duplicate of the wanted name) and on any
  error reading a tree object. Git itself canonicalises odd modes when it lists a
  tree, so in practice the refused shapes are a malformed record or name and
  an unreadable tree object; the check is deliberately stricter than needed.
  Absence is reported only when a name is missing from a successfully read,
  fully understood tree listing. A symbolic link, a submodule or a regular
  file at a parent component, and a link or submodule at the path itself, are
  reported as such and refused by the generator.

Exactly what is refused: a submodule (160000) or a symbolic link (120000) at
the path or at a parent is `optional-path-link`; a directory at the path, a
regular file as a parent, or any unknown mode, type or record is
`optional-path-unverifiable`. The recursive reader `Open` skips submodules and
other blob modes and is never used to prove absence.

The reason for refusing opaque entries: a skipped or misread entry is exactly
how a file can hide behind a "not found". An optional path is tolerated only
when every tree on the way was read completely and none of its records is
unknown.
