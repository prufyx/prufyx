# Version-ranged installPaths entries

A source can move over time (a project relocates its definition directory at
some release line). An `installPaths` entry of the rules file may therefore
carry a `role` and a tag range. Ranges are a generator-side selection and
check only: the emitted target lists the union of the paths read and its
format is unchanged.

```json
{"path": "config/crd/bases/", "reason": "...", "evidence": "...",
 "role": "core-crds", "toTag": "v1.13.8"},
{"path": "core/config/crd/bases/", "reason": "...", "evidence": "...",
 "role": "core-crds", "fromTag": "v1.14.4"}
```

Rules, all fail-closed:

1. `fromTag` and `toTag` are inclusive tags of the run (`--tags`). An omitted
   bound is the edge of the window (oldest or newest tag). A role needs at
   least one bound; a bound needs a role. A range never combines with
   `optional`/`absentTags` (parse error `range-with-optional`). All entries of
   a role are directories, or all exact files.
2. Entries sharing a role are the same logical source. Their ranges must be
   disjoint and contiguous and together cover the whole run exactly:
   `range-overlap`, `range-gap`, `range-not-covering-window` (uncovered tags
   are never dropped silently). A bound that is not a tag of the run, or a
   `fromTag` after its `toTag`, is `bad-input`.
3. Inside its range an entry is mandatory: the path absent from the full tree
   of the tag, or present with no definition file, is `range-path-absent-in-range`.
4. Outside its range the path must be absent from the full tree:
   `range-path-present-out-of-range` (the evidence that the directory moved is
   wrong). This is the boundary check.
5. Anything not provable (read error, symbolic link or submodule at the path or
   a parent, a directory where a file is expected, a tree reader that cannot
   probe, a git environment without `GIT_NO_LAZY_FETCH=1`, `GIT_ALLOW_PROTOCOL=none`)
   is `range-path-unverifiable`. These stops end the run whatever the tag; they
   never shrink the window.
6. The identical-set check keys a file under a ranged entry by role and the path
   relative to the entry, so the same logical file before and after the move is
   one key; a renamed file inside a role still differs.
7. A `pathFilter` whose glob lies only under ranged entries applies only at tags
   where one of them is inside its range; `expectFiles` stays an exact count per
   tag where the filter applies. A filter never removes an exact-file ranged entry.
8. `report.json` lists per window tag the selected entry of each role
   (`rangedPaths`: tag, role, path; window order, then role, then path) and the
   facts digest covers it. Without ranged entries nothing changes and every
   digest is as before.

## `--range-check-tags`

The run reads one final tag per line, so a move in the middle of a line is
invisible to it. `--range-check-tags TAG[,TAG...]` lists ALL tags of the lines
of the run; each is probed (never classified) with the same presence-inside,
absence-outside rule, using the line's range. It reads local Git only, with the
same environment contract as optional entries. A tag that is not `<prefix>X.Y.Z`
of the run's prefix, belongs to no line of the run, is listed twice or is not
readable is a stop; the option without ranged entries is `bad-input`. The checked
tags are listed in `report.json` (`rangeCheckedTags`) and in the facts digest.
Without the option the documented single-tag view is all that is checked.

## What stays a hand edit

The emitted target carries plain file paths. A file that does not exist at the
oldest tags of the window cannot be marked optional in the generated target; a
reviewed target that must tolerate the move still needs that mark added by hand
(or an extractor feature), and `--compare-a`/`--compare-b` will name it.
