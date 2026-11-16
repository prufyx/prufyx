# Generator backtest (report only)

`prufyx-maintainer target-draft backtest --manifest FILE --mirrors DIR --out DIR`

The backtest asks one question: does the draft generator, run offline on a
pinned local mirror, reproduce a reviewed target file byte for byte? It only
reports. It never fetches, never writes a target, and is not a merge gate.

## Manifest

`testdata/backtest-manifest.json` shows the shape (strict JSON, unknown
fields refused). `count` must equal the number of entries; shrinking it is a
manifest edit, never a flag. Each entry names a slug, tags, a mirror directory
name below `--mirrors`, an optional rules file, the reviewed target file
(`expected`) and the half to compare (`A` or `B`). Paths are relative to the
manifest directory and must stay inside it. A missing mirror is the typed stop
`mirror-missing`, never a skip.

Optional entry fields map to the generator flags of the same names and default
to off: `multiPrefix` (`--multi-prefix`), `collapseDirectories`
(`--collapse-directories`), `deriveDuplicateSources`
(`--derive-duplicate-sources`). `oraclePaths` copies the reviewed target's
paths into `installPaths` (a directory entry as `dir/`); it is refused when the
entry's rules file already carries `installPaths` or `installSurface`.

`inferInstallPaths` (`--infer-install-paths`) lets the generator derive the
install directory itself; `checkInstallPathCopies`
(`--check-install-path-copies`) checks every definition file outside the
install paths (it needs installPaths, an `oraclePaths` run, or
`inferInstallPaths`; otherwise the generator stops). `inferInstallPaths` is a
harness error when the entry's rules file carries `installPaths`,
`installSurface`, `pathFilter` or exclusions, or when `oraclePaths` is also set
(the generator refuses inference with exclusions). An inference run is a
normal result: inference is a recipe, not an oracle, so `reproduced` counts in
`strict`, and `install-path-ambiguous`, `install-path-hides-crd` and
`install-path-copy-differs` are `typed-stop` entries (listed in `stops`, counted
in `stops=`). Seeds run on a reproduced inference entry like any other.

`escalate` (default off) makes the entry stop-driven: it runs first without
inference (the entry's own flags, for example `collapseDirectories`,
`deriveDuplicateSources`, `multiPrefix`, `checkInstallPathCopies`). Any result
of that plain run other than a listed stop (`reproduced`, `differs`, another
typed stop, ...) is the entry result with `escalated: false`. Only when the plain
run ends in typed stops that are all in the escalation list (`escalateStops` in
`backtest.go`: `duplicate-crd`, `duplicate-crd-differs`, `unreadable-shape`,
`unpinned-exclusion`) does the harness run the entry again with
`inferInstallPaths` and `checkInstallPathCopies`; that second result is the entry
result with `escalated: true` and the plain stop code in `plainStop`. Every other
plain stop (for example `multi-prefix-ambiguous`, `reserved-group`,
`window-too-short`, `mirror-missing`), or a mix with an unlisted code, is the
result as is. `escalate` is a harness error together with `oraclePaths`,
`inferInstallPaths`, or rules that carry `installPaths`, `installSurface`,
`pathFilter` or exclusions. An escalated reproduction counts in `strict` like
any inferred recipe (it is a recipe, not an oracle); seeds run on the final
result only. When at least one entry escalated, the per-entry line gains
` escalated=true plainStop=CODE` and the summary line gains ` escalated=N` after
`digest=`; `backtest.json` gains `escalated` only when N is above 0.

`acceptFactEqualCopies` (`--accept-fact-equal-copies`, default off) needs
`inferInstallPaths` or `checkInstallPathCopies`; it never applies otherwise.
An outside copy whose full-spec digest differs from the installed definition
is accepted only when its fact projection equals the installed one at every
tag of the run: group, kind, the version set (name, served, storage; not
empty), `spec.scope`, `spec.names` and `spec.conversion` (absent on both sides
counts equal; absent against an explicit strategy is a difference). The
apiVersion text and schema-only differences are ignored. Any other difference,
or a digest that cannot be computed, stays `install-path-copy-differs`. The
accepted copies are listed in the facts digest and the changelog; nothing else
changes.

`skipPatchFragments` (`--skip-patch-fragments`, default off) sets aside
kustomize patch fragments as non-install, non-definition files. A fragment is
only a file whose own content has the extractor's patch-fragment shape (strictly
decoded `CustomResourceDefinition` documents of `apiextensions.k8s.io/v1` or
`v1beta1` that carry only `metadata.name`, labels, annotations,
`spec.conversion` and `spec.preserveUnknownFields`; no template syntax, no
JSON-patch list) and that lies below a directory holding a kustomization file.
Fragments are listed per tag in `patchFragments` of the report (part of the
facts digest), never rank and never count as install files. Everything else,
and any fragment reached through a symbolic link, stays the typed stop
`unreadable-shape`. With the option off the output is unchanged.

A reviewed directory entry (keys `path`, `directory`, `match`, `guard` with the
one default match and guard) is compared by bytes, but only reproduces when
the generator also emits it as a directory entry (use `collapseDirectories`);
an emitted exact-file list against a shipped directory entry is `differs`. A
directory entry with another match or guard, or any other key, stays a
`format-gap`.

## Result per project

| class | meaning |
|---|---|
| `reproduced` | generated bytes equal the reviewed file, no reviewed exclusions fed in |
| `reproduced-circular` | equal, but the rules file carried exclusions (reviewed text supplied, not derived); not counted as strict |
| `differs` | `fields` names every differing field; `cause` is `format-gap` (the reviewed file uses fields the generator cannot emit, such as `directory`, `match`, `guard`, `optional`), `window` (only minFrom or tagPrefixes) or `inference` |
| `reproduced-oracle` | equal, with the reviewed target's own paths fed to the generator as `installPaths` (entry field `oraclePaths: true`); it shows only that the generator compiles a given path set deterministically, not that the set can be inferred. Reported apart (`oracle=n`), never in `strict`; it wins over `reproduced-circular` |
| `typed-stop` | the generator refused (`stops` lists the codes); never a pass |
| `harness-error` | unreadable input, unknown stop code, bad path; exit 2 |

Summary line: `BACKTEST strict=a/N reachable=b/M circular=c stops=s differs=d errors=e seeds=k/K-failed digest=...`
`strict` is reproduced over all N entries and is the headline number.
`reachable` removes the format-gap entries from the denominator, so it shows
inference quality apart from the output-format gap.

## Wrong-target seeds

Seeds feed a deliberately wrong reviewed file (`swap` with another entry's
file, `path` flipped, `min-from` off by one, `attest` toggled,
`drop-exclusion`; for an entry with `"multiPrefix": true`: `swap-prefixes`,
`drop-prefix`, `extra-prefix`) to an entry that reproduced. Every seed must be rejected. A
seed that reproduces exits 1; a seed that cannot run (entry did not
reproduce, nothing to flip or drop) exits 2. A green percentage without
`seeds=K/K-failed` means nothing.

## Exit codes and determinism

0 only when all seeds failed and no harness error occurred (the percentage
does not change the exit code); 1 a seed reproduced; 2 usage, I/O, manifest or
harness error. The run is done twice and `backtest.json` must be
byte-identical, otherwise exit 2.
