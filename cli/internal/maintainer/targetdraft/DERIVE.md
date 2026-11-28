# Derive mode: the rules are computed, not written

Status: implemented, locally verified (unit tests on synthetic trees), library and command line. Not wired into any pipeline job in this repository; the job that calls it is a separate item. Exit 0 is never merge authority.

`prufyx-maintainer target-draft generate ... --derive-rules [--emit-proposals FILE]`

In derive mode the generator takes no rules file (`--rules` is refused) and computes the rules inputs from the tree facts at the tags of the run by fixed literal rules. Nothing in a derived rule is a judgment: every value is a fixed text plus computed values (tag, path, blob id, group list, proof kind). File names, group names and file contents of the upstream tree are data: parsed, compared, never executed, and never copied into a text unless they pass a strict allow-list (otherwise the typed stop `derive-unclean-text`).

Derive mode excludes `--rules`, `--range-check-tags`, the multi-prefix and inference options. It stops with `community-upstream-missing` for a community row. A duplicate definition stays the plain `duplicate-crd` stop (the duplicate derivation is not on main).

## What is derived

| input | rule | otherwise |
|---|---|---|
| install directory | R2 (see `infer.go`, unchanged) at every tag; where a tag has no R2 candidate, R3 | `install-path-ambiguous`, `install-path-unreferenced` |
| exclusions | only a foreign-carrier exclusion, per file, with a positive proof of foreign origin at every tag the file appears in | none written; the generator's own copy check stops (`install-path-hides-crd`, `install-path-copy-differs`) |
| owner-record proposals | reserved or shared groups the install directory defines; a scope that needs the owner | `scope-needs-owner` stop with the candidates |
| older tags | an older tag without definitions in the install directory is withheld by the window logic (`droppedTags`, `window-shortened` with `--strict-window`) | |

Never derived: `installSurface`, `pathFilter`, `optional`, `absentTags`, ranged entries, `upstream`. An absence is never evidence: an older tag with no definitions is withheld, not read as "the definitions were absent" (a pair is never a pass by absence).

## Rule R3 and the literal reference (second evidence)

When R2 has no candidate at a tag, R3 applies: the single directory that holds every non-skipped definition file (skipped segments: the R2 table, any `bundle*`, and the extractor's default-excluded and documentation segments), is not at the repository root, would read no deeper or skipped file, and is installed by a literal same-tag reference from OUTSIDE the directory that covers every definition file in it. References come from `ReadTreeRefs` (`treeref.go`), a pure function of the tree listing and a bounded reader, meant to be shared with any other reader of install surface facts:

- a kustomization's `resources:` and `bases:` string entries, normalised against the kustomization directory; a chart's `crds/` directory next to its `Chart.yaml`;
- no templating, no `:` (scheme), `$`, `{`, `*`, `~`, space or backslash, no absolute path, no `..` that leaves the tree, never through a link, never from a documentation, test, example, vendor, template or bundle directory, and only entries that name an existing path of the same tag;
- a reference to a directory covers nothing by itself; a file is covered only when a reference names it (or it sits directly in a chart `crds/` directory).

Several directories, a different directory at some tag, or a directory present at some tags only is `install-path-ambiguous`.

## Scope that needs the owner

Before any install rule runs, the scope trigger is checked at every tag: two candidate directories whose group sets are disjoint, or component-prefixed tags (a tag prefix other than none and `v`). Either is the stop `scope-needs-owner` and overrides R2 and R3: an operator-shaped tree is never auto-selected. The proposal lists the enumerated candidates (directory, groups, files with tag, path and blob id). A signed owner decision becomes owner-authored input (a hand-written rules file), not job output.

## Foreign-carrier exclusions

A definition file outside the install directory gets an exact-file exclusion only when all of these hold at every tag it appears in, and it is present at the newest tag:

1. it sits below a skipped segment (and every link that reaches it does too);
2. none of its groups is defined in any non-skipped file of the run (so never a group the install directory defines);
3. its path and groups are on the allow-list;
4. a positive proof of foreign origin: every definition (group and kind) is listed by exactly one OTHER project of the ownership table (`owner-listed`), or the file sits below `vendor` or `third_party` and its module origin (nearest `go.mod`, else the `vendor/modules.txt` line) is a module path that is neither the repository nor below it (`module`).

A group that is merely absent from the install paths proves nothing: an own definition that lives only in a bundle, olm or templates directory is never excluded. Evidence lists, per tag, the blob id, groups, segment and proof; there is no glob. Each exclusion is reported in the report block `derivedRules.loosening` and the proposals file, and in the changelog.

## Output and verification

- `rules.json` (canonical) is written next to the draft. The recipe says `"deriveRules": true`.
- `verify-pr` and the onboarding verifier (built from the base branch) re-run derive mode on the facts bundle and require `rules.json` to be byte-equal (`rules-derivation-differs`). A hand-written or hand-edited rules file is still refused: without `deriveRules` any exclusion is `exclusion-present`; with it, only the derivation's own output passes.
- The report block `derivedRules` (version, tables digest, idempotence key, rules digest, install path and rule, per-tag evidence, loosening) is part of the facts digest and compared byte for byte.
- The signed onboarding admission already binds the unsigned head commit and the blob digest of every changed file including `rules.json`; a lease refresh changes the head and invalidates the signature.

## Idempotence key

`DeriveKey(Input)` / `derivedRules.key`: the derivation version, the digest of the skipped-segment tables, file-name tables and fixed texts (constants of this code, hashed so a table edit changes the key even when nothing else does), the digest of the ownership table and reserved records, slug, repository, the strict-window flag, and every window tag with its commit id (a force-moved tag changes it). Equal key means equal input: no run is needed.

## Owner proposals

`--emit-proposals FILE` writes `prufyx.io/target-derive-proposals/v1` (also on a typed stop): `loosening` (every exclusion with its evidence, to be listed first in a signature packet) and `proposals` of kind `reserved-group`, `shared-group` or `scope-needs-owner` (`status` is always `proposed`; slug, repository, defining files per tag with blob id, install path or copy). A proposal is never a record: only the owner signs one.

## Typed stops added

`scope-needs-owner`, `install-path-unreferenced`, `derive-unclean-text`; every other stop is the generator's own.
