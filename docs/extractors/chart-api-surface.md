# Chart API-surface reader (measurement mode)

`prufyx-maintainer chart-api-surface` answers one question from pinned archive
bytes: which `(apiVersion, kind)` pairs can this chart release produce under
any values? It is a measurement. It writes no rule, no attestation, no trust
output and no verdict.

```
prufyx-maintainer chart-api-surface --chart ARCHIVE.tgz --out LEDGER.json \
  [--served-apis SERVED.json --lines 1.24,1.25] [--oracle-cmd /abs/path]
```

## What is listed

Every pair comes with its file and line, and a `conditional` flag (inside an
if, with or range, a helper, a conditional dependency, or a value choice).
Plain YAML under `crds/` is listed unconditionally. Besides literal fields, a
version or kind built from a template is listed only when it is a finite set,
in one of three closed groups:

- `capability_switch`: a helper or inline choice that branches on cluster
  capabilities and prints constants;
- `library_helper`: a helper defined in a subchart present in the archive, or
  an inline choice between constants (`inline_choice`);
- `templated_kind_set`: a kind chosen between constants.

## What is withheld (typed codes)

A chart with any code is `withheld`; the pairs found are still listed.

| Code | Meaning |
|---|---|
| `version_or_kind_built` | built by printf or another string function |
| `version_or_kind_variable` / `_user_value` / `_expression` | a variable, a user value, or any other expression |
| `version_or_kind_invalid` | not a valid apiVersion or kind, or empty |
| `lookup_feeds_version_or_kind` | the value comes from a lookup |
| `objects_from_files_or_tpl` | whole objects from chart files or rendered from strings, or an empty scan in a chart that reads files |
| `empty_scan` | templates exist and nothing was listed: an empty scan is never complete |
| `dependency_missing` | a declared dependency is not in the archive |
| `library_helper_not_found`, `helper_ambiguous` | the helper is absent or defined twice differently |
| `template_depth_exceeded`, `value_set_too_large`, `too_many_entries` | a bound was hit |
| `template_parse_error`, `document_pairing`, `list_kind_items_unscanned` | the text cannot be read as one apiVersion and one kind per document |
| `oracle_unavailable`, `tool_bug_oracle_mismatch` | see below |

An archive that is malformed, has links or unsafe paths, or exceeds a bound
(archive size, unpacked size, file count, nesting) is refused with no ledger.

Not claimed: objects the program creates at run time, hook jobs that call the
API themselves, objects injected through values, custom resources of other
projects.

## Served-API check

With `--served-apis` (a served-list document) and `--lines`, each line gets
`would-block` (an unconditional entry the line does not serve),
`would-pass` (nothing blocks and the chart is complete; unserved conditional
entries are notices) or `withheld` (chart withheld, no list for the line, or a
partial list). Pairs whose group no served list knows are reported as
`not_builtin` and never decided. Freshness of the served list is not judged
here.

## Oracle

The reader has no renderer and adds no dependency. `--oracle-cmd` names an
absolute path the factory provides; it runs without a shell with the archive
path as its only argument and prints an offline render with default values.
Every rendered pair must be in the static set. A miss on a complete chart is
`tool_bug_oracle_mismatch` and withholds it; a requested oracle that cannot
run or whose output is unreadable withholds with `oracle_unavailable`.
