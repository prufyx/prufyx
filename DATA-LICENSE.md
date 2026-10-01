# Prufyx knowledge data license

The Prufyx source code is licensed under the GNU Affero General Public License,
version 3 only ([LICENSE](LICENSE)). The reviewed compatibility knowledge that
the code evaluates is licensed separately, under the
[Creative Commons Attribution-ShareAlike 4.0 International](LICENSES/CC-BY-SA-4.0.txt)
license (CC BY-SA 4.0).

## What this license covers

The following files, in this repository and in any knowledge package, database
update, or offline bundle published from it, are Prufyx knowledge data:

- `cli/internal/*/data/*.json`, except `cli/internal/cncfcheck/data/landscape-projects.json`;
- `cli/contrib/rules/*.json`;
- `cli/docs/data/*.json` and `cli/docs/generated/*`;
- signed knowledge packages and database exports produced by `prufyx-maintainer`.

This covers the rules, their predicates, reason codes, descriptions, evidence
records, review dates, attestations, and the selection and arrangement of the
corpus as a whole.

## What it does not cover

- **Upstream excerpts and references.** Rules cite upstream projects by URL,
  commit, path, line range, and digest, and may quote short spans of upstream
  source or documentation. Quoted upstream material keeps its original license;
  CC BY-SA 4.0 applies only to the Prufyx contribution around it.
- **`cli/internal/cncfcheck/data/landscape-projects.json`.** Derived from
  [cncf/landscape](https://github.com/cncf/landscape) and distributed under that
  project's Apache-2.0 license.
- **Third-party files** listed in [THIRD-PARTY.md](THIRD-PARTY.md).
- **Names and marks.** Neither license grants rights to the Prufyx name or to
  upstream project names and trademarks.

## Attribution

When you share Prufyx knowledge data or material adapted from it, credit it as:

> Prufyx knowledge data, © 2026 Spas Atanasov and Prufyx contributors,
> CC BY-SA 4.0, https://github.com/prufyx/prufyx

and keep the per-rule source citations intact. Adapted data must be shared
under CC BY-SA 4.0 or a compatible license.

## Data embedded in binaries

Prufyx binaries embed the knowledge data as a separate data file read at run
time. The binary as a whole is distributed under the AGPL-3.0-only license; the
embedded data remains under CC BY-SA 4.0 and can be extracted and reused under
that license.
