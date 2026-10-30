# Agent instructions for prufyx/prufyx

Prufyx checks a planned Kubernetes or CNCF-project upgrade against your own configuration and answers PASS, BLOCKED or UNKNOWN, citing the upstream commit, file and line range behind every rule. The CLI is in `cli/` (Go), the shipped knowledge in `cli/internal/cncfcheck/data/` and related packages, docs in `cli/docs/` and `docs/`.

Rules for every change:
1. A wrong PASS is the worst bug. A missing proof is UNKNOWN, never PASS. Never loosen a check, guard or exclusion to raise coverage.
2. Knowledge data changes only through reviewed pull requests that pass the Knowledge gate; generated files (README coverage block, inventories, release-notes blocks) are regenerated with their scripts, never edited by hand (`scripts/readme-coverage.sh`).
3. Every user-visible change updates README / `cli/docs` in the same pull request and adds a changelog fragment `changelog.d/<slug>.md` (see `changelog.d/README.md`). Never edit `CHANGELOG.md` directly.
4. Docs, README and release notes must be true: check each sentence against the code and the generated data.
5. Tests: `cd cli && go test ./...`. CI also runs selected packages with `-race` (see the race jobs in `.github/workflows/ci.yml`) and staticcheck; match `ci.yml` before pushing Go changes.
6. Changes to the knowledge gate (`cli/internal/maintainer/knowledgegate`), signing, the knowledge feed/trust root, extractor guards or release/publish workflows need an independent review of the design and of the final diff.
7. One change per branch and pull request; merge commits only; a pull request merges only when CI is green on its exact head and it is up to date with `main`.
8. No secrets or key-shaped values in code, tests or docs. No AI attribution in commits or pull requests.
