### Changed

- A published `crd-version-removal` rule whose only change is the advice text (`nextAction`) can now be renewed by `extract apply --renew-attestations`, for the rules on a fixed pending list and only when the extractor release version rises and the rule and its pinned sources are otherwise unchanged. The renewal is reported as `remediation-text` with the advice before and after; `knowledge-gate` marks a changed `nextAction` with the kind `remediation-text`. A test now requires published advice to match the extractor output.
