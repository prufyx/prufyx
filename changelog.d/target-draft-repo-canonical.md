### Fixed
- The target draft generator refuses a repository that is not in the canonical lower-case form the extractor's target loader requires (typed stop repo-not-canonical), before writing anything.
- It also refuses a component that is not pkg:github/<owner>/<name> of that repository (component-not-canonical) and an upstream block the table loader would refuse, including one on a CNCF row (upstream-not-canonical), before writing anything.
