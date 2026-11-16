### Added

- A deterministic classifier for changelog entry items (inert library): from the reviewed vocabulary of a target and a closed trigger lexicon it labels every item either needs-review or mechanical-neutral. Anything that is not provably plain by a closed pattern is needs-review. It never emits a rule, never drops an item, and is not wired into any command.
