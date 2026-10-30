### Fixed

- The README no longer says every shipped rule was reviewed by a person. The sentence on how rules were established and the sentence on when they stop being valid are now generated from the rule packs (counts per evidence basis, earliest and latest `validUntil`), and `scripts/readme-coverage.sh --check` fails when they drift.
- `SOURCE-PREVIEW.json` no longer repeats the executable-project and source counts or the inventory digest of the generated support inventory; a test keeps those figures out of it.
