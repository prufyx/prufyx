### Changed

- `extract apply --renew-attestations` now also renews a mechanical rule derived again by the same extractor build when only its times move: sources, content and `evidence.lease` are unchanged, `derivedAt` is later than the stored one and not more than five minutes ahead of the clock, `reviewedAt` equals it, and `validUntil` is later than the stored one and at most 90 days after `derivedAt`. Anything else is still refused.
