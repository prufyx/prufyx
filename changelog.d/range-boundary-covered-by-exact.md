### Added

- Rule documents can opt in, by schema, to a contract in which a ranged rule's "release boundary not reviewed" answer for a hop is replaced when an exact reviewed rule decides the same check on the exact declared pair. The ranged claim stays UNKNOWN with the new reason `RULE_BOUNDARY_COVERED_BY_EXACT_RULE` and names the covering rule; the covering rule alone carries the verdict. Documents on earlier schemas replay byte for byte and keep the previous answer. No shipped rule document uses the new schema yet.
