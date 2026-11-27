### Fixed

- A check of a version pair inside a ranged rule's range now also reports every rule reviewed at a pair inside that range that does not match the declared pair, as `UNKNOWN` (`RULE_TRANSITION_NOT_REVIEWED`), and names it in the claim and in the human output. Before, such a rule was left out of the report. Affected published cases: `crossplane.composition-resources-mode-removed.1-20-2-0` and `strimzi.kafka-v1beta2-api-removed.1-0` at pairs other than the one reviewed. A result can only become more cautious.
