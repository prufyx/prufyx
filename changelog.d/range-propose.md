### Added

- `prufyx-maintainer range-propose` compares the cited source spans of exact-pair rules at every release tag of local bare clones and writes unreviewed candidate ranges, plus a list of rules that need review or were refused. The check is span-stable only: behaviour, a later reintroduction and the effect on decisions are not checked. It uses no network and changes no rule pack.
