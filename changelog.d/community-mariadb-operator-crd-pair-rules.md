### Added

- `prufyx check project --project mariadb-operator` now also checks two exact release pairs, `0.38.1` to `25.0.0` and `25.8.4` to `25.10.4`, against nine reviewed MariaDB CRD field rules (one retyped field and eight removed fields). A complete caller-selected MariaDB resource that still sets a removed or retyped key is blocked; each rule cites the CRD and API source lines at both release tags. The rules cover only those keys of the MariaDB kind, never other kinds, Helm values, flags, migration steps or whole-upgrade safety.
