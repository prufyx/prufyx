### Added

- `crd.version-removal` reads release tags with a zero-padded minor (`v26.02.0`, `v26.06.2`) for projects of major 20 or more, as the release 26.2.0 and the line 26.2. A padded minor below major 20 (`v1.02.3`), a zero minor with a leading zero (`v20.00.0`) and any further zero padding (`v20.010.1`, `v26.02.00`) are still no release. A line with both a padded and a canonical tag (`v26.02.0` and `v26.2.0`) is ambiguous and is withheld.
