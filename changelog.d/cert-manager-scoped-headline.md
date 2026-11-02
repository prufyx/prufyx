### Changed

- `prufyx check cert-manager-values` and the Prometheus agent-mode check now print `PASS (scoped)` like the other check routes, and the cert-manager route adds `Whole upgrade: not proven.` under a PASS headline (it was a bare `PASS` with the scope only ten lines below).
