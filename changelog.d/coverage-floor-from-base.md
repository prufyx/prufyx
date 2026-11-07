### Changed

- The knowledge gate (the required CI check) and onboarding admission now compare the published decided pairs, covered projects and per-project decided pairs of a change with the coverage baseline of the base branch, and refuse any drop that is not excused by a withdrawal already on the base branch. A withdrawal added in the same change does not count. The QA gate path is not wired yet (follow-up W0b).
