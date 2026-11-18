### Added

- A rule whose claim is a fixed from-to transition cited at immutable commits can hold a pinned lease (`evidence.lease: "pinned"`) and then no longer turns `UNKNOWN` when its review window ends; its freshness reads `pinned`. A pinned lease is set only by a signed human reattestation statement (`evidence reattest prepare --pin`), is checked by the knowledge gate, and is kept honest by `evidence repin --pinned-only`, which exits non-zero when a pinned citation drifts on its release line. `knowledge_age` counts pinned rules in their own bucket instead of as an expiry.
