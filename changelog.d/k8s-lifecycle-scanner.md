### Added

- Add an inert scanner for Kubernetes API lifecycle markers: it reads the introduced, deprecated and removed release markers of each API type from a pinned source tree (mechanical only when all three parse cleanly, appear once and are ordered), and lists field and type deprecations as drafts that need review. Nothing calls it yet.
