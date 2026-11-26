### Changed

- A rule pack can declare pack level `v1alpha16` to use the boundary-covered contract, and per-project external targets keep it while their rules hold a range. A rule merge or a served-list build never declares it.
- While a pack is at that level, the knowledge gate fails any change whose oldest supported client pin is missing, unreadable or below the first release that reads the level.
