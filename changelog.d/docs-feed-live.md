### Documentation

- Docs now say the official knowledge feed is published and its trust root is pinned in the build: `prufyx db update` with no flags fetches the signed feed; embedded knowledge still works offline. The build identity trust root stays `UNPINNED`.
- The knowledge age note and the `NO_SELECTION` next action no longer say that no official update or feed exists. They point to `prufyx db update`.
