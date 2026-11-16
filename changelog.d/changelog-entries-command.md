### Added

- `prufyx-maintainer changelog entries`: for one reviewed component and one release tag it reads the changelog entry through the offline mirror (or a fixture tree) and prints a deterministic manifest: the entry (source, section span and digest, structure, one digested item per list item or paragraph) or the typed reason the tag is withheld. It makes no classification and no disposition, reads no network, writes no file, and refuses unknown or repeated flags. The reviewed target table is empty, so every component is refused until a row is reviewed.
