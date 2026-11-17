### Documentation

- The changelog entry reader now withholds the whole file, for every tag, when its reading of the headings, fenced code, HTML blocks or list items disagrees anywhere with an independent CommonMark parser, when a release heading is nested inside a list item or quote, or when a block crosses the section boundary. The conditions are listed in `docs/extractors/changelog.entries.md`.
