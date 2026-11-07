# Provider excerpts

Anchored excerpts of official vendor lifecycle pages, committed so a
knowledge row can cite them as ordinary git evidence. One file per anchor at
`<provider>/<anchor>.txt`, listed in `manifest.json`.

- An excerpt is a table row set or one sentence, at most 8 KiB. Never a whole
  page.
- Verbatim text only where the licence class is `permissive-quote`. Where the
  terms are unknown (`unknown-paraphrase`) the file holds a paraphrase and the
  sentence id; no quotation.
- Source URLs are https, on an allowlisted official host, without query or
  fragment. No cookies, credentials or tracking identifiers.
- A row cites the commit that contains the excerpt (`constraintengine`
  `SourceEvidence`: revision, whole-file sha256, line span within the body,
  immutable github.com URL under this directory). The manifest `sha256` is the
  whole-file digest, so the unchanged source validator accepts it and the
  knowledge gate can re-derive it offline.

Validator: `cli/internal/maintainer/providerexcerpt`.
