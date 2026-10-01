# Community support inventory

[`generated/community-support-inventory.json`](generated/community-support-inventory.json)
is the canonical, generated inventory for the executable Community CLI surface
and separately retained selected public-source references. The companion
[Markdown view](generated/community-support-inventory.md) is generated from the
same inputs for GitHub readers.

The inventory distinguishes embedded CNCF source rules, named local checks,
standards-conformance profiles, target-only planned-operation preflights, and
selected-source-only records. Conformance and target-only profiles have no
invented version transition. It is a curated Community contribution and
reproducibility artifact in the current release policy. A selected source record is
**reference-only** and **license-unreviewed**. It does not establish
executable support, source authenticity, license clearance, compatibility, or
runtime proof. Neither a scoped check result nor this inventory establishes a
whole upgrade as safe.

Generate from a clean checkout:

```sh
go run ./cli/cmd/prufyx-maintainer support-inventory \
  --selected-source-manifest cli/docs/data/selected-source-records-v1.json \
  --json-output cli/docs/generated/community-support-inventory.json \
  --markdown-output cli/docs/generated/community-support-inventory.md
go run ./cli/cmd/prufyx-maintainer support-inventory \
  --selected-source-manifest cli/docs/data/selected-source-records-v1.json \
  --json-output cli/docs/generated/community-support-inventory.json \
  --markdown-output cli/docs/generated/community-support-inventory.md --check
```

Maintainers refresh `data/selected-source-records-v1.json` only from a
separately reviewed private reference collection. The importer accepts an
allowlisted, normalized subset of that collection and rejects raw source bytes,
excerpts, local capture paths, review receipts, timestamps, and unknown fields.
The committed manifest records the reviewed collection-index digest; inventory
freshness is derived from normalized committed inputs rather than the current
Git revision or clock.

```sh
go run ./cli/cmd/prufyx-maintainer selected-source-import \
  --corpus-root <private-reviewed-corpus-root> \
  --collection-index <private-reviewed-collection-index.json> \
  --expected-index-digest sha256:63a2c5a0c34dd03d6d0ad23796895afdb3c765e47f5027cf6b36a55f9ec2ba2d \
  --output cli/docs/data/selected-source-records-v1.json --check
```

The importer is a maintainer refresh step, not a network collector. It must not
be used to promote the retained source corpus into executable support.
