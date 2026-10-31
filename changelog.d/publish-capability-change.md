### Fixed

- The knowledge publish workflow can publish across an engine capability change (a project added to the supported table, a fact registered, an engine change): the previous package is verified by the client of the commit that produced it, and the release continues the revision and TUF version with the first-release layout. Before, no publish could succeed after such a change.
- A feed built for another engine capability than the client is reported as `KNOWLEDGE_CAPABILITY_MISMATCH` (exit `15`) instead of "a newer prufyx is needed". `db update` follows the feed only while its capability equals the client's; the embedded knowledge keeps working.
