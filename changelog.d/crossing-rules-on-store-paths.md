### Security

- Removal-crossing rules are embedded-only (a feed or store never carries them), but `check cncf`, `check batch`, auto knowledge selection and `scan` evaluated a selected local store without them, so a hop the embedded rules block (exit 10) could pass (exit 0) or turn UNKNOWN. Every store evaluation now includes the project's embedded crossing rules; a block stays a block. A store rule with the id of an embedded crossing rule is refused as an integrity failure on every path, as `scan` already did.
