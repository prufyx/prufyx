### Security

- A local knowledge database can no longer undo a withdrawn record in `scan`: an upgrade-path policy the binary holds as withdrawn stays withdrawn, also when the database has no record, unless the database record has a strictly later evidence review date. The same rule drops a line attestation or served-API list that a build lists as removed; this build lists none.
- The knowledge gate refuses a change that moves the evidence review date of a withdrawn rule earlier, with or without an approval.
