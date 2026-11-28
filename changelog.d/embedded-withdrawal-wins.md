### Security

- A local knowledge database can no longer re-activate a rule that the binary holds as withdrawn: unless the database rule has a strictly later evidence review date, `check cncf`, `check batch` and `scan` evaluate it as withdrawn (`UNKNOWN`, `RULE_EVIDENCE_WITHDRAWN`). Restoring a withdrawn rule needs a new review date. A report that an earlier build made from such a rule does not replay on this build (knowledge integrity failure).
