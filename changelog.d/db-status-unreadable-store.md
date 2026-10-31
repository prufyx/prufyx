### Documentation

- Known limitation for `prufyx db status`: a database that this build cannot read (too new, or built for another engine capability) is reported as `INTEGRITY_FAILURE` (exit `3`) although it is intact; `scan` and `check cncf --knowledge-db` report the real reason with exit `15`. A distinct `db status` state is planned for beta.1.
