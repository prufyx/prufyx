### Documentation

- Known limitation for `prufyx db status`: a database that this build cannot read (too new, or built for another engine capability) is reported as `INTEGRITY_FAILURE` (exit `3`), the same as a tampered one. `scan` and `check cncf --knowledge-db` tell them apart (exit `15` too new, exit `3` integrity failure). A distinct `db status` state is planned for beta.1.
