### Fixed

- A pinned `--now` no longer hides knowledge that has expired in real time: `scan`, `plan`, `check cncf`, `check project` and `check batch` print a warning (pinned time, today, expired rule count), and a result that would PASS at the pinned time but is not a PASS at the real time is reported as that real-time result (UNKNOWN, exit 11), not as PASS. Replays and runs without `--now` are unchanged.
