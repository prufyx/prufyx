### Changed

- The GitHub Action input `fail-on` now defaults to `blocked,unknown` (was `blocked`): a scan that is UNKNOWN (exit 11, not every area checked) now fails the step, so a green step means the scan passed. To keep the old behaviour (UNKNOWN stays green with a warning, which is not a pass), set `fail-on: blocked`.
