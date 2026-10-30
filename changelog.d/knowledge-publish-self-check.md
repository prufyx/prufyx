### Added (workflows)

- A daily `Knowledge publish self-check` workflow fetches the live knowledge feed, verifies it with the pinned root and opens one tracking issue when the feed is older than 8 days, its timestamp expires in under 5 days, the last successful `Knowledge publish` run is older than 8 days, or the feed is older than the newest knowledge merge. The weekly `Knowledge publish` run now always re-signs, so the timestamp expiry moves every week. See `cli/docs/knowledge-publisher.md`.
