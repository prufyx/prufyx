### Changed

- The evidence renewal workflow now opens its statement pull requests with a fine-grained token of the pinned knowledge bot account (`KNOWLEDGE_BOT_TOKEN`) instead of a GitHub App token, so the knowledge gate sees them as authored by `KNOWLEDGE_BOT_LOGIN`. The `pr` job refuses to write anything unless the token's login equals that variable.
- The pull request is authored by the bot account and merged through the normal merge train after the Knowledge gate; it is not auto-merged.
