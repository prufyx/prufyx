### Added (workflows)

- A scheduled workflow signs a new timestamp over the live, unchanged knowledge package with the timestamp key alone, so the feed stays valid when a content release is late; it alarms when a release has waited for approval for more than 48 hours or the targets and snapshot expire in under 5 days. Inactive until the environment `knowledge-refresh` exists.
