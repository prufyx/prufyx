## main / (unreleased)

## 0.34.0 / 2026-08-16

* [CHANGE] notify: The `reason` label on `alertmanager_notifications_failed_total` now distinguishes `authError` (HTTP 401/403) and `rateLimited` (HTTP 429) from the generic `clientError`. Dashboards/alerts matching `reason="clientError"` for these codes must be updated. #5332
* [FEATURE] Add optional templatable labels to alert routes. #5328
* [FEATURE] eventrecorder: Add inhibit rule names to `inhibition_muted_alert` events. #5315
* [FEATURE] eventrecorder: Add stdout output type. #5311
* [FEATURE] silences: Add active, expired, and pending boolean filter parameters to GET /api/v2/silences to allow filtering silences by state server-side. #5406
* [FEATURE] sns: Add aws `external_id` support in sigv4 configuration. #5157
* [FEATURE] template: Add `toDate` and `mustToDate` functions. #5327
* [ENHANCEMENT] doc: Add AlertmanagerClusterFailedPeers alertmanager-mixin. #5301
* [ENHANCEMENT] doc: Add description for Rocketchat parameters in global config. #5181
* [ENHANCEMENT] doc: Add top level tracing configuration key. #5314
* [ENHANCEMENT] doc: Fix Alertmanager port in amtool config routes example. #5312
* [ENHANCEMENT] eventrecorder: Add optional webhook batching. #5392
* [ENHANCEMENT] notify: The discord and webex integrations now report a failure `reason` on `alertmanager_notifications_failed_total`. #5332
* [ENHANCEMENT] ui: Improve responsiveness of UI when loading thousands of alerts. #5357
* [BUGFIX] eventrecorder: Fixed a minor performance regression when the event recorder is enabled. #5307
* [BUGFIX] msteamsv2: Inherit global `proxy_url` into partial `http_config`. #5379
* [BUGFIX] webhook: Keep custom `payload` string values verbatim instead of reinterpreting JSON leaves that look like YAML (e.g. values ending with a colon). #5304

## 0.33.1 / 2026-07-04

* [BUGFIX] doc: fix missing `notification_reason` field in webhook documentation (#5329)
* [BUGFIX] silences: fix silences snapshot missing legacy matchers field. This caused a bug that prevented older alertmanager versions from reading newer snapshots unnecessarily. (#5330)
* [BUGFIX] silence with no matchers should populate an empty array in API response (#5331)

## 0.32.3 / 2026-07-04

* [BUGFIX] doc: fix missing `notification_reason` field in webhook documentation (#5329)
* [BUGFIX] silences: fix silences snapshot missing legacy matchers field. This caused a bug that prevented older alertmanager versions from reading newer snapshots unnecessarily. (#5330)
* [BUGFIX] silence with no matchers should populate an empty array in API response (#5331)

