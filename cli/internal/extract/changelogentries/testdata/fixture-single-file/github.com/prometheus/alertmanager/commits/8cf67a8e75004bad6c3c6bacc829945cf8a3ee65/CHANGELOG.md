## main / (unreleased)

Please do **not** add any entries in this section. If your change affects
behaviour, describe it in the pull request description. Those entries are added
here, when the release is prepared.

## 0.35.0 / 2026-11-09

* [CHANGE] Promote the `auto-gomemlimit` feature flag to the `--auto-gomemlimit` command-line flag. This is a breaking change: the `--enable-feature=auto-gomemlimit` option has been removed. #5464
* [CHANGE] Remove the deprecated `types` package in favor of the `alert` package. #5585
* [CHANGE] eventrecorder: Every output now requires a `name`. This is a breaking change: configurations with unnamed outputs fail to load. The name identifies the output in metrics and logs instead of its URL, broker or topic. #5393
* [CHANGE] eventrecorder: The output data format now uses the new `events/v2` schema. This is a breaking change: alert labels, alert annotations, group labels, silence annotations, and muted-alert labels are JSON maps, and protobuf consumers must use the new schema. #5409, #5500
* [FEATURE] Add a distroless container image. #5258
* [FEATURE] amtool: Look up the default config file in `%APPDATA%` and `%ProgramData%` on Windows. #5073
* [FEATURE] api: Add an experimental ConnectRPC API served alongside `/api/v2/` under the version-neutral `/api/` prefix, exposing the Connect, gRPC, and gRPC-Web protocols plus the gRPC Health Checking Protocol and server reflection. The first service is `status.v3.StatusService`. #5377, #5506, #5507, #5508, #5509
* [FEATURE] incidentio: Add templated `metadata` field. #5022
* [FEATURE] pagerduty: Report more specific failure reasons in `alertmanager_notifications_failed_total`. #5659
* [FEATURE] rocketchat: Add `message_text` option to set the message text shown in desktop and push notifications. #5595
* [FEATURE] slack: Add `post_updates_to_thread` option to post subsequent notifications of an alert group as replies in the thread of the initial message. #5540
* [FEATURE] telegram: Add `timeout` option to limit how long a notification request may take. #5127
* [FEATURE] telegram: Count only visible HTML text toward the message length limit, excluding link URLs. #5499
* [FEATURE] template: Add `addDuration` function to shift a timestamp by a duration such as `-30m` and return it in Unix milliseconds. #5550
* [FEATURE] template: Allow the `join` function to accept slices and arrays of any type. #5233
* [FEATURE] timeinterval: Allow weekday ranges to wrap around the end of the week, e.g. `friday:monday`. #5579
* [FEATURE] ui: Make the creator and comment of a silence optional, matching the API. #5471
* [FEATURE] ui: Serve the new Mantine UI at `/ui/` alongside the existing UI. #5502, #5538, #5539, #5537
* [ENHANCEMENT] Compute alert fingerprints once at ingestion instead of on every mute check, reducing CPU usage and allocations. #5583
* [ENHANCEMENT] api: Speed up `/api/v2/alerts/groups` by evaluating mutes only once per alert and group. #5674
* [ENHANCEMENT] cluster: Fix the `memeberlist` typo in error messages. #5472
* [ENHANCEMENT] docs: Add a Gotify example using a custom webhook payload. #5408, #5498
* [ENHANCEMENT] docs: Add a reusable HTML email template example. #5391
* [ENHANCEMENT] docs: Clarify the usage of the KV `Remove` template function. #5297
* [ENHANCEMENT] docs: Clarify which route options are inherited by child routes. #5565
* [ENHANCEMENT] docs: Correct the PagerDuty default config. #5397
* [ENHANCEMENT] docs: Document OAuth2 support in the `http_config` of `jira_config`. #5571
* [ENHANCEMENT] docs: Document VictorOps custom fields. #5399
* [ENHANCEMENT] docs: Document `project` and `issue_type` in `jira_config` as templated strings. #5549
* [ENHANCEMENT] docs: Document `victorops_api_key` and `victorops_api_key_file` in the global config. #5168
* [ENHANCEMENT] docs: Fix `rocketchat_config` defaults and field types. #5591
* [ENHANCEMENT] docs: Fix the `tracing` config key, which was misspelled as `traciing`. #5437
* [ENHANCEMENT] notify: Add the receiver name to the log message for failed notifications. #5401
* [ENHANCEMENT] silences: Reduce allocations when computing the `alertmanager_silences` metric. #5460
* [ENHANCEMENT] victorops: Use Splunk On-Call branding in documentation and error messages without renaming configuration fields. #5402
* [BUGFIX] api: Report alerts muted by time intervals as of the time of the request instead of the last group flush, matching silences and inhibitions. #5661
* [BUGFIX] cluster: Downgrade memberlist to v0.5.4 to fix `Failed to read remote state: user state length (...) exceeds limit` errors. #5640
* [BUGFIX] config: Fix merging of global configs for the smtp, opsgenie, victorops and rocketchat notifiers. #5448, #5457
* [BUGFIX] discord: Retry notifications on HTTP 429 (rate limited) instead of dropping them. #5496
* [BUGFIX] httpserver: Fix the `/-/reload` endpoint getting stuck when the client cancels the request. #5234
* [BUGFIX] notify: Wait the full backoff interval before retrying a notification that failed slowly. #5497, #5389, #5553
* [BUGFIX] opsgenie: Respect the notification timeout and tracing span for the update-message request sent when `update_alerts` is enabled. #5465
* [BUGFIX] pagerduty: Report the failure reason of Events API v1 requests in `alertmanager_notifications_failed_total` instead of `reason="other"`. #5505
* [BUGFIX] pushover: Trim whitespace from `token_file` and `user_key_file` contents so keys stored in files with a trailing newline are accepted. #5590
* [BUGFIX] silences: Treat a silence as expired at exactly its end time, consistent with the API. #5665
* [BUGFIX] silences: Use a single evaluation time for each read or write of silences. #5666
* [BUGFIX] slack: Avoid a panic when `update_message` relies on `global.slack_api_url`. #5589
* [BUGFIX] slack: Retry notifications on HTTP 429 (rate limited) and honor the `Retry-After` header instead of dropping them. #5048
* [BUGFIX] telegram: Redact the bot token from logged notification errors. #5254
* [BUGFIX] telegram: Report the failure reason in `alertmanager_notifications_failed_total`. #5375
* [BUGFIX] template: Preserve quoted numeric strings as strings in templated JSON fields. #5098
* [BUGFIX] timeinterval: Fix negative `days_of_month` resolving one day early in months with a DST transition. #5447
* [BUGFIX] timeinterval: Reject month numbers outside 1-12. #5626
* [BUGFIX] webex: Fix a panic when truncating long notifications containing non-ASCII characters. #5544
* [BUGFIX] webex: Retry notifications on HTTP 429 (rate limited) and honor the `Retry-After` header instead of dropping them. #5548
* [BUGFIX] wechat: Report template errors in `corp_id` and `api_secret` instead of sending a token request with empty values. #5688

## 0.34.2 / 2026-10-29

* [SECURITY] api: Alertmanager no longer sends CORS headers by default. This means `api/v2` now disallows cross-origin requests. This is a breaking change. The new `--web.cors.origin` flag can be used to restore the previous behaviour. #5664
* [SECURITY] Build with Go 1.26.10, which distrusts the eight compromised eMudhra intermediate CA certificates in `crypto/x509`. CVE-2026-111943

## 0.34.1 / 2026-09-17

* [BUGFIX] inhibit: Fix several issues related to inhibitions that caused alerts to be improperly un-muted in some cases. #5542, #5449, #5559

