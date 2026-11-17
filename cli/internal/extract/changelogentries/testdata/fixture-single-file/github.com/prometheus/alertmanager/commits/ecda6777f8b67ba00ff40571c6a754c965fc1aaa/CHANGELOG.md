## main / (unreleased)

* [CHANGE] ...
* [FEATURE] ...
* [ENHANCEMENT] ...
* [BUGFIX] ...

## 0.30.0 / 2025-12-15

* [CHANGE] Don't allow calling qids with an empty ids list. #4707
* [FEATURE] Add mattermost integration. #4090
* [FEATURE] Add saturday to the first day of the week options. #4473
* [FEATURE] Add templating functions for working with urls. #4625
* [FEATURE] cluster: Allow persistent peer names. #4636
* [FEATURE] dispatch: Add start delay. #4704
* [FEATURE] provider: Add subscriber channel metrics. #4630
* [FEATURE] template: Add tojson function. #4773
* [FEATURE] Add api http metrics. #4162
* [FEATURE] Add distributed tracing support. #4745
* [FEATURE] Add names to inhibit rules. #4628
* [FEATURE] Add timeout option for pagerduty notifier. #4354
* [FEATURE] Add timeout option for slack notifier. #4355
* [FEATURE] Allow nested details fields in pagerduty. #3944
* [FEATURE] Implement `phantom_threading` to group email alerts into threads. #4623
* [FEATURE] gc: Report errors, but remove erroneous silences and continue. #4724
* [FEATURE] jira: Template customfields. #4029
* [FEATURE] jira: Allow configuring issue update via parameter. #4621
* [FEATURE] Slack app support. #4211
* [ENHANCEMENT] Add comment about smtp plain authentication. #4741
* [ENHANCEMENT] Add documentation about high availability. #4708
* [ENHANCEMENT] Add documentation for `client_allowed_sans`. #4706
* [ENHANCEMENT] Improve logging around webhook dispatch failure. #4511
* [ENHANCEMENT] Compile silence matchers when the silence is added. #4695
* [ENHANCEMENT] Fix '`s/client/alerts_api/g`' broken link in 0.29. #4718
* [ENHANCEMENT] Fix `rocketchat_config` docs. #4767
* [ENHANCEMENT] Fix: `<mute_time_interval>` was renamed. #4729
* [ENHANCEMENT] Improve inhibition performance. #4607
* [ENHANCEMENT] Loadsnapshot: update matcher index properly while not holding lock. #4714
* [ENHANCEMENT] Logging improvements. #4113
* [ENHANCEMENT] Move query locking back into private query function. #4694
* [ENHANCEMENT] Optimize the new inhibitor implementation for ~2.5x performance improvement. #4668
* [ENHANCEMENT] Reduce the time dispatch.group holds the mutex. #4670
* [ENHANCEMENT] Use b.loop() to simplify the code and improve performance. #4642
* [ENHANCEMENT] Remove duplicate slice during silences query. #4696
* [ENHANCEMENT] Silences: optimize incremental mutes queries via a silence version index. #4723
* [ENHANCEMENT] Update description for filter param in openapi. #4775
* [BUGFIX] Add new behavior to avoid races on config reload. #4705
* [BUGFIX] config: Fix duplicate header detection for all case variants. #2810
* [BUGFIX] marker: Stop state leakage from aggregation groups. #4438
* [BUGFIX] Fix pprof debug endpoints not working with --web.route-prefix. #4698
* [BUGFIX] Set context timeout for resolvepeers. #4343

## 0.29.0 / 2025-11-01

* [FEATURE] Add incident.io notifier. #4372
* [FEATURE] Add monospace message formatting. #4362
* [FEATURE] Add ability to customize interval for maintenance to run. #4541
* [ENHANCEMENT] Update Jira notifier to support both Jira cloud API v3 and Jira datacenter API v2. #4542
* [ENHANCEMENT] Increase mixin rate intervals for alert `FailedToSendAlerts`. #4206
* [ENHANCEMENT] Make /alertmanager group writable in docker image. #4469
* [BUGFIX] Fix logged notification count on error in notify. #4323
* [BUGFIX] Fix docker image permissions path. #4288
* [BUGFIX] Fix error handling in template rendering for Telegram. #4353
* [BUGFIX] Fix duplicate `other` in error messages for config. #4366
* [BUGFIX] Fix logic that considers an alert reopened in Jira. #4478
* [BUGFIX] Fix Jira issue count #4615

## 0.28.1 / 2025-03-07

* [ENHANCEMENT] Improved performance of inhibition rules when using Equal labels. #4119
* [ENHANCEMENT] Improve the documentation on escaping in UTF-8 matchers. #4157
* [ENHANCEMENT] Update alertmanager_config_hash metric help to document the hash is not cryptographically strong. #4210
* [BUGFIX] Fix panic in amtool when using `--verbose`. #4218
* [BUGFIX] Fix templating of channel field for Rocket.Chat. #4220
* [BUGFIX] Fix `rocketchat_configs` written as `rocket_configs` in docs. #4217
* [BUGFIX] Fix usage for `--enable-feature` flag. #4214
* [BUGFIX] Trim whitespace from OpsGenie API Key. #4195
* [BUGFIX] Fix Jira project template not rendered when searching for existing issues. #4291
* [BUGFIX] Fix subtle bug in JSON/YAML encoding of inhibition rules that would cause Equal labels to be omitted. #4292
* [BUGFIX] Fix header for `slack_configs` in docs. #4247
* [BUGFIX] Fix weight and wrap of Microsoft Teams notifications. #4222
* [BUGFIX] Fix format of YAML examples in configuration.md. #4207

