## main / (unreleased)

* [CHANGE] ...
* [FEATURE] ...
* [ENHANCEMENT] ...

## 0.32.0 / 2026-04-10

* [CHANGE] `go get github.com/prometheus/alertmanager/ui` will now fail as compiled UI assets are no longer checked into the repository. Downstream builds that rely on these assets being present in the source tree must now build the UI from source. #5113
* [CHANGE] The '--enable-feature=auto-gomaxprocs' option is deprecated and will be removed in v0.33. This flag currently has no effect and can be safely removed from any startup scripts. #5090
* [CHANGE] Update internal function signatures across multiple packages. This affects any project that integrates `Alertmanager` code.
* [ENHANCEMENT] Add static asset caching. #5113
* [ENHANCEMENT] Reduce memory allocations through pre-sizing collections and batch allocation. #5020
* [ENHANCEMENT] Replace help with documentation in navigation bar. #4943
* [ENHANCEMENT] docs(ha): Update high availability documentation. #5136
* [ENHANCEMENT] docs: Add `auth_secret_file` for smtp in document. #5036
* [ENHANCEMENT] docs: Add description for global `telegram_bot_token`. #5114
* [ENHANCEMENT] docs: Add note about notifier timeouts. #5077
* [ENHANCEMENT] docs: Fix `force_implicit_tls` config field name. #5030
* [ENHANCEMENT] docs: Link community supported integrations. #4978
* [ENHANCEMENT] docs: Remove duplicate header. #5034
* [ENHANCEMENT] docs: Update mutual tls reference in high availability documentation. #5120
* [ENHANCEMENT] tracing: Use noop spans when tracing disabled. #5118
* [ENHANCEMENT] ui: Serve pre-compressed assets. #5133
* [FEATURE] Add silence annotations. #4965
* [FEATURE] Add silence logging option. #4163
* [FEATURE] Add support for multiple matcher set silences. #4957
* [FEATURE] Add the reason for notifying in dedup stage. #4971
* [FEATURE] mattermost: Flatten attachments into top-level config. #5009
* [FEATURE] mattermost: Support global webhook url. #4998
* [FEATURE] slack: Add default color from template. #5014
* [FEATURE] slack: Allow receiver to edit existing messages. #5007
* [FEATURE] template: Add dict, map and append functions. #5093
* [FEATURE] webhook: Add full payload templating support for notifier. #5011
* [BUGFIX] config: Check for empty cluster tls client config. #5126
* [BUGFIX] config: Don't crash upon reading empty config for notifier. #4979
* [BUGFIX] config: Fix ipv6 address handling in hostport.string(). #5040
* [BUGFIX] mattermost: Omit empty text field in notifications. #4985
* [BUGFIX] telegram: Send fallback message when notification exceeds character limit. #5074
* [BUGFIX] tracing: Properly shutdown tracer provider. #5131
* [BUGFIX] ui: Fix escaping for matcher values with quotes. #4862
* [BUGFIX] ui: Handle special chars in silence regex-matchers. #4942
* [BUGFIX] ui: Support utf-8 label names in matchers. #5089

## 0.31.1 / 2026-02-11

* [BUGFIX] docs: Fix email TLS configuration example. #4976
* [BUGFIX] docs: Add telegram bot token options to global config docs. #4999

## 0.31.0 / 2026-02-02

* [ENHANCEMENT] docs(opsgenie): Fix description of `api_url` field. #4908
* [ENHANCEMENT] docs(slack): Document missing app configs. #4871
* [ENHANCEMENT] docs: Fix `max-silence-size-bytes`. #4805
* [ENHANCEMENT] docs: Update expr for `AlertmanagerClusterFailedToSendAlerts` to exclude value 0. #4872
* [ENHANCEMENT] docs: Use matchers for inhibit rules examples. #4131
* [ENHANCEMENT] docs: add notification integrations. #4901
* [ENHANCEMENT] docs: update `slack_config` attachments documentation links. #4802
* [ENHANCEMENT] docs: update description of filter query params in openapi doc. #4810
* [ENHANCEMENT] provider: Reduce lock contention. #4809
* [FEATURE] slack: Add support for top-level text field in slack notification. #4867
* [FEATURE] smtp: Add support for authsecret from file. #3087
* [FEATURE] smtp: Customize the ssl/tls port support (#4757). #4818
* [FEATURE] smtp: Enhance email notifier configuration validation. #4826
* [FEATURE] telegram: Add `chat_id_file` configuration parameter. #4909
* [FEATURE] telegram: Support global bot token. #4823
* [FEATURE] webhook: Support templating in url fields. #4798
* [FEATURE] wechat: Add config directive to pass api secret via file. #4734
* [FEATURE] provider: Implement per alert limits. #4819
* [BUGFIX] Allow empty `group_by` to override parent route. #4825
* [BUGFIX] Set `spellcheck=false` attribute on silence filter input. #4811
* [BUGFIX] jira: Fix for handling api v3 with ADF. #4756
* [BUGFIX] jira: Prevent hostname corruption in cloud api url replacement. #4892

