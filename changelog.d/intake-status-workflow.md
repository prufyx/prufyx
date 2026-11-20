### Added (workflows)

- Status replies for onboarding request issues without an installed App: a scheduled workflow reads the published intake status feed, checks every id against the live issue and posts one status comment per issue (edited in place on a state change). It never runs on an issue or comment event and changes no labels.
