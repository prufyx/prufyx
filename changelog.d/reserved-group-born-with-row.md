### Changed
- An owner-signed onboarding batch can now add a reserved-namespace group record (`k8s.io`, `x-k8s.io`, `kubernetes.io`) together with the new project row that owns it. Existing records cannot change or go, and a record for any other project, an unsigned batch or a group the upstream repository does not declare is still refused.
