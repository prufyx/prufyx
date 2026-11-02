### Changed

- The custom-resource table lists `argoproj.io` for `argo-cd` by kind (`AppProject`, `Application`, `ApplicationSet`, the kinds of its `manifests/crds`) instead of as a whole group, so the group can be shared with Argo Workflows, Argo Rollouts and Argo Events once the table lists their kinds. An `argoproj.io` object of another kind (a `Rollout`, a `Workflow`) is attributed to no project and keeps the `argo-cd` custom-resource set incomplete, so a rule on that set answers UNKNOWN for a bundle that holds one.
