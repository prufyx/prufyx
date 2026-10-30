### Added

- `crd.version-removal` targets can name a chart tag prefix (`jenkins-`, `cluster-autoscaler-`), the tag form of a repository that releases several charts. A prefix is lower-case words joined by single dashes and ends in a dash; a tag is a release only when it is exactly the prefix and `X.Y.Z`, so the tags of a chart whose name extends the prefix are never read.
