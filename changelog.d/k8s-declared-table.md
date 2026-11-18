### Documentation

- Added a generated table of the Kubernetes versions that ten upstream projects declare per release line (chart `kubeVersion` or a published compatibility table), each row cited to the repository, tag, upstream-resolved commit, file path, lines and digests. It states what upstream declared, not support by Prufyx; minimums are never shown as ranges and projects with nothing citable are listed as not declared upstream. `prufyx-maintainer k8s-declared --check` verifies the committed files offline.
