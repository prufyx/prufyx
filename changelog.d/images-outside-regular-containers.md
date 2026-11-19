### Fixed
- A reviewed component image found only in an init container, an ephemeral container or a bare Pod is no longer reported absent; ownerReferences must be the managing controller with the exact apiVersion to count a ReplicaSet or Job as derived. The collector now also lists Pods and projects only their container images and owner references.
