### Added

- The coverage README block and the coverage counts file now show one row per evidence family for decided upgrades (CRD versions and the chart families), each on its own row and never summed, with "none yet" for a family that decides nothing; a project marked as having no Kubernetes surface is a permanent typed gap (`NO_KUBERNETES_SURFACE`) with its reason shown and never counted as decided. The counts file is schema v3; v1 and v2 files still load.
