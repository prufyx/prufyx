### Fixed

- `prufyx scan` on a chart-declared route (`--chart` with `--to <chart>=X`) now turns entries it did not read (symlinks, hidden directories, templated or non-manifest files) into `DOCUMENTS_NOT_EVALUATED` gaps, like the Kubernetes and custom-resource routes, instead of listing them only as omitted.
