### Added

- Maintainer-side extractors that turn committed provider excerpts into lifecycle rows of the distribution record shape: upstream Kubernetes release data (schedule, end-of-life list, stable marker) and the Amazon EKS release calendar (markdown and HTML forms). They read excerpts only, never fetch, and reject any changed header, unparsable row, empty or prerelease input with a typed drift error and no partial output. Nothing reads them yet and no shipped pack changes.
