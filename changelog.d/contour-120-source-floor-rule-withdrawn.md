### Fixed

- The Contour 1.19.0 to 1.20.0 rule about Gateway API v1alpha1 resources is withdrawn. The upstream 1.20.0 upgrade guide requires a Contour older than 1.19.1 to be upgraded to 1.19.1 first, so the scoped PASS this rule gave from 1.19.0 was wrong. That transition now reports UNKNOWN, including the case it used to report as blocked.
