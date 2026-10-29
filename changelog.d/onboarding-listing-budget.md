### Fixed

- The onboarding dry run no longer counts directory listings against a project's 3000-read budget. A project with a large vendored tree (a thousand or more directories per tag) used it up on listings answered from one cached subtree fetch. Listings now have their own bound of 10000 per project; the REST request budget and the read budget are unchanged, and every file is still listed and read.
