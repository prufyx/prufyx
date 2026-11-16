### Changed
- The CRD completeness scan no longer depends on the upstream spelling the kind literally: a file that names the kind through escapes, line continuations, UTF-16 or a templated kind value is now an unread finding instead of a clean scan (extractor 2.17.0).
