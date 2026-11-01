### Documentation

- Document the custom-resource instance collector of the manifest intake: it keeps only allowlisted public spec paths and enum tokens as members and counts, never raw paths, values, names, `status` or Secret content, and marks a result incomplete when a document cannot be read or a wrapper object may hide custom resources. It is not yet connected to `scan` reports.
