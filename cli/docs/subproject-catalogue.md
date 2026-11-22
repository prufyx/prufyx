# Offline subproject catalogue

From a complete public repository export, run:

```sh
prufyx-maintainer subprojects catalogue --root /path/to/export
```

This command validates the reviewed subproject overlay with the landscape,
custom-resource table and every custom-resource version target in that export.
It makes no network requests and writes nothing to the export. Its versioned
JSON output lists exact repository identities and hashes of the input bytes.
`inputDigests.targets` hashes the compact JSON array of `[filename, digest]`
pairs, sorted by filename. Every digest uses `sha256:` followed by lowercase hex.
A genuinely absent overlay returns an empty row list and a null overlay digest;
malformed or unreadable inputs are refused with no JSON output. Output is bounded
to 1 MiB. Exit codes are 0 for success, 1 for refused input, and 2 for usage errors.

The command validates local data; it does not authenticate the export's origin,
re-fetch cited evidence, enrol a target or establish upgrade compatibility.
Callers must separately trust the executable and bind its output to their exact
input snapshot. The existing `subprojects verify` command remains the networked
maintainer review step for checking cited upstream files.
