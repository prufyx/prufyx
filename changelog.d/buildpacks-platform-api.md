### Fixed

- `buildpacks.lifecycle-platform-api-support` no longer passes on lifecycle labels that contradict the reviewed Platform API sets of 0.16.5 and 0.17.7 (for example a 0.17.7 config claiming Platform API 0.13): the lifecycle config is now treated as unsupported metadata and the verdict is UNKNOWN instead of PASS.
