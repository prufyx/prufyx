### Added

- Add the command line flag scanner for Go sources: it reads registered flag names from the standard flag package, pflag, cobra, urfave and kingpin, withholds a binary's set when any registration cannot be proven, and encodes members through the shared member encoder.
