# Jaeger 2.20 explicit configuration target constraint

These public fixtures exercise one narrow target-only predicate for each
reviewed origin `2.15.1`, `2.16.0`, `2.17.0`, `2.18.0`, or `2.19.0` to
`2.20.0`. Copy a fixture to a private `0600` path, then run the local Go-built
Community binary with `prepare cncf --project jaeger`. The declared
`--non-memory-storage-required true` and `--official-jaeger-distribution true`
values are required before absent `--config` is a blocker.

`pass.json` has one literal local configuration selection. Use it with
`prepare cncf --project jaeger` and the two declared guards; the subsequent
check passes this narrow predicate. `unknown-empty.json` and `unknown.json`
exercise native selections that are ambiguous (empty or expansion syntax), so
their prepare and check results are `UNKNOWN`: native preparation does not
invent an absent configuration fact.

`blocked-operator-declared.json` is a separate canonical input for
`check cncf --project jaeger --input`. It demonstrates `BLOCKED` only after an
operator explicitly declares all three facts: no explicit configuration,
non-memory storage required, and official Jaeger distribution. It is not a
claim that the native empty fixture detected that absence. The check does not
read the configuration file, inspect its backend or credentials, launch
Jaeger, or prove whole-upgrade safety.
