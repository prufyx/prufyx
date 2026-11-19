### Added

- An upgrade of a custom-resource project through several minor lines is answered from the hops of the stepwise path instead of one direct hop that no rule covers: a blocked hop makes the jump BLOCKED and names the rule, every hop is listed with its own status, and STEPWISE_PASS is given only when every hop is decided PASS on one object set (the report stays UNKNOWN and never claims a direct jump). Plans print a per-hop table for every route of several hops, Kubernetes included.
