### Changed
- An upgrade across a major version is now listed hop by hop: the minor hops of the old major, one explicit major hop, and the minor hops of the new major. The major hop is undecided (`MAJOR_HOP_NOT_COVERED`) unless a reviewed rule scoped to it decides it, so such a jump is never a pass.
- A project that scan does not evaluate now lists the requested path hop by hop, each hop undecided with `COMPONENT_NOT_COVERED` and its next action, instead of "0 hops". The verdict and exit code are unchanged.
- A major hop that is not decided by a rule scoped to it names the release lines the client does not know (`LINES_NOT_LISTED`); a wider-range rule that blocks, or a notice of one, makes the jump BLOCKED or ATTENTION, labelled as not scoped to the hop. No pass path is added.
