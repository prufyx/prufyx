### Fixed
- A jump across a major line is always typed: when the old side has no reviewed line after it and the target is the first line of the new major, the single hop is still reported as an undecided major hop (MAJOR_HOP_NOT_COVERED) with its next action instead of a bare unknown. The verdict and exit code are unchanged and the hop is never a pass.
