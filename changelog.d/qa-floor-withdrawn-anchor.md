### Changed

- QA: the custom-resource oracle accepts UNKNOWN at the exact anchor of a removal rule only when that rule is listed in the
  oracle as withdrawn for an upstream source floor and the shipped rule table marks it withdrawn; a pass is still refused.
