### Fixed

- The onboarding dry run now asks GitHub once for a whole directory tree it had earlier read one level only, instead of once per directory below it. Such a second answer is used only if every listing in it hashes to its git object id.
- A dry run refused for its budget now names the counter that was used up (REST requests, reads or listings) and the values of all three. The budgets are unchanged.
