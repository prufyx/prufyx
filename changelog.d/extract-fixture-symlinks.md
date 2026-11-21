### Fixed

- The extractor fixture reader now lists symlinks as git mode 120000 entries whose content is the link target, never following them, as the mirror reader does; it refuses absolute or root-escaping targets with a typed error instead of aborting on the first symlink.
