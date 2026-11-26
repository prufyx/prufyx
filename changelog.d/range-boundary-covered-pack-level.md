### Changed

- The knowledge gate admits a raise of a rule pack to level `v1alpha16` only if the same change adds or alters the range of an existing rule of that pack, with an owner approval or a batch approval of that rule, and the oldest supported client is `v0.1.0-beta.3` or later both before and after the change, in a pin file of the form the publication workflow accepts. An owner approval binds the bytes of the rule, not the pack level.
- A knowledge package that carries level `v1alpha16` names `v0.1.0-beta.3` or later as its minimum client version, and a publication build of it is refused while the oldest supported client is older or unknown.
