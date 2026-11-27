### Changed

- The knowledge gate admits a raise of a rule pack to level `v1alpha16` only with an owner approval of that raise (`approval sign --subject packLevel`), which names the pack and both levels and binds the base and head pack files; if the same change also adds or alters the range of an existing active rule of that pack, with an owner approval of that rule; and if the oldest supported client is `v0.1.0-beta.2` or later both before and after the change, in a pin file of the form the publication workflow accepts.
- A knowledge package that carries level `v1alpha16` names `v0.1.0-beta.2` or later as its minimum client version, and a publication build of it is refused while the oldest supported client is older or unknown.
