### Changed

- The release-line additions file and its tag files are now admitted only by an owner-signed onboarding v3 batch that binds, per new project, the tag file digest and the entry digest; a plain batch, an older schema, or a change with no record fails closed in the gate admission of these paths. A human data change with no record is decided by the owner merge, never automatically.
