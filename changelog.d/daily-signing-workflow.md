### Added (workflows)

- The knowledge publish workflow becomes a daily plan, approval and sign run: a keyless plan job builds the packet of merged changes and checks the approval gate, the sign job (environment `knowledge-release`) signs only what the plan describes, and the per-push trigger is removed. Not active until the owner adds the required reviewer; a manual run is a dry run by default. Needs the packet generator and the publisher guard subcommands from the two pull requests it depends on.
