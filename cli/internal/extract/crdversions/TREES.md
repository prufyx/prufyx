# Derived non-install trees

CRD-like files under a directory named `test`, `testdata`, `e2e`, `example`
and so on never withhold a pair, but they block attestation unless something
proves they are not installed. A directory name is not that proof: it only
nominates a tree (the directory up to its first such segment). The extractor
(`WithDerivedTrees`, on for `extract run`, only for a target that attests,
never in an onboarding dry run, never on an incomplete scan) clears a tree
at a release only when all of these hold, computed from the pinned bytes:

| Condition | Reason when it fails |
|---|---|
| segment is a test or example name (vendored code is another component) | `other-component` |
| no overlap with a listed path, an inventory file, a generation, literal-kustomization or remote path, or a reviewed exclusion | `overlaps-install-path` |
| every blocking finding under it is an extra, conflict, reference, unread, unsupported or go-defined file | `holds-finding-of-other-class` |
| the install-surface guard finds no referrer (kustomization, chart, Makefile, script, document, container build, nix, kodata, `//go:embed` in a non-test package) | `install-surface-reference` |
| no file the guard does not read (CI configuration, other scripts and build systems, Go code outside test directories, Makefiles, shell scripts, container builds) holds a path word that overlaps it, a path built from variables only, or a context-wide COPY | `unread-surface-overlap`, `container-build-copies-context` |
| no symbolic link in the tree, none named like an install file, none on a listed path (links are never followed) | `symbolic-link` |
| bounds (files, links, roots) | `bounds` |

A pair is attestable only when every release of both lines scans clean, so a
tree is proven at every release of both lines or the pair stays blocked
(UNKNOWN). A cleared file is recorded as `excluded` or `excluded-unread` with
location `derived: <class> <root>/`; `treeVerdicts` in the scan record holds
every verdict with the files, the object ids and a digest of the files that
were checked. A fixture CRD is never added to the inventory: clearing only
subtracts a blocker.

Not covered here: external chart dependencies (`external` findings), embedded
components, and files that are install copies outside the listed paths.
Residual: a path assembled only at run time from non-literal parts cannot be
excluded by reading source.
