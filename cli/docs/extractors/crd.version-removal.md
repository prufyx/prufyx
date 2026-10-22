# Extractor `crd.version-removal`

Version 2.9.0. Derives `forbid_set_member` rules for custom-resource
versions that a project's release line no longer serves, from the
CustomResourceDefinition manifests the project ships in its repository. It is
deterministic, reads only upstream source pinned by full commit SHA, and
involves no model.

A run reads one repository, so the extractor is registered once per project,
as `crd.version-removal.<project>`; every registration runs the same code and
carries the same version. Its code digest covers that code and its own target
file only, so each id has its own digest (see Running and verifying).

## Projects and paths

The reviewed source table is one data file per target compiled into the
extractor, `cli/internal/extract/crdversions/target-<project>.json` (schema
`prufyx.io/crd-version-target/v1`, one `target` member; the file name must
name the project it holds, and no project, fact, repository or component may
appear in two files). A target file is part of the code digest of its own
`crd.version-removal.<project>` id and of no other: any change to it is a new
code digest of that id, and rules that id derived before no longer re-derive;
adding a target, or changing one, leaves every other id's digest as it was.
Each entry names a catalog project, its repository, the prefixes of its release
tags, the first release line a pair may start from, the paths that hold its
rendered CRD manifests, and the reviewed exclusions of the full-tree scan
(below), each with the reason it was accepted and, for chart templates that are
copies of the listed definitions, the flag `copies` that makes the scan check
that claim, or, for the generated sources a kustomization renders into a
listed bundle, the kustomization `prePatch` whose rendering the scan checks,
or, for YAML or JSON data files that define no CRD, `"defines": "none"`, a
claim the scan checks.

An entry of a project outside the CNCF landscape catalog carries
`"catalog": "community"` (an entry without the field is a CNCF catalog
project; `"cncf"` is not spelled out). Such a project must be a community
project of the reviewed custom-resource table, with the same repository and
name, and neither its slug nor its component may be a CNCF catalog one (see
[../custom-resources.md](../custom-resources.md)). A community target never
attests: the loader refuses `"attest": true` for it, until the reviewed path
that admits a community project's line reviews exists (the pack and the
knowledge store can carry its rules, but the line-review families admit no
community component). Its runs follow every other rule of this
extractor (full-commit citations, full-tree scan, withheld pairs).

Every target, with its catalog, repository, release tags, first line, the
paths it reads and the number of reviewed exclusions, is listed in
[../generated/crd-version-targets.md](../generated/crd-version-targets.md),
generated from the target data by `prufyx-maintainer docs-tables`
(`prufyx-maintainer extract list` lists the registered ids).

In a listed directory, a file whose name contains `crd` (in any case) but
does not match the pattern makes the inventory incomplete: it may hold a
definition the extractor would not read. A listed path must exist at every
release unless it is marked optional (Strimzi's `install/access-operator`).

Only the custom-resource version sets of `argo-cd`, `istio` and `strimzi` are
registered today (see [../custom-resources.md](../custom-resources.md)). The
rules derived for the other projects are correct candidates, but the knowledge
gate refuses them until their set and API groups are added to the reviewed
custom-resource table in a change of their own.

## Another repository from some line on

A target may carry a `remote` member (Kong Ingress Controller from 3.4: its
CRDs moved to `Kong/kubernetes-configuration`). From the line `fromLine` on, a
release does not read the target's `paths`. It reads the release's own
`kustomization` file (`config/crd/kustomization.yaml`), which must hold, in
the strict subset and with no other key than `apiVersion`, `kind` and
`resources`, exactly one resource, `https://github.com/<repo>/<directory>?ref=<tag>`
of the declared repository and directory with exactly one `ref` that is a
release or pre-release tag. The tag is resolved to a commit through the
`pins` of the target (a reviewed list of tag and full commit, in ascending
order): a tag that is not pinned withholds the release, so a tag upstream moves
later cannot change what is read. At the pinned commit the extractor reads the
directory's own `kustomization.yaml` (again exactly `apiVersion`, `kind` and a
list of plain file names of the directory) and the files it lists, which are
parsed as any CRD manifest; a file of the directory that the kustomization does
not list is not installed and is only counted. Every citation of such a
definition names the other repository and its full commit; the proof records
the kustomization, the tag, the commit and the files. The release's own
repository is still scanned in full. A target with a `remote` never attests
its lines.

## Install channels

A project that ships more than one install (Gateway API's standard and
experimental channels) declares `declaredChannel` (the install `paths`
describe) and `channels` (the others, each with its own paths, at most four).
The rules are about the declared channel. Every channel is read in full and
strictly at every release (a definition is unique within its channel, and
channels may define the same custom resource differently; a missing,
unreadable or templated channel withholds the pairs that read the release),
and a channel's files are not scan findings. A version that the declared
channel stops serving but another channel still serves at a release of the
later line is recorded as `channelRetained` in the proof and is not
forbidden: no rule is derived for it, so a user of the other channel is never
blocked on a version their install still serves. A definition that only
another channel still holds is not told from a removed one, and the pair is
withheld as for a moved file. A rule of such a target says in its description
which channel it is about. A target with channels never attests its lines,
and cannot have a `remote`.

## Release lines and pairs

A **line** is one `major.minor` of a project with at least one final release
tag (`<prefix>X.Y.Z`; release candidates never count). A target names one or
two prefixes from a closed set: none, `v`, and `knative-v` (the release tags of
the Knative projects, `knative-v1.15.0`); each ends in a character that is not
a digit or a dot, so no part of a version is ever read as the prefix, and a
tag with anything before the prefix (`xknative-v1.15.0`), a suffix
(`knative-v1.15.0-rc1`) or a leading zero (`knative-v01.2.3`) is not a release
of the target. When a release is tagged
under both prefixes of a project they must name one commit, or every pair of
that line is withheld. A **pair** is two consecutive lines in version order (so
a major release follows the last minor of the previous major, and a skipped
minor number is skipped), starting from the line in the table; it is named by
the first final release of each line (normally `X.Y.0`), which is the rule's
anchor transition. A repository with an unacknowledged tag alarm yields no
pairs.

For each pair the extractor reads **every final release of both lines**.

## What it reads at each release

Through the offline factory mirror (or a fixture tree), never the network.

- **CRD manifests.** Every listed file, and every matching file in a listed
  directory, is read in full and decoded in a strict YAML subset: anchors,
  aliases, merge keys, custom tags, non-string, empty or duplicate keys are
  refused, as are documents nested deeper than 128 levels, over 4 000 000
  nodes, over 1 024 documents, or files over 8 MiB. Template syntax (`{{`)
  makes the file unreadable, except where it is documentation (below).
  Documents of other kinds are counted and otherwise ignored.
- **Template syntax, precisely.** A file is a rendered manifest, not a
  template, so `{{` makes it unreadable, with one exception that is decided by
  the file's structure and not by a search for the characters: a CRD's OpenAPI
  schema documents its fields in `description` strings, and a description may
  quote template syntax (Cluster API's ClusterClass documents its patch
  templates that way). Nothing the extractor reads depends on description
  text. A file with `{{` is read as a rendered manifest only when all of these
  hold; otherwise it is template syntax and the pair is withheld as before:
  the file decodes in the strict subset; the file with every `{{` replaced by
  `{T` decodes to a tree of the same shape; the two trees differ only in
  strings, and each string that differs is the value of a `description` key of
  the schema of a CRD document (`spec.versions[i].schema.openAPIV3Schema`
  reached only through schema keywords: `properties` and `patternProperties`
  with a field name, `items`, `additionalProperties`, `not`, and `allOf`,
  `anyOf` and `oneOf` with an index) and is exactly the other tree's string
  with its `{{` replaced; no key and no other string holds `{{`; and the `{{`
  of those strings are all the `{{` of the file's bytes (one in a comment, a
  directive line, a name, a flag, an annotation, a default, an enumeration, a
  validation rule, a flow collection or another kind of document is one
  more). Text that only decodes to `{{` (an escape, a line continuation) holds
  none in its bytes and is not template syntax.
- **Each `apiextensions.k8s.io/v1` CustomResourceDefinition**: its name,
  group, kind, plural and scope, and for every entry of `spec.versions` the
  name, `served` and `storage` flags and the lines of the entry and of its two
  flags.
- **The whole repository tree (full-tree scan).** Every directory is listed
  (none is skipped), and every file outside the listed paths of these kinds is
  read: `*.yaml`, `*.yml`, `*.json` and files named `Kustomization`; template,
  jsonnet and cue sources (`*.tmpl`, `*.tpl`, `*.gotmpl`, `*.jsonnet`,
  `*.libsonnet`, `*.cue`, `*.j2`, `*.jinja`, `*.jinja2`); and Go sources whose
  path contains `crd` (in any case), except `_test.go` files. In a Go source,
  the gzip-compressed string literals (`[]byte("\x1f\x8b...")`, as generated
  sources such as Velero's `config/crd/v1/crds/crds.go` hold the definitions
  `velero install` applies) are decompressed, with bounds, and read like YAML
  files: the file is a `copy`, `extra` or `conflict` like any other, and a
  literal that cannot be read is `unread`. Definitions held as other encoded
  bytes (base64, byte-slice literals, other compressions) are not read
  (`notRead`). A packaged Helm
  chart (`*.tgz` in a directory named `charts`) is not read and is recorded as
  unsupported. YAML and JSON files that contain the word
  `CustomResourceDefinition` anywhere, Helm `Chart.yaml` files and
  kustomizations are decoded in the strict subset; a definition is found
  whatever its YAML form (block or flow style, the value of `kind` on the next
  line). A templated YAML file is read by the template rules below. Each
  file is placed in one of three **locations**: the open tree; a
  **default-excluded directory** (a path segment named `test`, `tests`,
  `testdata`, `_testdata`, `e2e`, `example`, `examples`, `vendor` or
  `third_party`), whose content a project does not normally install; or a
  **reviewed exclusion** of the table. Each file with CRD-like content, and each
  file that names another repository's definitions, is classified:

  | Class | Meaning |
  | --- | --- |
  | `copy` | every definition in it is in the inventory with the same versions and `served` flags |
  | `schema-patch` | a kustomization whose only mentions of the kind are patch targets, each patch (a file, or a string given inline under `patch`) a JSON 6902 list whose every operation path lies under `/spec/versions/N/schema/`, `/spec/conversion`, at `/spec/preserveUnknownFields` or under metadata labels and annotations, or a `crd-patch` fragment (below) of listed definitions; an inline patch that is a mapping or a strategic merge string keeps the file a `reference` |
  | `crd-patch` | a kubebuilder strategic merge patch fragment (`webhook_in_*.yaml`, `cainjection_in_*.yaml`) below a declared definition kustomization directory: every document is an `apiextensions.k8s.io/v1` or `v1beta1` `CustomResourceDefinition` of a listed definition with nothing but `metadata.name`, metadata labels and annotations, `spec.conversion` (strategy, webhook client configuration, review versions) and `spec.preserveUnknownFields`, each of its known shape; a template, any other key (`spec.versions`, `spec.version`, `spec.group`, a `$patch` or `$retainKeys` directive, ...) or a definition the listed paths do not hold leaves the file `unread` |
  | `kustomize-config` | a kustomize transformer configuration (`kustomizeconfig.yaml`) below a declared definition kustomization directory that holds only `nameReference`, `namespace`, `varReference`, `commonLabels` and `commonAnnotations`, in which every field spec of the kind names the `apiextensions.k8s.io` group, and it and every field spec without a kind a path under `spec/conversion` or metadata labels and annotations; otherwise the file stays a `reference`. Every configuration a kustomization below such a directory names (`configurations`), and every `kustomizeconfig.yaml` there, is read even when it never contains the kind name (a field spec without a kind applies to every kind); one that cannot be read or has an unchecked field spec is a `reference` |
  | `legacy-copy` | every definition in it is strictly read, at least one is an `apiextensions.k8s.io/v1beta1` definition (versions from `spec.versions` with `served` and `storage`, the first equal to `spec.version` when both are given, or from `spec.version` alone, served and stored; exactly one storage version), and every one is in the inventory with the same group, kind, versions and `served` flags; a v1beta1 definition with other versions or flags is a `conflict`, one not in the inventory `extra`, an incomplete one `unread` |
  | `templated-copy` | a templated file in the open tree, a default-excluded directory or a reviewed exclusion that does not declare copies, whose rendered versions its literal lines determine (see below) and which, read that way, is a copy; recorded with its definitions and the members they serve |
  | `pre-patch-copy` | a file under a reviewed exclusion with `prePatch` whose rendering the scan accepted (see below): with the kustomization's patches applied, its definitions are listed ones with the same versions and `served` flags; recorded with its definitions, the members they serve and, in the detail, the operations applied to each |
  | `pre-patch` | the kustomization named by such an exclusion, when its rendering is accepted |
  | `conflict` | it defines a CRD of the inventory with other versions or `served` flags |
  | `extra` | it defines a CRD that is not in the inventory |
  | `reference` | it holds the kind as a value (a nested object, a field, a manifest embedded in a string) but defines none at the top level, and is not a schema-only kustomization; a file that only mentions the word in a comment or a description is not a finding |
  | `unread` | it is not strictly decodable or over the bounds and holds the kind as the value of a `kind` key (on the same line or the next); a templated file that holds the kind and whose rendered versions cannot be determined, or whose top-level `apiVersion` or `kind` is an expression; a templated file outside a declared copy that is read but is not a copy (the comparison is in the detail); or a submodule |
  | `unsupported` | a template, jsonnet or cue source that holds the word, or a packaged Helm chart |
  | `go-defined` | Go code that builds a definition as a composite literal (`CustomResourceDefinition{ObjectMeta: ...}`, or of its spec, names or versions); its served versions are not read |
  | `external` | a Helm `Chart.yaml` with a dependency whose `repository` is another repository (`https://`, `oci://`, an alias such as `@repo`; not a local `file://` path or none), or a kustomization with a remote resource, component or base (a URL, `github.com/...`, `git@...`, `?ref=`) |
  | `excluded` | a file under a reviewed exclusion that does not declare copies, whose content is recorded (path, sha256, the definitions it holds) |
  | `excluded-unread` | the same, when its content could not be read |
  | `no-definition` | a YAML or JSON file under a reviewed exclusion with `"defines": "none"` that, at this release, is within the size bound, holds no template syntax, is strictly decodable, has no document that is an `apiextensions.k8s.io` object, of the kind, a kustomization (kind `Kustomization` or `Component`, or a mapping with a resource, base, component, patch, configuration or replacement field) or names `dependencies`, no mapping at any depth that holds the kind as the value of any key and has a `spec`, and no string that holds a manifest line naming the kind; recorded with its sha256 (see below) |
  | `exclusion-void` | a reviewed exclusion that an install surface refers to at this release (see below); it blocks attestation |

  The effect depends on the class and the location:

  - `copy`, `templated-copy`, `schema-patch`, `crd-patch`, `kustomize-config`,
    `legacy-copy`, `pre-patch-copy` and `pre-patch`: none, anywhere.
  - `conflict` in the open tree: the pair is withheld when the release is a
    pair's first release; otherwise the pair's rules hold for the anchor pair
    only.
  - `unread`, `unsupported` or `go-defined` in the open tree, and `conflict`,
    `unread`, `unsupported` or `go-defined` among declared copies (with
    `copies` or `prePatch`): at the later
    line's first release the pair's rules are withheld (a version they forbid may still be served
    there); at another release of the later line the rules hold for the anchor
    pair only.
  - every other class in the open tree or among declared copies, and every
    class but those six under a default-excluded directory:
    the pair is not attestable.
  - `no-definition`: recorded; the pair stays attestable, and the file does
    not keep a definition from being established as gone.
  - any class under a reviewed exclusion with `"defines": "none"` (location
    `defines none: <entry>`), and `unread` there for a file that would
    otherwise not block or not be a finding: the pair is not attestable; the
    pair is never withheld and its rules are never narrowed because of it,
    but an opaque file there keeps a definition from being established as
    gone (as under a void entry).
  - `excluded` and `excluded-unread`: recorded; the pair stays attestable. An
    `excluded-unread` file keeps a definition from being established as gone,
    unless it also lies in a default-excluded directory (a test-fixture entry
    such as `test/e2e/manifests/`).
  - A templated YAML file that holds the word is read, in every location,
    only when its literal lines fix the versions it renders. It is checked
    line by line before it is decoded. Every action must be well formed: an
    action whose text holds `{{` or `}}` (such as `{{ if eq .x "}}" }}`, or
    literal text after an action that a later `}}` seems to close) makes the
    file `unread`. A line that holds nothing but one action is dropped, and
    is accepted only as a template comment in the form the template lexer
    reads (`{{/* ... */}}`, with `{{- ` or ` -}}` trim markers; `{{ /* ... */ }}`
    is not a comment), as an `if` around the whole file (on the first line
    that is not blank or a comment, its `end` on the last line that is not
    blank), or as an `if`, `with` or `end` line, or an `include` or `toYaml`
    line whose pipeline ends in `indent` or `nindent` by at least one column,
    inside a top-level `metadata` block (from a `metadata:` line at column 0
    to the next line at column 0 that is not blank or a comment), where
    every `if` and `with` must also end. An expression inside a line is
    accepted only in a top-level `metadata` block or in the `conversion`
    block of `spec`, and becomes a placeholder; a key whose whole value is
    an expression followed by more indented lines keeps those lines, in
    `metadata` only. The output of such an expression must be bounded: a
    release or chart name (`.Release.Name`, `.Release.Namespace`,
    `.Release.Service`, `.Release.Revision`, `.Chart.Name`, `.Chart.Version`,
    not inside a `with`, where the dot is another value), a field reference
    piped to `quote` (one line, its line breaks escaped), or a pipeline that
    ends in `indent` or `nindent` by at least one column, so no line of the
    output that a newline starts reaches column 0 and no `---` separator can
    appear. The text an `include` or a value renders is not read: `indent`
    pads only after a newline, so a carriage return or a Unicode line
    separator in that text is not bounded. A chart whose named templates or
    default values hold such a line break is outside what the scan
    establishes. An inline `include`,
    `tpl`, `toYaml`, `.Files.Get` or `.Values` reference without them may
    render any text, including a further definition, and is not read
    (kueue's chart, which names its webhook service with an inline
    `include`, is `unread`). Anything else also makes the file `unread`: an
    `else`, `range`, `define`, `template` or `block`, a variable assignment,
    a directive or expression anywhere else (a condition around a version
    entry, a templated `served` flag or `spec.versions`), a directive that
    trims the line break after it other than on the last line or on the
    first line that is not blank when the next line that is not blank starts
    at column 0 (as in `{{- if .Values.crds.enabled -}}` before a `---`
    line, where nothing is joined), an expression that trims a line break, an
    `indent` or `toYaml` expression in `spec.conversion`, or an expression
    left open across lines. Once decoded, a placeholder in a document's
    `apiVersion` or `kind`, in a definition's `metadata.name`, in its `spec`
    when that is not a mapping, or anywhere in its `spec` but
    `spec.conversion` also makes it `unread`, and what remains must be
    `apiextensions.k8s.io/v1` definitions. Outside a reviewed exclusion that
    declares copies, a file read this way that is a copy is `templated-copy`;
    one that is not is `unread`, never a `conflict` or `extra`, since nobody
    has claimed it is a copy.
  - A reviewed exclusion with `copies` (chart templates of the listed
    definitions) is checked: each file is read by the template rules above
    and must define only listed CRDs with the same versions and `served`
    flags. A copy is listed under `copies`, a file that serves other versions
    is a `conflict`, one that defines another CRD is `extra`, and one that
    cannot be read is `unread`.
  - A reviewed exclusion with `prePatch` (a directory prefix, such as Elastic
    Cloud on Kubernetes' `config/crds/v1/resources/`, which
    `kubectl kustomize config/crds/v1/patches` renders into the listed
    `config/crds/v1/all-crds.yaml`) states that its files are the listed
    definitions before the patches of the named kustomization apply. Its
    files keep their classes, as among declared copies, unless the scan
    accepts the rendering at the release, which it does only in this exact
    shape:
    - the named kustomization, strictly decoded, has exactly the keys
      `resources` and `patches` (no inline patch, `patchesStrategicMerge`,
      `replacements`, `components`, `commonLabels`, `namePrefix`, ...); its
      one resource is a local path to the entry's directory; each patch
      entry has exactly a `target` (group `apiextensions.k8s.io`, version
      `v1`, kind `CustomResourceDefinition` and a definition name whose only
      regular expression characters are its dots and which, anchored as
      kustomize anchors it, matches no other definition of the resources)
      and a `path` to a file inside the kustomization's directory;
    - the `kustomization.yaml` of the entry's directory, strictly decoded,
      has exactly the key `resources`, each a file of that directory; they
      are every file under the entry that holds the kind, and each holds
      `apiextensions.k8s.io/v1` definitions only, strictly read;
    - every operation of every patch file is one a `schema-patch` may hold,
      or an `add` at `/spec/versions/-` of a version the definition does
      not list yet, with a valid name, `served: false` and `storage: false`
      as booleans and nothing but a `schema` besides; any other operation,
      a templated patch, or a target that no resource defines refuses the
      rendering;
    - with the patches applied in order, the definitions are those of the
      inventory: the same names, and the same group, kind, versions and
      `served` flags for each.

    When the rendering is accepted the resource files are `pre-patch-copy`
    and the kustomization is `pre-patch`. Otherwise nothing changes: a
    resource that lacks the added version stays a `conflict`, and a
    kustomization that is a `reference` says in its detail why the rendering
    was refused. The loader refuses `prePatch` together with `copies`, on a
    file or pattern entry, when it is not the clean path of a kustomization,
    lies under the entry or a listed path, or the target has install
    channels or a `remote` source.
  - A reviewed exclusion with `"defines": "none"` (such as a discovery list
    or an ignore list that names the kind and that a Go program embeds)
    states that its files define no CRD. The scan checks that claim for each
    file at every release: a YAML or JSON file for which every condition of
    `no-definition` holds is of that class, whatever else it holds (a
    mapping that names the kind without a `spec` is not a `reference`
    there). Any other file there is classified as in the open tree and keeps
    its class, located `defines none: <entry>`; a file that would then not
    block attestation (a copy, a `schema-patch`, ...) or not be a finding at
    all is `unread` with the failed condition in its detail. The loader
    accepts only the value `none`, and refuses it together with `copies` or
    `prePatch`, on a directory prefix, on a file or pattern whose last
    element does not end in `.json`, `.yaml` or `.yml`, and on a name (or a
    pattern that matches a name, in lower or upper case) `kustomization.yaml`,
    `kustomization.yml`, `Kustomization`, `Chart.yaml`, `requirements.yaml` or
    `values.yaml`, or when an earlier entry covers it. Such an entry is not
    a declared copy: it may not lie under an install directory, and it is
    guarded (below), except against `//go:embed`. A definition encoded in a
    string (base64, compressed) that a program decodes is not read: that
    part of the claim rests on the reviewer's evidence.

  **Reviewed exclusions carry evidence and are guarded.** Every entry of the
  table names its repository, the path (a directory prefix ending in `/`, one
  file or a pattern whose wildcards are in the last path element only), the
  reason the files are not installed and the evidence a reviewer read, and the
  claim must hold at every release of the window. An
  entry that is not a declared copy (`copies` or `prePatch`) may not lie under a chart, deploy,
  deployment, install or installation directory, below a `config/crd` or
  `config/crds` directory, or below a top-level `manifests` directory (the
  loader refuses it), and never covers a listed path. At each release the
  **install-surface guard** checks the part of the claim a program can: an
  entry with files at the release is void for that release when
  - the entry lies under a Helm chart (a directory with a `Chart.yaml`);
  - a kustomization (resources, bases, components, patches, generators, any
    path-like word, followed from every kustomization outside the excluded
    paths through the kustomizations they name) or a Helm `Chart.yaml` or
    `requirements.yaml` (local `file://` dependencies) refers to a path under
    it;
  - a Makefile command line of a target that is not a test target
    (`test`, `e2e`, `lint`, `check`, `verify`, `conformance`, `integration`,
    `bench`, `smoke`, `fuzz`, `coverage`, `unit`, unless the name also says
    `install`, `deploy`, `setup`, `apply`, `bootstrap`, `provision`, `release`
    or `up`: `verify-install` installs) runs `kubectl`, `kustomize`, `helm` or
    a similar tool on a path under it, directly or through a variable;
  - a document (`*.md`, `*.mdx`, `*.rst`, `*.adoc`, `*.txt`) or a shell script
    (`*.sh`, `*.bash`), outside `vendor`, `third_party` and `node_modules`, has
    a command line that runs such a tool on a path under it;
  - a container build (`Dockerfile*`, `Containerfile*`, `*.dockerfile`,
    `Earthfile`) copies a path under it (`COPY` and `ADD` sources, Earthfile
    `SAVE ARTIFACT` sources), read from the repository root and from the
    build file's directory; a copy of the whole context (`COPY . ...`) or of
    a source directory above it (build stages copy `cmd/`, `internal/` to
    compile) is not followed;
  - a nix file names a path under it;
  - it lies under a ko `kodata` directory (packed into the image), or a
    symbolic link lies inside a `kodata` directory;
  - a Go package in a directory above it, or inside it, embeds a file under
    it (`//go:embed`); not for an entry with `"defines": "none"`, whose files
    are checked to define nothing at every release (a program that embeds
    such a file installs no definition from it).

  **Dev-only Makefile targets.** A target file may list `devOnlyMakeTargets`:
  Makefile targets a reviewer states exist for development only (a local lab
  cluster), each with the `makefile` (the clean repository path of a Makefile),
  the `target` (a plain name: letters, digits, `_`, `.`, `-`, no leading dot or
  dash, up to 128 characters, never a name that says `install`, `deploy`,
  `setup`, `apply`, `bootstrap`, `provision`, `release` or `up`), and a
  `reason` and `evidence` bounded like an exclusion's. The loader refuses a
  listed pair twice. Such an entry loosens the guard, so the target guard lists
  every added pair as a narrowing that needs a reviewed removals entry
  (`devOnlyMake:<makefile>:<target>`); removing an entry, or rewording its
  reason or evidence, needs none, and a new target admitted by an onboarding
  batch may not list any.

  The entry is **applied** at a release only when the files of that release
  show the target is reached from nowhere else. It is not applied when any of
  these holds, and then the exclusion is void exactly as without the entry:
  - the Makefile is missing, unread, or has no rule header that names the
    target; or a `GNUmakefile`, `makefile` or `Makefile` next to a Makefile of
    that name could be read instead;
  - the target name occurs as a word in any Makefile, shell script or
    container build of the release, except in its own rule headers and recipe
    lines in the listed Makefile, in the header of a rule whose every target
    is one of the GNU special targets whose prerequisites are never built as
    goals (`.PHONY`, `.SUFFIXES`, `.PRECIOUS`, `.INTERMEDIATE`,
    `.NOTINTERMEDIATE`, `.SECONDARY`, `.SECONDEXPANSION`, `.DELETE_ON_ERROR`,
    `.IGNORE`, `.LOW_RESOLUTION_TIME`, `.SILENT`, `.EXPORT_ALL_VARIABLES`,
    `.NOTPARALLEL`, `.ONESHELL`, `.POSIX`; not the recipe of such a rule), and
    in a rule whose every target is itself an applied entry. Any other name
    that starts with a dot (`.lab`) is a normal rule. Lines that are comments
    (`#` first) are not words. Files under an excluded path or a vendored
    directory (`vendor`, `third_party`, `node_modules`) are read for this
    check although the guard's own checks leave them out. A document that
    names the target does not void the entry: the proof lists it;
  - a Makefile, shell script or container build line runs `make`, `gmake`,
    `$(MAKE)` or `${MAKE}` with a word that holds `$` or `%` (the name may be
    built at run time) or that selects the makefile (`-f`, a cluster of short
    options ending in `f`, `--file`, `--makefile`);
  - a rule of a target that is not an applied entry has a prerequisite word
    that may expand to the target name. A word with variable references is
    expanded over-approximately: each `$(V)`, `${V}` or `$V` (a plain name) is
    replaced, recursively (depth 8, 256 expansions per word, at most 256
    results), by every value assigned to `V` in any Makefile of the release,
    split into words; a variable assigned in no Makefile (`PWD`, `CURDIR`, the
    environment) is a wildcard that matches any string without white space.
    The prerequisite is safe when no result can equal the name. A function
    call, a substitution reference, an automatic variable, `$$`, a variable
    set with `define` or `!=`, a cycle, a bound, a `%` and a target-specific
    assignment are not read, so the entry is not applied. A value given at the
    command line or the environment to a variable the Makefiles assign is not
    seen;
  - an `include`, `-include` or `sinclude` operand is not a literal, clean
    path of a Makefile that was read; an include precedes the first rule while
    no `.DEFAULT_GOAL` is set; the target is the default goal; `.DEFAULT_GOAL`
    occurs anywhere but in an assignment of a non-empty literal value (a
    recipe, rule form, an empty or computed value); the first rule's target
    (a name starting with a dot counts when it holds a `/`) holds a variable or
    `%`; or
    `.RECIPEPREFIX` occurs in a Makefile;
  - a file over the bounds of the check (more than 50000 distinct words, or
    5000 rules or includes), or an install surface the guard cannot check, at
    that release.

  The entries of a target are decided together, as the greatest set in which
  every entry holds (all start applied, the ones that fail are dropped, and
  this repeats), so two entries can be each other's prerequisite. For an
  applied entry the Makefile check leaves out the recipe lines of that
  Makefile whose every target is an applied entry; a rule that also has another
  target, the same name in another Makefile, a recipe after a `define`,
  `endef`, `include` or `.RECIPEPREFIX` line (these end the rule above them),
  and every other referrer still void the exclusion. The scan record has a
  `devOnlyMake` member (absent for a target with no entry): per entry the
  Makefile, target, whether it is applied, why not, the references of an
  excluded path it left out (the exclusion and the word of the recipe line),
  and the documents that name the target (at most 20). Nothing is withheld
  because of it.

  A void entry (also one with `"defines": "none"`) is treated like a
  default-excluded directory at that release,
  with the location `void: <entry>`: its files are classified (Go sources
  under it are read too), block attestation and never withhold a pair or
  narrow its rules, but an opaque file there still keeps a definition from
  being established as gone. A finding of class `exclusion-void` names the
  referrer, so the release, and every pair that reads it, is not attestable.
  Not followed, and listed in every scan's `notRead`: symbolic links, CI
  configuration, other scripts and build systems (Bazel, Tilt, ko
  configuration), a container build that copies its whole context and selects
  files while it runs, and Go code that opens a path at run time. Go sources
  under a reviewed exclusion are not read for definitions, only for
  `//go:embed` directives. Declared copies (`copies` or `prePatch`) are not
  guarded: they are install surfaces by nature and are checked file by file
  instead.

  A file with the same git blob id (and kind) as one already read is not read
  again; what the scan concludes from the bytes never depends on the path they
  were read at, so the result is the same at any read concurrency.

## What it claims

A version is **no longer served** in the later line when some release of the
earlier line lists it with `served: true` and no release of the later line
serves it (it is absent, or listed with `served: false`). For each CRD with
such versions the extractor emits one rule:

- id `<project>.crd-version-removal.<crd name>.<from>-to-<to>` (the anchors),
  where the CRD name has each `-` written as `--` and each `.` as `-`, and the
  versions have dots as hyphens; two rules of one pair that would still share
  an id withhold the pair;
- operator `forbid_set_member` over the proposed-side set fact
  `component.<project>.custom_resource_versions_set` (for Argo CD
  `component.argo_cd....`), whose members are `group/version/Kind`; the rule
  forbids the versions no longer served;
- subject: the project's catalog component and the anchor transition, and —
  when the rule holds for both whole lines (below) — a **range** over them:
  - consecutive minor lines `M.m-1 -> M.m`: from `[M.(m-1).0, M.m.0)`, to
    `[M.m.0, M.(m+1).0)`, bounds `PREVIOUS_MINOR_LINE`, `REMOVED_IN_RELEASE`
    (twice) and `TARGET_SERIES`, so the engine knows the release boundary;
  - a new major or skipped minor numbers: each whole line, bounds
    `UPGRADE_FROM_SERIES` (twice) and `TARGET_SERIES` (twice);
- next action: `change apiVersion of <Kind> to <group>/<version> before
  upgrading to <To>`, naming the highest version the later anchor serves, or
  `migrate <Kind> objects before upgrading to <To>` when it serves none. When a
  removed version was the CRD's storage version at any release read (see
  `storageHistory`), objects may still be stored in it and it stays in the
  CRD's `status.storedVersions`, and an API server refuses a definition that
  drops a stored version; the next action then says so first: `migrate stored
  <Kind> objects to <version> and remove <removed versions> from
  status.storedVersions, then change apiVersion to <group>/<version> before
  upgrading to <To>` (or the same without a replacement version);
- sources (each with the whole-file sha256 of the bytes read):
  `crd-versions-<release>`, the lines of the removed version entries at the
  earlier anchor (or, for a version only a later earlier-line release served,
  at the highest such release); and either `crd-<to>`, the whole CRD file at
  the later anchor when a version is absent from it, or
  `served-false-<version>-<to>`, the `served: false` line of each version the
  later anchor still lists. Every range bound cites one of them.

A rule holds for **both whole lines** only when every release of both lines
was read completely, no release holds a conflicting copy, every CRD keeps its
group and kind, no version that some earlier-line release serves is served by
some later-line releases and not by others, no release of the later line drops
a definition its first release holds, and no release of the later line holds an
unread, unsupported or Go-defined CRD source (or a declared copy serving other versions). Otherwise the pair's rules are
derived from the two anchors only, carry no range, and match only the anchor
transition. (Cilium 1.20.2 serves CiliumNodeConfig `v2alpha1` again after 1.20.0
and 1.20.1 dropped it, so that rule holds for 1.19.0 -> 1.20.0 only.)

A CRD that the earlier line defines and the later anchor defines nowhere — not
under the listed paths, and with a complete scan in which no file defines it
and every CRD-like file outside the default-excluded directories (and outside the reviewed exclusions that do not lie in one) was read — is recorded under `definitionsRemoved` and is
**not** a rule: whether the old definition is kept (`kubectl apply`, Helm
`crds/`) or deleted with every object of it (Helm templates, Argo CD or Flux
pruning) depends on the install method and is not established. Otherwise the
definition may have moved, and the pair is withheld. A CRD that the later
anchor defines and a later release of its line defines nowhere is recorded the
same way (with the releases that lack it); the pair's rules then hold for the
anchor pair only.

Each rule's test vectors (blocked, pass-complete, unknown-incomplete) are
evaluated through the engine before anything is written.

## Proof recorded in the manifest

For every pair, `manifest.json` records under `pairs[].proof`:

- `target` and `factId`;
- `from` and `to`, the complete inventory of each anchor: `tag`, `commit`,
  `complete`, `problem` (when incomplete), `paths` (each listed path: `file`,
  `directory` or `missing`, files read and directory entries ignored), `files`
  (path, `sha256:` digest of the whole file, size, lines, documents, CRDs,
  other documents), `crds` (each with `name`, `group`, `kind`, `plural`,
  `scope`, `path`, `document`, `startLine`, `versionsLine`, `storageVersion` and
  `versions`, each with `name`, `served`, `storage`, `startLine`, `endLine`,
  `servedLine`, `storageLine`) and `scan` (`complete`, `problem`, `files` read
  and how many of them lie under a default-excluded directory
  (`defaultFiles`) or a reviewed exclusion (`excludedFiles`), the default
  segments and reviewed entries that hold a file (`exclusions`), the kinds of
  files the scan does not read (`notRead`), the `copies`, and every other
  finding with `path`, `sha256`, `class`, `location`, `crds`, the members its
  definitions serve (`served`) and `detail`);
- `lines`: for each of `from` and `to`, the `line` and each release (`tag`,
  `commit`, `complete`, `problem`, `crds`, the served members `added` and
  `dropped` relative to the line's first release, `scanClean` and
  `scanFindings`); `lineWide`, and `notLineWide`, why the rules hold for the
  anchor pair only;
- `removals`: each version no longer served (`crd`, `member`, `version`,
  `reason` `absent` or `unserved`, `fromTag`, `fromPath`, `fromStartLine`,
  `fromEndLine`, `toPath`, `toServedLine`, 0 when absent, and `wasStorage`);
- `storageChanges`: each CRD whose storage version differs between the anchors
  (`crd`, `from`, `to`);
- `definitionsRemoved`: each CRD a release of the later line defines nowhere
  (`crd`, the `members` served before, `fromTag` and `fromPath` of the latest
  release before that defines it, and `absentAt`, the later-line releases
  without it); for a CRD the later line's first release no longer defines,
  `successor` names the one definition of that release with the same kind and
  plural under another API group (a renamed group), when there is exactly
  one and no release of the earlier line defines it. It is recorded only: the
  completeness reason adds that a definition of the kind exists under the new
  name and that whether objects are converted is not established; it is never
  a rule (the old group's members get none) and the pair stays not
  attestable;
- `storageHistory`: for each CRD, every storage version it has at the releases
  read;
- `unlistedRemovals`: each version that a definition outside the listed paths
  (an `extra` file, such as Rook's `deploy/examples/csi-operator.yaml`) serves in
  the earlier line and that no file of the later line serves (`member`,
  `fromTag`, `path`); recorded, never a rule;
- `completeness`: `declared` (every listed path read completely at every
  release of both lines), `scan` (the full-tree scan clean at every release),
  `lineWide`, `hop` (`previous-minor` for `M.(m-1) -> M.m`, `major` or
  `skipped-minor`), `attestable` (declared, scan and line-wide, a
  `previous-minor` hop, and no removed definition) and the `reasons` when not.

`completeness.attestable` is the account a line attestation of the later line
rests on (see below). It means
complete for the repository's own files at every release of both lines, as the
scan reads them: CRDs that come from other repositories (Helm chart
dependencies, remote kustomize resources) make the pair not attestable when the
scan sees them, and CRDs from release assets, from sources the scan does not
read (`notRead`) or installed by code at run time are not established.

## Line attestations

From version 2.1.0 the extractor attests lines for the fact family
`crd.custom_resource_versions` (see [../line-attestations.md](../line-attestations.md)).
For a derived pair it writes one attestation of the later line exactly when:

- `completeness.attestable` holds (every release of both lines read
  completely, a clean full-tree scan at each, rules over both whole lines, no
  removed definition);
- the later line is the next minor line of the same major (a new major or a
  skipped minor number is not attested: the family's hop shape is one minor
  line);
- the target has `"attest": true` in its target file, which a test pins to the
  CNCF catalog projects of the custom-resource table (the projects whose set
  fact is registered and whose line reviews the family admits): today Argo
  CD, Istio and Strimzi. A community target never attests.

The attestation lists exactly the pair's rules (empty for a quiet line),
names in `releases` every final release of both lines with the commit its tag
pointed at, and cites one CustomResourceDefinition manifest at each first
release. It has the rules' provenance and lease. Otherwise the manifest records
`"attestation": {"status": "not-attested", "reason": ...}` for the pair.
`run` writes the attestations to `attestations.json`, which `verify` covers;
the knowledge gate admits one only by re-deriving it byte for byte.

These field names are stable within major version 2.

## What it never claims

- A removal when either anchor cannot be read completely (any listed path
  missing that is not optional, a listed directory without a matching file, a
  templated or not strictly decodable file, a `List` document, a CRD of an API
  version other than `apiextensions.k8s.io/v1` or incomplete — no versions,
  flags that are not booleans, not exactly one storage version, a name that is
  not `<plural>.<group>` — two documents defining the same CRD or kind, more
  than 512 CRDs or 64 versions of one CRD), when a CRD changes group or kind,
  when an anchor holds a conflicting copy, or when a definition disappears
  without a clean scan. The pair is then withheld: no rule, and the manifest
  says why.
- Anything about storage versions (recorded only, and named in the next
  action), stored objects, conversion webhooks, schema or field changes inside
  a version, kustomize patches other than schema-only JSON 6902 patches, CRDs
  that are only shipped templated (Helm charts) or only as release assets, or
  CRDs other than those under the listed paths.
- Anything about the definitions of another repository: a Helm chart
  dependency or remote kustomize resource is found, never read.
- That a repository holds no other definition where the scan does not look:
  files of other kinds, Go sources whose path does not contain `crd` (or that
  build a definition in another way than a composite literal, or hold it as
  encoded bytes other than gzip string literals), symbolic links, or CRDs that
  a program generates or installs at run time.
- Anything about a removed definition (recorded only).
- That an upgrade is safe: a PASS from these rules only says that a complete
  declared set of custom-resource versions holds none of the versions no
  longer served.

`component.<project>.custom_resource_versions_set` is registered for the
projects of the custom-resource table, and `check cncf --custom-resources` and
`scan` declare it from rendered manifests (see
[../custom-resources.md](../custom-resources.md)). No rule is shipped yet. They
are the first set rules of the CNCF pack, so the first change that publishes
any of them raises the pack's schema level as well; the knowledge gate never
admits a schema change on its own, so that change is reviewed.

## Running and verifying

```
prufyx-maintainer extract run    --extractor crd.version-removal.strimzi --mirror-state DIR --out OUT [--derived-at 2026-10-04T00:00:00Z] [--concurrency N]
prufyx-maintainer extract verify --extractor crd.version-removal.strimzi --mirror-state DIR --out OUT
prufyx-maintainer extract oracle --extractor crd.version-removal.strimzi --out OUT --expected FILE
```

`run` writes `candidates.json`, `vectors.json`, `manifest.json` and `reads/`,
as for every extractor; `--concurrency` only bounds parallel reads during the
scan. The mirror must hold every file the scan reads at every release of the
lines; a run that misses one names it under `--wants-out` and exits 3.
`verify` re-derives from the pinned bytes with the recorded `derivedAt` and
fails unless every output file is byte-identical. The code digest is sha256
over the sorted lines `<dir>/<file> NUL <sha256> LF` of the non-test Go files
of `internal/extract` and `internal/extract/crdversions` and of the id's own
target file `target-<project>.json`, and of no other target file; the manifest
lists them. No derivation of one id reads another target: the other files are
read only to check, when the program starts, that no two targets name the same
project, fact, repository or component.

`oracle` compares a run with an expected-results file:

```json
{
  "removals": [{"from": "0.51.0", "to": "1.0.0", "member": "kafka.strimzi.io/v1beta2/Kafka", "reason": "absent"}],
  "rules": [{"name": "a reviewed rule", "from": "0.51.0", "to": "1.0.0", "members": ["kafka.strimzi.io/v1beta2/Kafka"]}],
  "storageChanges": [{"from": "0.51.0", "to": "1.0.0", "crd": "kafkas.kafka.strimzi.io", "fromStorage": "v1beta2", "toStorage": "v1"}],
  "pairs": [{"from": "1.0.0", "to": "1.1.0", "status": "derived", "removals": 0, "lineWide": true, "attestable": true}]
}
```

Every listed removal must be derived with the same reason and forbidden by a
rule; every rule's members must be forbidden on its transition; every listed
storage change must be recorded; every listed pair must have the given status
and, when given, number of removals, `lineWide` and `attestable`. When removals
(or storage changes) are listed, any other one the run derives is reported as
`EXTRA`. The exit code is 1 when there is any disagreement.

## Per-id code digests

The target table was one file, `targets.json`, covered by the code digest that
every id shared, so any change to one target moved every id's digest. It is
now one file per target, covered by its own id's digest only. The code of the
extractor and its version are unchanged, as are rules, vectors,
candidates and attestations, except that every id's code digest differs once
from the digest it carried before.

Records already published keep the digest they were derived with and are not
touched by this change. The knowledge gate re-derives a mechanical rule or a
line attestation that a change adds or modifies, and refuses it unless it
names the extractor id, version and code digest of the build that runs the
gate. So the first rule or attestation of a project changed after this
version must come from a full run of that project's id with this build (which
then carries the id's own digest), not from an edit of a record that carries
the old shared digest. From then on, a change to one target only requires
re-deriving the records of that target's id.
## Changes from version 2.6.0

Version 2.9.0 adds the `devOnlyMakeTargets` member of a target file and the
`devOnlyMake` member of the scan record (above). It loosens the guard for an
entry that uses it, at a release where every condition holds, and for no other
file or target: output is unchanged for every target without the member, except
the extractor version and the code digest. A `define`, `endef`, `include`,
`-include`, `sinclude` or `.RECIPEPREFIX` line in a Makefile now ends the rule
above it, so a tab line after one is no longer attributed to that rule (and no
longer skipped as the recipe of a test target): this can only void an exclusion
that was not void before.

## Changes from version 2.5.0

Version 2.6.0 adds the `defines` member of a reviewed exclusion (the one
value `"none"`) and the class `no-definition` (above). It loosens the scan
for an entry that uses it: the install-surface guard no longer voids it for a
`//go:embed` directive, and a file that names the kind without defining a CRD
no longer blocks attestation there, while every condition is checked at every
release. No target uses it in this version: output is unchanged for every
target and file, except the extractor version and the code digest.

## Changes from version 2.4.0

Version 2.5.0 adds the `prePatch` member of a reviewed exclusion and the
classes `pre-patch-copy` and `pre-patch` (above), and reviews Elastic Cloud on
Kubernetes' `config/crds/v1/resources/` with it: its resource files, which lack
the unserved `v1alpha1` the patches add, were conflicts in the open tree and
withheld its pairs. A kustomization patch given inline as a string is read like
a patch file, so a kustomization whose inline patches only touch metadata
labels (Percona's PostgreSQL operator) is `schema-patch` instead of a
`reference`; that project's 2.9 to 3.0 pair stays withheld, since another
patch of those kustomizations writes a scratch path (`/work`) the scan does not
accept. A removed definition records its `successor` under a renamed API group.
The tag prefix `knative-v` is accepted. Output is unchanged for every target
and file none of these applies to, except the extractor version and the code
digest.

## Changes from version 2.3.0

Version 2.4.0 reads templated YAML files in every location, not only under a
reviewed exclusion that declares copies, by the stricter template rules
above: a template whose literal lines fix its rendered versions and that is a
copy of the listed definitions is `templated-copy` and does not block; one
that is not a copy is `unread`. Templated declared copies are read by the
same rules, so a form the earlier reader accepted (a condition that never
ends, a directive under `spec`, an expression outside `metadata` and
`spec.conversion`, an inline `include` or `.Values` reference whose output
is not bounded) is now `unread`. A templated file whose top-level
`apiVersion` or `kind` is an expression is `unread` instead of not being a
finding. Go code that builds a definition is `go-defined` instead of
`unsupported`, with the same effects. Rules, vectors and candidates of a scan
where none of these applies are unchanged except for the extractor version
and code digest.

## Changes from version 2.2.0

Version 2.3.0 reads a `{{` in a CRD schema description as documentation
(above), adds the `remote` member (a per-line source switch to another
repository) and the `declaredChannel` and `channels` members (install
channels) of `targets.json`, and starts Kong Ingress Controller's
`config/crd/ingress-controller` source at 3.4 and Gateway API's experimental
channel. Output is unchanged for every target without those members and every
file without `{{`, except the extractor version and the code digest.

## Changes from version 2.1.0

Version 2.2.0 reads the kubebuilder scaffolding next to a project's generated
definitions and its legacy copies: the classes `crd-patch`,
`kustomize-config` and `legacy-copy` above, and kustomization patches that are
`crd-patch` fragments or JSON 6902 operations on the conversion settings. A
**declared definition kustomization directory** is a directory other than the
repository root holding a kustomization whose local `resources` or `bases`
name a file of the listed paths at that release, or a directory that holds
one (`config/crd` for `config/crd/bases/...`); fragments and transformer
configurations anywhere else stay `unread` or `reference`. Before 2.2.0 these
files were `unread` (fragments, v1beta1 copies) or `reference`
(configurations) and kept every pair of the project from being attestable.
Rules and vectors are unchanged; the scan records of the inventory and the
completeness of a pair change where such files exist.

## Changes from version 2.0.0

Version 2.1.0 adds the line attestations above and the `attest` member of
`targets.json`. Rules, vectors and candidates are unchanged except for the
extractor version and code digest.

## Changes from version 1

Version 1.0.0 read only the two `X.Y.0` tags of a pair, had no range and no
full-tree scan, kept its three targets in Go, withheld every pair in which a
CRD left the listed paths, and refused Argo CD's definitions (nested deeper
than 32 levels). Version 2.0.0 reads every release of both lines, adds the
range, the scan, optional and recursive paths, two tag prefixes, the data-file
target table and nine projects; its rules have new evidence (version and code
digest) and ranges, so rules of version 1 do not re-derive.
