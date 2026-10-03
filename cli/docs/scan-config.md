# Repository declaration file: `prufyx.yaml`

A repository can keep a small file named `prufyx.yaml` that records the inputs,
versions and declarations a scan would otherwise take from command-line flags.
This page describes the file format.

The `scan` command that reads this file is not available yet. The format and
its checks are fixed now so files written today keep working; this page will
say so when the command ships.

## Example

```yaml
apiVersion: prufyx.io/v1alpha1
kind: ScanConfig
inputs: [rendered/]
current: {kubernetes: 1.27.16}
target:  {kubernetes: 1.30.4}
declarations:
  kubernetes:
    distribution: official_upstream
    resourceScopeComplete: true
    targetApplyRequired: true
```

## Keys

The schema is closed: an unknown key anywhere is an error, and a misspelled key
is never ignored. The file holds exactly one YAML document.

| Key | Required | Meaning and allowed values |
| --- | --- | --- |
| `apiVersion` | yes | Exactly `prufyx.io/v1alpha1`. |
| `kind` | yes | Exactly `ScanConfig`. |
| `inputs` | no | 1 to 64 paths of manifests or directories to read. Each is relative to the directory of the file, in clean form (no `..`, no `./` prefix, no empty or doubled slashes, not absolute). One trailing slash is allowed (`rendered/`). |
| `current` | no | Map from project name to the version in use now. |
| `target` | no | Map from project name to the version you plan to move to. |
| `declarations.kubernetes.distribution` | no | `official_upstream` or `custom_build`. Same as `--distribution`. |
| `declarations.kubernetes.resourceScopeComplete` | no | `true` or `false`: the supplied resources are the complete set. Same as `--resource-scope-complete`. |
| `declarations.kubernetes.targetApplyRequired` | no | `true` or `false`: the resources are required for applying to the target API. Same as `--target-api-apply-required`. |

Versions are plain `X.Y.Z` numbers written as text, with no leading zeros, no
`v` prefix and no suffix. `1.27`, `v1.27.16`, `01.2.3` and `1.29.3-eks-adc7111`
are all rejected. Project names are the names shown by
`prufyx catalog cncf`; an unknown name is an error that names the key.
Declarations exist for `kubernetes` only; another project under `declarations`
is an error.

A declaration you leave out stays unset. Prufyx never fills in `true` for a
missing declaration, so the check it controls cannot pass on a guess.

## Precedence

A command-line flag overrides the same key in the file, key by key. A key that
neither supplies is unset. The result records, for every value, whether it came
from the file or from a flag.

## What is refused

- Anything but a regular file: symlinks, directories and standard input are not
  accepted as the configuration file.
- A file larger than 64 KiB.
- A file that group or other users can write. The stricter mode, which also
  refuses files readable by group or other users, files owned by someone else
  and files with several hard links, can be selected where the command offers it.
- Template syntax (`{{` or `${`) anywhere in the file, YAML anchors, aliases,
  merge keys, custom tags, keys that are not text, duplicate keys, and keys that
  differ only in letter case. A configuration file is never templated.

Error messages name the offending key, never the file's contents.

## Digest

The digest of the file is `sha256:` followed by the SHA-256 of the file's exact
bytes. It identifies which file was used.

## Finding the file

When no file is named, the file is looked for as `prufyx.yaml` next to the
first input: inside it when the input is a directory, otherwise in the directory
that contains it. Parent directories are never searched. A missing file is not
an error.

Because the file itself has an `apiVersion` and a `kind`, a directory scan has
to leave it out of the manifests it evaluates; it is recognised by the exact
pair `prufyx.io/v1alpha1` and `ScanConfig`.
