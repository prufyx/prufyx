# Quickstart

This gets you from a clean clone to a real **BLOCKED** verdict, with a
citation into upstream Kubernetes source, in under five minutes. It uses the
Kubernetes API-removal route, which is real, published, and checked in CI.

**Start with `prufyx scan`.** It is the command for rendered Kubernetes
manifests, and its report leads with the answer, the file and line of every
problem, and the fix. The [README quickstart](../../README.md#quickstart) runs
it first; section 7 below shows it on the same manifest. This guide starts with
`prufyx check`, which gives the same decision for one rule route with the full
upstream citation, and is the command for other projects' configuration.

Every command below was run from a fresh temporary directory to produce this
transcript. You can copy them as-is.

## 1. Build the CLI

From the `cli/` directory:

```sh
cd cli
go build -o /tmp/prufyx ./cmd/prufyx-community
```

(If your Go toolchain rejects VCS stamping outside a clean checkout, add
`-buildvcs=false`: `go build -buildvcs=false -o /tmp/prufyx ./cmd/prufyx-community`.)

## Finding your way around the CLI

`prufyx` (or `prufyx help`) prints a short overview of the commands grouped by
purpose. `prufyx <command> help`, `prufyx <command> --help`,
`prufyx <command> -h` and `prufyx help <command>` print the detailed usage of
one command, for example `prufyx help check`.

Help output is coloured (bold headings, highlighted command names) only when
standard output is a terminal. Report output is never coloured. Control it with
environment variables:

| Variable | Effect |
| --- | --- |
| `NO_COLOR` (any non-empty value, see https://no-color.org) | no colour |
| `PRUFYX_COLOR=never` | no colour |
| `PRUFYX_COLOR=always` | colour even when piped (overrides `NO_COLOR` and `TERM=dumb`) |
| `TERM=dumb` | no colour |

## 2. What the verdicts mean

Every `prufyx check` starts with one headline line: the verdict word, the counts
(must fix, undecided; a PASS also counts passed) and the scope. For UNKNOWN and BLOCKED a `checked:` line gives the passed count. Rules that decide something are
listed under it, grouped by the action they share. Rules that came back `PASS`
are counted, not listed (add `--show-passes` to list them). Sources, rule ids
and provenance are behind `-v`.

- **PASS**: the checked rules passed for that scope. Not a certificate that the
  rest of the upgrade is safe.
- **BLOCKED**: the input matches a reviewed, pinned source condition that the
  target release enforces. Exit `10`, so CI can gate on it.
- **UNKNOWN**: the input does not give Prufyx enough to decide (a required
  declaration is missing, the fact is outside what the rule reviews, or another
  rule in the set could not be evaluated). Exit `11`. **This is a feature, not a
  bug.** Prufyx never claims a scoped PASS from missing evidence, and it never
  claims a whole-upgrade PASS from a set of scoped PASS results.

[verdicts.md](verdicts.md) has the full page: what each answer means, what it
does not mean, and what to do.

## 3. A file, mode 0600

Every input file the `check` commands read must be **owner-only, mode 0600**
(`prufyx scan` is less strict by default: it refuses files other users can
write and only notes files they can read; see [scan.md](scan.md)). This is a
deliberate privacy control: the files you point Prufyx at (rendered
manifests, config, argv) can contain internal names, hosts, or other
operational detail, and Prufyx refuses to read anything a co-tenant on the
same machine, or a wider group, could also read. Create the file and lock it
down before running anything:

```sh
mkdir -p /tmp/prufyx-quickstart && cd /tmp/prufyx-quickstart
cat > applyset.json <<'JSON'
{
  "apiVersion": "v1",
  "kind": "List",
  "items": [
    {
      "apiVersion": "batch/v1beta1",
      "kind": "CronJob",
      "metadata": { "name": "nightly-report", "namespace": "default" },
      "spec": {
        "schedule": "0 2 * * *",
        "jobTemplate": {
          "spec": { "template": { "spec": { "containers": [{"name": "report", "image": "example/report:1.0"}], "restartPolicy": "OnFailure" } } }
        }
      }
    }
  ]
}
JSON
chmod 600 applyset.json
```

This is a `v1` `List` — the same shape `kubectl` produces from
`kubectl get -o json` across multiple resources, or that you would render
from a Helm chart or Kustomize build. It stands in for "everything this
apply is about to send to the API server." The `CronJob` inside it is still
declared at `batch/v1beta1`, the API version Kubernetes 1.25 stops serving.

If you forget the `chmod 600` step (for example the file is left at the
default umask, `0644`), the check now tells you exactly that:

```
$ prufyx check cncf --project etcd --native-resource applyset.json --from 3.5.17 --to 3.6.0 --now 2026-09-24T00:00:00Z --format json
prufyx: NATIVE_CNCF_RESOURCE_INPUT_INVALID: input file is readable or writable by group or others; prufyx requires owner-only permissions to protect its private contents; run `chmod 600 <file>` and retry
```

`--now` pins the evaluation time but never hides real-time expiry. When the
knowledge built into the binary has rules that ended after the pinned time and
before the real date, `prufyx check cncf` (also `check project` and `check batch`) prints a warning on standard error naming the pinned
`--now`, today's date and the number of rules that expired. A check that passed at the pinned time is evaluated again at the real time, and the real-time result is given when it is not a PASS (exit 11 for expired rules). Replays of a
saved report (`--replay-report`) and runs with `--knowledge-db` keep their
recorded time and get no warning.

Example commands in these docs pin `--now`. Once the embedded knowledge
expires (the first rules end on 2026-12-07 at the current data), a command
with an earlier pinned `--now` warns and answers UNKNOWN; change the date in
the example to the current time, or drop `--now`.

## 4. Run the check: Kubernetes 1.24 → 1.25

```sh
/tmp/prufyx check cncf --project kubernetes --native-resource applyset.json \
  --from 1.24.0 --to 1.25.0 \
  --distribution official_upstream --target-api-apply-required --resource-scope-complete \
  --now 2026-11-20T00:00:00Z --format human
```

Verified output (the complete human output; the six other removals
in this pair came back `PASS` because this apply set does not contain them, so
they are counted rather than listed):

```
BLOCKED  1 must fix · 0 undecided     kubernetes 1.24.0 -> 1.25.0, 7 reviewed rules
checked: 6 rules passed; this is not a pass

MUST FIX (1)
  Kubernetes 1.25 stops serving CronJob through batch/v1beta1
    applyset.json:6  CronJob default/nightly-report
    fix: Migrate the named CronJob manifests to batch/v1. Reassess the complete target apply set. Validate admission, CRDs, stored objects, runtime clients, and API-server configuration separately.

Whole upgrade: not proven. This report evaluated only 7 reviewed rules.
3 cited upstream sources (show with -v). 6 passed rules (--show-passes). Knowledge: embedded cncf-2026-09-13.8. No network used.
```

Under each blocking rule the report names the objects that made it true:
`file:line  Kind namespace/name`, the line being the object's `apiVersion` line
(five objects are listed; `-v` lists all). The `--format json` report carries the
same objects as an additional `locations` member on each BLOCKED claim; no other
byte of the report changes, and the input digest does not depend on them. This is
the route `--project kubernetes --native-resource` only. The file path and object
names print as typed; add `--redact` to print their digests instead, as
`prufyx scan --redact` does.

```sh
echo "exit code: $?"
# exit code: 10
```

That `10` is `ExitBlocked`. In CI use `--strict-exit` on every `prufyx
check`: then `14` means only the rules for this pair passed, and every
other code (2 = usage error, 3 = integrity failure, 10 = BLOCKED, 11 = UNKNOWN)
needs a human decision. Without the flag a scoped pass exits `0`, but the
whole upgrade is still `UNKNOWN` (the `Whole upgrade: not proven` line says so, and the
command repeats it on standard error), so a `0` is not "proceed". `10` means a
pinned upstream source says the target release no longer serves this
resource's API version. See [exit-codes.md](exit-codes.md).

The default output only counts the cited sources. Add `-v` to list them: each
source line is a citation, not a description. Open that
exact URL at that exact revision and you will find, at lines 48-74, the
Kubernetes source file that declares `CronJob` at `batch/v1beta1` removed in
1.25. The rule was derived from that source by the extractor named in the
`evidence basis` line that `-v` prints under the rule. `digest` pins the exact bytes it read, so if
upstream silently edits that page later, Prufyx's own corpus checks (not
this command) catch the drift rather than silently citing changed text.

Notice the whole-upgrade result stays `UNKNOWN` (`-v` prints `aggregate UNKNOWN`) even though one rule is `BLOCKED`. A
`BLOCKED` claim is still a `BLOCKED` claim — that specific resource will
break — but Prufyx never inflates "one scoped claim was decisive" into
"the whole upgrade was fully evaluated." The other removals in this pair
came back `PASS` only because this particular apply set does not contain
those kinds; that is not the same as proving they never occur anywhere in a
real cluster.

## 5. What `--resource-scope-complete` and `--target-api-apply-required` are actually asserting

(The complete list of declaration flags is in [declarations.md](declarations.md).)

Both flags are on the command deliberately — they are not boilerplate.

- **`--resource-scope-complete`** is *your* declaration that the file you
  passed is the entire rendered resource set you are about to apply, not an
  excerpt. Prufyx cannot verify this itself (it never talks to a cluster or
  a Git repo); it takes your word for it. Without this flag, every fact in
  the check would have to stay `UNKNOWN`, because a `PASS` derived from "the
  removed kind is absent from what I was shown" is worthless if what you
  were shown was only half the picture.
- **`--target-api-apply-required`** declares that this rendered set is
  actually what gets applied against the target API server at the new
  version (as opposed to, say, a reference manifest that is never applied,
  or applied against a different cluster). It scopes the claim to "this will
  really be sent," not "this JSON merely exists somewhere."

Drop either flag and every removal in this pair reports `UNKNOWN` instead of
`PASS`/`BLOCKED` — try it: the `to decide:` line names the missing
declaration and the flag that makes it, for example "the file is not declared
to be the complete apply set; if it is, add --resource-scope-complete and run
again". The reason code is `RULE_FACT_UNAVAILABLE`.

## 5a. The same check on YAML

You do not have to convert anything to JSON first. The Kubernetes route reads
single or multi-document YAML, such as the output of `helm template` or
`kustomize build`, and `kubectl get -o yaml` lists. Nothing is rendered or
executed: a document that still contains template syntax (`{{ ... }}` or
`${...}` in a value) makes the result `UNKNOWN` and asks for rendered output.
A removed API version in another, readable document is still reported as
`BLOCKED`, unless that document may not be rendered at all (for example when a
template action of another document in the same file can enclose it); see
`scan.md`, "Gaps".

```sh
cd /tmp/prufyx-quickstart
cat > applyset.yaml <<'YAML'
# Two documents, as `helm template` or `kustomize build` prints them.
apiVersion: batch/v1beta1
kind: CronJob
metadata:
  name: nightly-report
  namespace: default
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: report
              image: example/report:1.0
          restartPolicy: OnFailure
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: report-settings
  namespace: default
data:
  mode: nightly
YAML
chmod 600 applyset.yaml
/tmp/prufyx check cncf --project kubernetes --native-resource applyset.yaml \
  --from 1.24.0 --to 1.25.0 \
  --distribution official_upstream --target-api-apply-required --resource-scope-complete \
  --now 2026-11-20T00:00:00Z --format human
```

Verified output:

```
BLOCKED  1 must fix · 0 undecided     kubernetes 1.24.0 -> 1.25.0, 7 reviewed rules
checked: 6 rules passed; this is not a pass

MUST FIX (1)
  Kubernetes 1.25 stops serving CronJob through batch/v1beta1
    applyset.yaml:2  CronJob default/nightly-report
    fix: Migrate the named CronJob manifests to batch/v1. Reassess the complete target apply set. Validate admission, CRDs, stored objects, runtime clients, and API-server configuration separately.

Whole upgrade: not proven. This report evaluated only 7 reviewed rules.
3 cited upstream sources (show with -v). 6 passed rules (--show-passes). Knowledge: embedded cncf-2026-09-13.8. No network used.
```

With `-v`, the `prepared input digest` is the same as for the JSON file, because both
files describe the same removal facts; only the `raw input digests` differ,
since the bytes differ. The exit code is again `10`.

Anchors, aliases, merge keys, custom tags, duplicate keys and non-string keys
are rejected, as they are for JSON: each can make the bytes you read differ
from the value Kubernetes decodes.

## 5b. Pairs Prufyx has not reviewed

A pair that no reviewed rule covers, such as a multi-minor jump, prints one
line and exits `11`:

```sh
/tmp/prufyx check cncf --project kubernetes --native-resource applyset.json \
  --from 1.21.0 --to 1.25.0 \
  --distribution official_upstream --target-api-apply-required --resource-scope-complete \
  --now 2026-11-20T00:00:00Z --format human
```

```
UNKNOWN  0 must fix · 29 undecided     kubernetes 1.21.0 -> 1.25.0, 29 reviewed rules

UNDECIDED (29 rules)
  UNKNOWN: kubernetes 1.21.0 -> 1.25.0 is not a reviewed transition; reviewed pairs: 1.21.0 -> 1.22.0, 1.23.17 -> 1.24.0, 1.24.0 -> 1.25.0, 1.25.0 -> 1.26.0, 1.26.0 -> 1.27.0, 1.28.0 -> 1.29.0, 1.29.0 -> 1.31.0, 1.29.0 -> 1.32.0, and 32 more (prufyx catalog checks --project kubernetes); for a multi-minor upgrade, check each minor step; a step without a reviewed pair stays UNKNOWN
  20 rules about release boundaries (1.22.0, 1.25.0) this hop crosses are not reviewed for this hop

Whole upgrade: not proven. No reviewed rule decided this transition.
0 cited upstream sources (show with -v). Knowledge: embedded cncf-2026-09-13.8. No network used.
```

`--format json` still lists every rule that was considered.

## 6. A second worked example: Kubernetes 1.21 → 1.22

The same route, a different transition and a different removed kind
(`extensions/v1beta1` `Ingress`, removed in 1.22):

```sh
cd /tmp/prufyx-quickstart
cat > applyset-1-22.json <<'JSON'
{
  "apiVersion": "v1",
  "kind": "List",
  "items": [
    {
      "apiVersion": "extensions/v1beta1",
      "kind": "Ingress",
      "metadata": { "name": "legacy-ingress", "namespace": "default" },
      "spec": {
        "rules": [
          { "host": "example.com", "http": { "paths": [ { "path": "/", "backend": { "serviceName": "web", "servicePort": 80 } } ] } }
        ]
      }
    }
  ]
}
JSON
chmod 600 applyset-1-22.json
/tmp/prufyx check cncf --project kubernetes --native-resource applyset-1-22.json \
  --from 1.21.0 --to 1.22.0 \
  --distribution official_upstream --target-api-apply-required --resource-scope-complete \
  --now 2026-11-20T00:00:00Z --format human
```

Verified output:

```
BLOCKED  1 must fix · 0 undecided     kubernetes 1.21.0 -> 1.22.0, 13 reviewed rules
checked: 12 rules passed; this is not a pass

MUST FIX (1)
  Kubernetes 1.22 stops serving Ingress through extensions/v1beta1
    applyset-1-22.json:6  Ingress default/legacy-ingress
    fix: Migrate the named Ingress manifests to networking.k8s.io/v1. pathType is now required. Reassess the complete target apply set. Validate admission, CRDs, stored objects, runtime clients, and API-server configuration separately.

Whole upgrade: not proven. This report evaluated only 13 reviewed rules.
3 cited upstream sources (show with -v). 12 passed rules (--show-passes). Knowledge: embedded cncf-2026-09-13.8. No network used.
```

Exit code is again `10`. The 1.21 → 1.22 pair reviews thirteen separate
removals at once (webhooks, CRDs, RBAC, leases, and more); the twelve that do
not match are counted. Add `--show-passes` to list them.

## 7. One command for the whole upgrade: `prufyx scan`

`prufyx scan` takes your manifests (files, directories or `-` for standard
input) and the versions you are moving between, and answers first. It accepts
files other users can read (with a note) and refuses files they can write. On
the YAML file from step 5a:

```sh
cd /tmp/prufyx-quickstart
/tmp/prufyx scan applyset.yaml --from kubernetes=1.24.17 --to kubernetes=1.25.3 \
  --distribution official_upstream --resource-scope-complete --target-api-apply-required \
  --now 2026-11-20T00:00:00Z
```

Verified output:

```
BLOCKED: 1 problem must be fixed; 1 area was not checked

kubernetes 1.24.17 -> 1.25.3: 1 hop (path policy sequential_minor)
  1.24.17 -> 1.25.3   Kubernetes 1.25 stops serving CronJob through batch/v1beta1
                      applyset.yaml:2  CronJob default/nightly-report
                      fix: Migrate the named CronJob manifests to batch/v1. Reassess the complete target apply set. Validate admission, CRDs, stored objects, runtime clients, and API-server configuration separately.

NOT CHECKED (1)
  kubernetes   no reviewed list of the API versions Kubernetes 1.25 serves; 2 manifest(s) cannot be checked - check them against the API reference of that Kubernetes release by hand, or request coverage: https://github.com/prufyx/prufyx/issues/new?template=project-knowledge.yml

Read 2 documents over 1 hop; 1 of 1 component has rules (partially evaluated). 6 checks passed (--show-passes).
Scope limits: node and kubelet version skew not evaluated; Kubernetes: only API versions in the supplied manifests are evaluated; live cluster objects, CRDs, stored versions, admission and component configuration are not.
Evidence: every finding cites pinned upstream source (--verbose). No network used.
evaluated at 2026-11-20T00:00:00Z; input sha256:cac5facf042643aa2ca473b53dbc8e3de6e3001562dc1a16c4a0d15115aa07b0; knowledge embedded cncf-2026-09-13.8 sha256:4798d687e1680cc93cb0827634daa52f7f13091878edb66f2e1b00d9fb1a8e2e
```

The exit code is `10`, and the finding names the file, the line of the
object's `apiVersion`, its kind and its name. Every area that was not checked
is listed with what to do about it. A jump across several minor lines, such as
`--to kubernetes=1.30.4`, is planned one minor line at a time under the
reviewed Kubernetes upgrade-path policy: each line is a hop of its own, and the
report says `path policy sequential_minor`. See [`scan.md`](scan.md) for every flag, the
gaps, `--redact`, JSON output and `prufyx.yaml`.

## 8. Where to go next

- [`community-checks.md`](community-checks.md) documents every embedded
  project route, including the other native-resource checks besides
  Kubernetes.
- [`catalog checks`](community-checks.md#discovering-embedded-source-rule-routes)
  lists the exact rule identities and input shape for one project without
  running a check.
- The current build has **198 registered native check routes** across all
  projects (enforced by `internal/checkroutemetadata`, not a doc claim you
  have to trust); Kubernetes decides removed APIs for the upgrades
  to 1.22, 1.25, 1.26, 1.27, 1.29, 1.32, 1.33, 1.34 and 1.37 plus the 1.24
  dockershim removal. This quickstart exercised two of them.
- [`one-command-flow.md`](one-command-flow.md) covers `prufyx assess`, which
  reads a live cluster (read-only) and lists which checks apply to it. Put all
  flags before the context name:
  `prufyx assess --kubeconfig FILE --acknowledge-kubeconfig-exec-risk --format json CONTEXT`.
- A scoped `PASS`, `BLOCKED`, or `UNKNOWN` result is never a whole-upgrade
  safety claim. See the root [README](../README.md) and
  [`docs/product-contract.md`](product-contract.md) for what Prufyx does and
  does not promise.
