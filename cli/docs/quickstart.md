# Quickstart

This gets you from a clean clone to a real **BLOCKED** verdict, with a
citation into upstream Kubernetes source, in under five minutes. It uses the
Kubernetes API-removal route, which is real, published, and checked in CI.

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

## 2. What the verdicts mean

Every `prufyx check` prints one aggregate assessment and one line per rule it
evaluated:

- **PASS** — the input does not match the reviewed source condition for this
  rule. It is not a certificate that the rest of the upgrade is safe.
- **BLOCKED** — the input matches a reviewed, pinned source condition that
  the target release actually enforces (a removed API, a removed flag, and
  so on). The command exits with code `10`, so CI can gate on it.
- **UNKNOWN** — the input does not give Prufyx enough to decide either way
  (a required declaration is missing, the fact is outside what the rule
  reviews, or a different rule in the same set could not be evaluated).
  **This is a feature, not a bug.** Prufyx never claims a scoped PASS from
  missing evidence, and it never claims a whole-upgrade PASS from a set of
  scoped PASS results. Guessing "probably fine" from an absent fact is
  exactly the failure mode a deterministic checker exists to avoid.

## 3. A file, mode 0600

Every input file Prufyx reads must be **owner-only, mode 0600**. This is a
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

## 4. Run the check: Kubernetes 1.24 → 1.25

```sh
/tmp/prufyx check cncf --project kubernetes --native-resource applyset.json \
  --from 1.24.0 --to 1.25.0 \
  --distribution official_upstream --target-api-apply-required --resource-scope-complete \
  --now 2026-09-24T00:00:00Z --format human
```

Verified output (trimmed to the decisive line and its citation; the full run
also prints six other reviewed removals in this pair, all `PASS` because
this apply set does not contain them):

```
kubernetes native input review
raw input digests: sha256:74b724b3dbe66cdea762575500e4fce48a5469b669668a7108280e026456a355
prepared input digest: sha256:619e1cfad17ce822d3ad4d36b1cdc3ef3024e9ec37720096f2af8076b92660b2
aggregate: UNKNOWN
network used: false
whole-upgrade compatibility: UNKNOWN
kubernetes.cronjob-v1beta1-removed.1-24-0-to-1-25-0: BLOCKED (REVIEWED_SOURCE_CONSTRAINT)
next action: Migrate the named CronJob manifest to batch/v1, then reassess the complete target apply set. Validate admission, CRDs, stored objects, runtime clients, and API-server configuration separately.
pinned source: https://github.com/kubernetes/website/blob/9f1af2971c32124bff0a1f42255ba5a2f3c8a16f/content/en/docs/reference/using-api/deprecation-guide.md lines 87-93; revision 9f1af2971c32124bff0a1f42255ba5a2f3c8a16f; digest sha256:96f34a49cbdd7bd53008cc7b7cc8aff58c373ad323e64eef0155cbbc44494f61
```

```sh
echo "exit code: $?"
# exit code: 10
```

That `10` is `ExitBlocked`. Wire it into CI as a hard gate: any nonzero exit
from `prufyx check` (2 = usage error, 3 = integrity failure, 10 = BLOCKED, 11
= UNKNOWN) means "do not proceed without a human decision," and `10`
specifically means a reviewed, pinned source confirms the upgrade will break
this resource.

The `pinned source` line is not a description — it is a citation. Open that
exact URL at that exact revision and you will find, at lines 87-93, the
Kubernetes deprecation guide stating that `CronJob` stops being served at
`batch/v1beta1` in 1.25. `digest` pins the exact bytes reviewed, so if
upstream silently edits that page later, Prufyx's own corpus checks (not
this command) catch the drift rather than silently citing changed text.

Notice the aggregate stays `UNKNOWN` even though one rule is `BLOCKED`. A
`BLOCKED` claim is still a `BLOCKED` claim — that specific resource will
break — but Prufyx never inflates "one scoped claim was decisive" into
"the whole upgrade was fully evaluated." Ten other removals in this pair
came back `PASS` only because this particular apply set does not contain
those kinds; that is not the same as proving they never occur anywhere in a
real cluster.

## 5. What `--resource-scope-complete` and `--target-api-apply-required` are actually asserting

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
`PASS`/`BLOCKED` — try it, the CLI will tell you why in the `next action`
field.

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
  --now 2026-09-24T00:00:00Z --format human
```

Verified output (trimmed to the decisive line):

```
kubernetes.ingress-extensions-v1beta1-removed.1-21-0-to-1-22-0: BLOCKED (REVIEWED_SOURCE_CONSTRAINT)
next action: Migrate the named Ingress manifest to networking.k8s.io/v1, then reassess the complete target apply set. Validate admission, CRDs, stored objects, runtime clients, and API-server configuration separately.
pinned source: https://github.com/kubernetes/website/blob/9f1af2971c32124bff0a1f42255ba5a2f3c8a16f/content/en/docs/reference/using-api/deprecation-guide.md lines 257-269; revision 9f1af2971c32124bff0a1f42255ba5a2f3c8a16f; digest sha256:96f34a49cbdd7bd53008cc7b7cc8aff58c373ad323e64eef0155cbbc44494f61
```

Exit code is again `10`. This same run prints thirteen lines in total — the
1.21 → 1.22 pair reviews thirteen separate removals at once (webhooks, CRDs,
RBAC, leases, and more), and every one of them gets a line every time you run
this check, whether or not that particular kind is present in your input.

## 7. Where to go next

- [`community-checks.md`](community-checks.md) documents every embedded
  project route, including the other native-resource checks besides
  Kubernetes.
- [`catalog checks`](community-checks.md#discovering-embedded-source-rule-routes)
  lists the exact rule identities and input shape for one project without
  running a check.
- The current build has **194 registered native check routes** across all
  projects (enforced by `internal/checkroutemetadata`, not a doc claim you
  have to trust); Kubernetes alone reviews removed APIs across five separate
  from/to pairs, plus a sixth pair (1.31.0 → 1.32.0) for flow-control API
  removals specifically. This quickstart exercised two of the five.
- A scoped `PASS`, `BLOCKED`, or `UNKNOWN` result is never a whole-upgrade
  safety claim. See the root [README](../README.md) and
  [`docs/product-contract.md`](product-contract.md) for what Prufyx does and
  does not promise.
