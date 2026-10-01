# Local batch checks

`prufyx check batch` evaluates up to 64 prepared canonical inputs from one
private local root. The command reads only the plan, the named relative input
files, embedded rules, and, when selected, one local signed CNCF knowledge
store. It performs no network, subprocess, cluster, database update, or config
upload operation. The signed-store verifier may advance its documented local
clock floor after successful current verification.

Embedded batches declare:

```json
{"knowledge":{"mode":"embedded_only"}}
```

and run with an explicit UTC evidence clock:

```sh
batch_root="$(mktemp -d)"
cp examples/batch/kyverno.json examples/batch/loki.json "$batch_root/"
chmod 600 "$batch_root/kyverno.json" "$batch_root/loki.json"
prufyx check batch --plan examples/batch/embedded-mixed-plan.json \
  --root "$batch_root" --now 2026-09-12T22:00:00Z --format human
```

The public synthetic run reports the scoped Kyverno claim `BLOCKED`, the Loki
claim `PASS`, the aggregate compatibility decision `UNKNOWN`, and exits `10`.

Signed CNCF batches declare the complete mixed knowledge policy:

```json
{"knowledge":{"mode":"external_cncf_embedded_community","cncf":"external_signed_local","communityProject":"embedded"}}
```

and select exactly one current constraints store:

```sh
prufyx check batch --plan /private/plan.json --root /private/inputs \
  --knowledge-db /private/cncf-store --format json --exit-mode detailed
```

Signed mode rejects `--now`. After the full plan and every input pass local
admission, the command opens the current selected store revision once. Every
CNCF item uses those exact verified bytes with no embedded fallback. Neutral
community-project items remain embedded but use the same verifier clock, so a
mixed report has one evaluation instant. Historical batch replay is not
implemented.

Every input path is relative to `--root`. The root and each ancestor are opened
with descriptor-relative no-follow directory operations; each input must be a
current-user-owned, one-link, regular `0600` file. The bounded read compares
the observed descriptor identity, ownership, mode, link count, size, and
modification/change metadata before and after reading; an optional digest binds
the exact supplied bytes. This is not an atomic filesystem snapshot guarantee.
Reports replace plan labels with `item-001` positions and do not include input
paths or the store path. Each item states `knowledgeOrigin`; signed reports
also bind the selected revision, bundle digest, and trust receipt digest.

The aggregate compatibility decision remains `UNKNOWN`, including when every
scoped claim passes. Legacy exits are `0` scoped pass, `10` blocked, `11`
unknown or stale, `2` invalid input, and `3` integrity failure. Detailed mode
uses `12` for stale source evidence and `13` when the evaluation clock precedes
source review. The fixed aggregate precedence is integrity, input, blocked,
not-yet-reviewed, stale, unknown, then pass.

The [`embedded`](../examples/batch/embedded-mixed-plan.json) and
[`signed`](../examples/batch/signed-mixed-plan.json) public synthetic plans use
the same minimized Kyverno and Loki inputs. They contain no trust root or
signing key. Use an independently provisioned signed constraints store for
signed operation; the repository's generated fixture is test-only and confers
no official trust or compatibility proof.
