# Kind-judge report, 2026-10-22

Aggregate results of the kind validation of knowledge claims, as of
2026-10-22. This page is a dated snapshot, not a live metric.

## Provenance

The numbers below are **reported by the maintainers' validation pipeline**.
They are not recomputed from the data in this repository, and a reader cannot
reproduce the totals from a clone. What a reader can reproduce is the
method: each claim is checked by `kind-val.sh` against a real API server
(see [kind-val](kind-val.md)), with the pinned node images listed below. The
report holds counts only. It lists no claim, project, cluster or host.

A kind check tests one claim on one throwaway cluster. It does not show that
any upgrade is safe, and it does not change what `prufyx check` reports.

## Totals

| Item | Count |
|---|---|
| Claims in the validation ledger | 5097 |
| Claims checked on kind | 4729 |
| Claims not checkable on kind | 368 |
| Validation batches | 78 |
| Claims pulled for validation (with repeats) | 7721 |

Claims not checkable on kind are model-drafted candidates and CRD schema
changes. Those have no kind method; they are not counted as confirmed.

## Outcome per claim

The latest outcome of each of the 4729 checked claims:

| Outcome | Claims |
|---|---|
| confirmed | 4305 |
| refuted | 19 |
| undetermined | 152 |
| error | 253 |

Confirmed means the cluster behaved as the claim states. Refuted means it did
not. Undetermined and error mean the check gave no answer; both are treated
as unknown, never as a pass. Claims are re-checked, so the raw count of
validation rows (13286) is larger than the number of claims.

## Pinned inputs

Period: 2026-10-10 to 2026-10-21. Prufyx commit used by the runner:
`196702e743ef86c51dd11e70a7a6ad0034bf5371`.

Kind node images (by digest). [kind-val](kind-val.md) lists only the 1.36 and
1.37 digests as examples; the other six are pipeline-reported.

| Line | Image |
|---|---|
| 1.30 | `kindest/node:v1.30.13@sha256:397209b3d947d154f6641f2d0ce8d473732bd91c87d9575ade99049aa33cd648` |
| 1.31 | `kindest/node:v1.31.14@sha256:6f86cf509dbb42767b6e79debc3f2c32e4ee01386f0489b3b2be24b0a55aac2b` |
| 1.32 | `kindest/node:v1.32.11@sha256:5fc52d52a7b9574015299724bd68f183702956aa4a2116ae75a63cb574b35af8` |
| 1.33 | `kindest/node:v1.33.12@sha256:3f5c8443c620245e4d355cfe09e96a91ead32ceaa569d3f1ca9edf0cb2fe2ff4` |
| 1.34 | `kindest/node:v1.34.11@sha256:44e222ee2132dab25ff87301682f89eb82c7880ea3a1bf543bfe9708fd08d67d` |
| 1.35 | `kindest/node:v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0` |
| 1.36 | `kindest/node:v1.36.4@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed` |
| 1.37 | `kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5` |
