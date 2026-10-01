---
name: Upstream evidence contribution
about: Propose public upstream evidence for a CNCF identity or exact transition
labels: contribution, evidence
---

## Packet

- [ ] I attached a `prufyx.io/upstream-evidence-packet/v1` packet.
- [ ] `(cd cli && GOTOOLCHAIN=local GOWORK=off GOPROXY=off GOSUMDB=off GOFLAGS='-mod=vendor -buildvcs=false' go run ./cmd/prufyx-maintainer contribution validate --packet PACKET.json)` returned a `CANDIDATE` receipt.
- [ ] The packet uses only public-source metadata and bounded excerpts.

## Proposal

State whether this is a new catalogue identity proposal or an exact existing-project transition. For a transition, include exact current/proposed versions and the declared tag-to-commit bindings.

## Limits and evidence

Explain what the packet does **not** prove. Link the immutable primary-source URL(s) and identify any source/license/attribution uncertainty. A validator receipt is consistency-only; it is not source verification, approval, compatibility proof, or publication.

## Data boundary

Do not post customer configurations, Kubernetes objects, Secrets, credentials, private paths, logs, proprietary source text, or production snapshots.
