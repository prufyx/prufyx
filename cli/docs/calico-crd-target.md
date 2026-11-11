# Calico CRD target enrollment

The Calico target uses the community catalogue and the canonical upstream
repository, `github.com/projectcalico/calico`. It enrolls CRD source paths
from release line 3.28 onward, with attestation disabled. The frozen
release-line snapshot contains five consecutive pairs from 3.28 to 3.33;
this enrollment publishes no decided pair. A later attestation change must
establish complete source evidence for each pair before it can decide it.

Calico appears in the [full pinned landscape](https://github.com/cncf/landscape/blob/c1ef02752bbb9bbff9c405541ebed483e736f9c5/landscape.yml#L4000-L4005) without a CNCF-project marker and is absent from Prufyx's derived CNCF-project catalogue.
The generated coverage report therefore moves Calico's five snapshot pairs
from the CNCF denominator to the community denominator: 395 to 390 CNCF
pairs and 88 to 93 community pairs. Decided counts remain 53 and 42,
respectively. This classification change adds no decided coverage.

The declared paths are `libcalico-go/config/crd`, `api/config/crd` when present,
and `kube-controllers/pkg/apis/migration/v1/crd` when present. The candidate
table attributes `crd.projectcalico.org`, `projectcalico.org`, and
`migration.projectcalico.org` to Calico. The migration API is installed only
when running a datastore migration, as described in the pinned upstream
[manifest documentation](https://github.com/projectcalico/calico/blob/fbaa371111636a37ecc82625fce8453064a7fff2/manifests/README.md).

There are no exclusions. The existing full-tree scan must establish the
complete source surface before any line can be attested. Bundled operator
APIs and Kubernetes-reserved groups are not attributed to Calico merely
because its repository carries their definitions.

This is source target enrollment, not published compatibility knowledge.
Registry admission, reviewed extraction evidence, and the Knowledge gate
remain required before publishing any derived result. The onboarding gate
refuses attestation for a new table project: the table row must first be
present in the base revision before a later batch can enable attestation.
This enrollment keeps attestation disabled. Unknown or conflicting source
forms remain unknown.
