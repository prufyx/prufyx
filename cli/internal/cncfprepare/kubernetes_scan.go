// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"github.com/prufyx/prufyx/cli/internal/intake"
	"github.com/prufyx/prufyx/cli/internal/k8sremovals"
)

// KubernetesScan is the rendered apply-set preparation for documents that
// intake already read from files, directories or stdin. Prepared is exactly
// what PrepareKubernetesRemovedAPIs returns for one file holding the same
// documents (the same canonical input, digest, state and reason); only
// SourceDigest differs, because there is no single file: it is the
// workspace digest.
type KubernetesScan struct {
	Prepared Prepared
	// Sources maps every fact the canonical input declares true to the
	// documents that made it true, in workspace order. It is provenance for
	// reports: it never enters the canonical input or any digest.
	Sources map[string][]intake.Source
}

// PrepareKubernetesScan prepares the removed served API facts of one
// transition from a workspace. The workspace must be the complete apply set
// the caller declares: every omission it carries leaves the set unresolved,
// exactly as it does for a single file. Callers remove documents that are
// not part of the apply set (such as a scan configuration file) before.
//
// declaration carries the caller's declared kubelet versions. When it names a
// minimum, the preparation adds the kubelet version-skew fact, evaluated by
// the same predicate as the component-configuration route; the fact is never
// a document-backed source. A declaration that does not validate is refused.
func PrepareKubernetesScan(workspace intake.Workspace, from, to, distribution string, targetApplyRequired, complete bool, declaration KubeletDeclaration) (KubernetesScan, error) {
	if err := ValidateKubeletVersionDeclarations(declaration.Minimum, declaration.Maximum); err != nil {
		return KubernetesScan{}, err
	}
	var extra []inputFact
	if declaration.Minimum != "" {
		extra = []inputFact{kubeletSkewDeclaredFact(declaration, to, distribution)}
	}
	read := func() (kubernetesApplySet, error) { return kubernetesApplySetOf(workspace), nil }
	var (
		prepared Prepared
		sources  map[string][]intake.Source
		err      error
	)
	if _, reviewed := kubernetesRemovalsForCrossedMinorLine(from, to); reviewed {
		prepared, sources, err = prepareKubernetesRemovedAPIs(read, workspace.Digest, from, to, distribution, targetApplyRequired, complete, extra)
	} else {
		prepared, sources, err = prepareKubernetesFlowControl(read, workspace.Digest, from, to, distribution, targetApplyRequired, complete, extra)
	}
	if err != nil {
		return KubernetesScan{}, err
	}
	if sources == nil {
		sources = map[string][]intake.Source{}
	}
	return KubernetesScan{Prepared: prepared, Sources: sources}, nil
}

// KubernetesRemovedVersion is one reviewed removal of a served API version:
// the kinds of Group at Version stop being served when a cluster enters Line.
type KubernetesRemovedVersion = k8sremovals.RemovedVersion

// KubernetesRemovedVersions lists every removal the rendered apply-set route
// knows, including the 1.32 flow-control removal, ordered by line, group,
// version. It is read-only provenance for callers that must notice an
// object at a version removed on a line no evaluated transition crosses.
func KubernetesRemovedVersions() []KubernetesRemovedVersion { return k8sremovals.RemovedVersions() }

// KubeletDeclaration is the caller's declared kubelet versions for a scan.
// Minimum is the lowest kubelet version of any node after the control plane
// upgrade, Maximum the optional highest (else the minimum), both x.y.z.
// Source says where the declaration came from ("flag" or "file"); it is
// provenance only and never enters a canonical input or digest.
type KubeletDeclaration struct {
	Minimum, Maximum, Source string
}

// kubeletSkewDeclaredFact is the skew fact for one hop target from declared
// versions: true or false from the shared predicate, unsupported when the
// distribution is not official upstream or the versions cannot be compared.
func kubeletSkewDeclaredFact(declaration KubeletDeclaration, to, distribution string) inputFact {
	unsupported := inputFact{ID: KubernetesKubeletSkewFact, State: "unsupported"}
	if distribution != "official_upstream" {
		return unsupported
	}
	lowest, lowestOK := kubernetesVersionParts(declaration.Minimum)
	highest, highestOK := lowest, lowestOK
	if declaration.Maximum != "" {
		highest, highestOK = kubernetesVersionParts(declaration.Maximum)
	}
	target, targetOK := kubernetesVersionParts(to)
	if !lowestOK || !highestOK || !targetOK {
		return unsupported
	}
	present, resolved := KubeletSkewUnsupported(lowest, highest, target)
	if !resolved {
		return unsupported
	}
	return boolFact(KubernetesKubeletSkewFact, present)
}
