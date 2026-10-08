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
func PrepareKubernetesScan(workspace intake.Workspace, from, to, distribution string, targetApplyRequired, complete bool) (KubernetesScan, error) {
	read := func() (kubernetesApplySet, error) { return kubernetesApplySetOf(workspace), nil }
	var (
		prepared Prepared
		sources  map[string][]intake.Source
		err      error
	)
	if _, reviewed := kubernetesRemovalsForCrossedMinorLine(from, to); reviewed {
		prepared, sources, err = prepareKubernetesRemovedAPIs(read, workspace.Digest, from, to, distribution, targetApplyRequired, complete)
	} else {
		prepared, sources, err = prepareKubernetesFlowControl(read, workspace.Digest, from, to, distribution, targetApplyRequired, complete)
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
