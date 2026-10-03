// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"github.com/prufyx/prufyx/cli/internal/intake"
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
