// SPDX-License-Identifier: AGPL-3.0-only

package knowledgefixture

import (
	"fmt"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
)

// EmbeddedProjectBundle returns one bounded unsigned project envelope for
// legacy reader fixtures. It neither signs nor publishes knowledge.
func EmbeddedProjectBundle(project, revision string) ([]byte, error) {
	_, targets, err := cncfcheck.BuildEmbeddedExternalTargets(revision, nil)
	if err != nil {
		return nil, err
	}
	for _, target := range targets {
		if target.Path == cncfcheck.ProjectTargetPath(project) {
			return target.Bytes, nil
		}
	}
	return nil, fmt.Errorf("project fixture %q is absent", project)
}
