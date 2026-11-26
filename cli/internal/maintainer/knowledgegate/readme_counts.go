// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import "github.com/prufyx/prufyx/cli/internal/maintainer/coveragereport"

// ReadmeCounts returns the document (coveragereport.ReadmeCountsJSON) for the
// tree rooted at root: the report, the inventory counts and the digest of the
// coverage block, all from the same data and clock the README block is
// rendered from.
func ReadmeCounts(root string) ([]byte, error) {
	return countsOfTree(Tree{Root: root}, DefaultLayout().Onboarding.TablePath)
}

// countsOfTree is ReadmeCounts of a tree with its table at tablePath.
func countsOfTree(t Tree, tablePath string) ([]byte, error) {
	report, inventory, now, err := coverageReportOf(t, tablePath)
	if err != nil {
		return nil, err
	}
	block, err := coveragereport.RenderREADMEBlock(report, inventory, now)
	if err != nil {
		return nil, err
	}
	return coveragereport.ReadmeCountsJSON(report, inventory, block)
}
