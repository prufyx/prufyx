// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"github.com/prufyx/prufyx/cli/internal/customresources"
)

// ReservedLeftOut is the one predicate that decides whether a definition of
// the group and kind found in a file under a default-excluded directory is
// left out of the comparison like a definition the table assigns to another
// project. The scan calls it. The target generator does not call it yet:
// wiring it in (a reserved-namespace-copy decision) is a follow-up for the
// generator owner, so that both use one predicate. The caller must apply it only to a definition read from a file
// whose place is a default-excluded directory and not void.
//
// It holds only when all of these hold; any doubt is false (the definition
// stays, and the file stays an extra finding):
//
//   - the inventory of the release is known and complete, and none of the
//     groups it defines (with its other channels) is the group;
//   - the group is a documentation name (customresources.DocumentationGroup) or lies in a
//     Kubernetes-reserved namespace (customresources.ReservedNamespace);
//   - the table does not give the group and kind to the target, and does
//     not give them ambiguously (unlisted, or owned by another project).
func ReservedLeftOut(index customresources.Index, project string, inv *Inventory, group, kind string) bool {
	if project == "" || group == "" || inv == nil || !inv.Complete {
		return false
	}
	if !customresources.DocumentationGroup(group) && !customresources.ReservedNamespace(group) {
		return false
	}
	for _, g := range targetGroups(inv) {
		if g == group {
			return false
		}
	}
	owner, attr := index.OwnerOf(group, kind)
	switch attr {
	case customresources.Unknown:
		return true
	case customresources.Owned:
		return owner != project
	}
	return false
}
