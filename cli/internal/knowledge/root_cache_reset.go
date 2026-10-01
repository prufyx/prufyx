// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"fmt"
	"sort"

	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
)

// rootChainRotatesUpdateAuthority replays only the consecutive, authenticated
// root prefix the updater can consume. A change to either timestamp or snapshot
// key IDs makes the TUF 5.3.11 timestamp/snapshot cache reset sticky across all
// accepted hops, including a rotation away from and back to the original IDs.
// Invalid, unsupported, and non-consecutive offered roots do not authorize a
// reset; Refresh remains authoritative for the update outcome.
func rootChainRotatesUpdateAuthority(initialRoot []byte, files map[string][]byte) bool {
	trusted, err := trustedmetadata.New(initialRoot)
	if err != nil || validateRootPolicy(trusted.Root) != nil {
		return false
	}
	previous := trusted.Root
	reset := false
	for offset := int64(1); offset <= 8; offset++ {
		version := previous.Signed.Version + 1
		raw, ok := files[fmt.Sprintf("metadata/%d.root.json", version)]
		if !ok {
			break
		}
		if len(raw) > rootMetadataMaxBytes || validateTUFJSON(raw) != nil {
			break
		}
		next, updateErr := trusted.UpdateRoot(raw)
		if updateErr != nil || validateRootPolicy(next) != nil {
			break
		}
		if !sameRootRoleKeyIDs(previous, next, metadata.TIMESTAMP) || !sameRootRoleKeyIDs(previous, next, metadata.SNAPSHOT) {
			reset = true
		}
		previous = next
	}
	return reset
}

func sameRootRoleKeyIDs(oldRoot, newRoot *metadata.Metadata[metadata.RootType], roleName string) bool {
	if oldRoot == nil || newRoot == nil {
		return false
	}
	oldRole, oldOK := oldRoot.Signed.Roles[roleName]
	newRole, newOK := newRoot.Signed.Roles[roleName]
	if !oldOK || !newOK || oldRole == nil || newRole == nil || len(oldRole.KeyIDs) != len(newRole.KeyIDs) {
		return false
	}
	oldIDs := append([]string(nil), oldRole.KeyIDs...)
	newIDs := append([]string(nil), newRole.KeyIDs...)
	sort.Strings(oldIDs)
	sort.Strings(newIDs)
	for index := range oldIDs {
		if oldIDs[index] != newIDs[index] {
			return false
		}
	}
	return true
}
