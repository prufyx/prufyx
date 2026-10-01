// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import "github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"

func verifyStoredRootChain(state trustState, history map[int64][]byte) error {
	if len(state.RootHistory) == 0 {
		return ErrIntegrity
	}
	first := state.RootHistory[0]
	raw := history[first.Version]
	if digestBytes(raw) != state.InitialRootDigest || validateTUFJSON(raw) != nil {
		return ErrIntegrity
	}
	trusted, err := trustedmetadata.New(raw)
	if err != nil || validateRootPolicy(trusted.Root) != nil {
		return ErrIntegrity
	}
	for _, entry := range state.RootHistory[1:] {
		next := history[entry.Version]
		if validateTUFJSON(next) != nil {
			return ErrIntegrity
		}
		if _, err = trusted.UpdateRoot(next); err != nil || validateRootPolicy(trusted.Root) != nil {
			return ErrIntegrity
		}
	}
	if trusted.Root.Signed.Version != state.Root.Version || roleReceipt(trusted.Root, history[state.Root.Version]) != state.Root {
		return ErrIntegrity
	}
	return nil
}
