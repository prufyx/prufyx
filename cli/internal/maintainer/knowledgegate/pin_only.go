// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import "slices"

// A change of the oldest-supported-client pin is made alone. The tests and the
// workflow that prove a pin run from the proposed head, so a change that moves
// the pin and anything else could weaken its own proof, or ship data for a
// client in the same step. The gate is built from the base and refuses it. A
// rename of the pin changes two paths and is refused the same way.
const checkClientPinOnly = "client-pin-only"

func (r *Report) clientPinOnlyCheck() {
	if !slices.Contains(r.ChangedPaths, OldestClientPinPath) {
		return
	}
	if len(r.ChangedPaths) == 1 {
		r.add(checkClientPinOnly, true, "the oldest supported client pin is the only changed file")
		return
	}
	r.add(checkClientPinOnly, false, "a change of %s may change nothing else; %d files changed%s", OldestClientPinPath, len(r.ChangedPaths), listDetail(r.ChangedPaths))
}
