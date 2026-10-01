// SPDX-License-Identifier: AGPL-3.0-only

//go:build !unix

package factorymirror

import "time"

// processAlive cannot be determined here; rely on the heartbeat only.
func processAlive(int) bool { return true }

func platformAcquire(path string, body []byte, rec lockRecord, staleAfter time.Duration) (func(), error) {
	return acquireExcl(path, body, rec, staleAfter)
}
