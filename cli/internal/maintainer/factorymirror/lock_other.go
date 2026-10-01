// SPDX-License-Identifier: AGPL-3.0-only

//go:build !unix

package factorymirror

// processAlive cannot be determined here; rely on the heartbeat only.
func processAlive(int) bool { return true }
