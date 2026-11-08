// SPDX-License-Identifier: AGPL-3.0-only

//go:build !darwin && !linux

package knowledgegate

import "errors"

func writeApprovalFiles(string, []string, [][]byte) error {
	return errors.New("signing many approvals is supported on Linux and macOS only")
}
