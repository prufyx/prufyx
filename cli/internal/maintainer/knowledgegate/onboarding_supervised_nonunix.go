// SPDX-License-Identifier: AGPL-3.0-only

//go:build !unix

package knowledgegate

import "errors"

func claimSupervisedInputs() (*supervisedInputs, error) {
	return nil, errors.New("supervised immutable input descriptors require Linux")
}
