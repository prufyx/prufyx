// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package knowledgegate

import "errors"

func (s *supervisedInputs) read(supervisedFlags) ([]byte, []byte, []byte, []byte, error) {
	return nil, nil, nil, nil, errors.New("supervised immutable input descriptors require Linux")
}
