// SPDX-License-Identifier: AGPL-3.0-only

//go:build !unix

package knowledgegate

import (
	"errors"
	"os"
)

func claimOnboardingReadyPipe(int) (*os.File, error) {
	return nil, errors.New("bot admission control pipe is unsupported on this platform")
}
