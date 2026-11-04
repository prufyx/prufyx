// SPDX-License-Identifier: AGPL-3.0-only

//go:build !unix

package knowledgegate

import (
	"os"
	"testing"
)

func admissionTestPipe(t *testing.T) (*os.File, int) {
	t.Helper()
	t.Skip("bot readiness pipe requires Unix")
	return nil, -1
}
