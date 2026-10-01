// SPDX-License-Identifier: AGPL-3.0-only

//go:build !darwin && !linux

package knowledgepublish

import "os"

func fileUID(os.FileInfo) (int, bool) { return 0, false }
