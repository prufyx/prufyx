// SPDX-License-Identifier: AGPL-3.0-only

//go:build !darwin && !linux

package knowledgesign

import "os"

func ownedByCurrentUser(os.FileInfo) bool { return false }
