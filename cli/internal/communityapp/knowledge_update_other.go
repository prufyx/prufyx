// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux && !darwin

package communityapp

import "os"

// Windows has no POSIX owner or link-count to check, and no O_NOFOLLOW. The
// ownership predicates therefore report false, so the retained-package checks
// refuse rather than pass without the guarantee.
const openNoFollowNonblock = 0

func ownedByEffectiveUser(os.FileInfo) bool { return false }

func singleLinkOwnedByEffectiveUser(os.FileInfo) bool { return false }
