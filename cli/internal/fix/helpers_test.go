// SPDX-License-Identifier: AGPL-3.0-only

package fix

import "reflect"

func deepEqual(a, b any) bool { return reflect.DeepEqual(a, b) }
