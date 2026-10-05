// SPDX-License-Identifier: AGPL-3.0-only

package extractpack_test

import "github.com/prufyx/prufyx/cli/internal/extract"

func canonical(v any) ([]byte, error) { return extract.Canonical(v) }
