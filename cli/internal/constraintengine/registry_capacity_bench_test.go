// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"fmt"
	"testing"
)

func BenchmarkCompiledRegistry(b *testing.B) {
	for _, count := range []int{252, MaxCompiledRegistryFacts} {
		definitions := capacityDefinitions(count)
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := NewCompiledRegistry(definitions); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
