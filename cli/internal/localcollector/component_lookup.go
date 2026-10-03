// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

import (
	"sort"
	"sync"
)

var componentLookup struct {
	once     sync.Once
	registry adapterRegistry
}

func lookupRegistry() adapterRegistry {
	componentLookup.once.Do(func() {
		loaded, err := loadAdapterAssets("v3")
		if err == nil {
			componentLookup.registry = loaded.Contract
		}
	})
	return componentLookup.registry
}

// ComponentIDs returns the component identities of the exact component
// registry, sorted.
func ComponentIDs() []string {
	registry := lookupRegistry()
	ids := make([]string, 0, len(registry.Adapters))
	for _, adapter := range registry.Adapters {
		ids = append(ids, adapter.ComponentID)
	}
	sort.Strings(ids)
	return ids
}

// ComponentForImage returns the component whose registered image repository
// matches the image reference, ignoring tag and digest. It reports false for
// an image the registry does not know.
func ComponentForImage(image string) (string, bool) {
	registry := lookupRegistry()
	for i := range registry.Adapters {
		if findAdapterByParticipation(&registry.Adapters[i], image) {
			return registry.Adapters[i].ComponentID, true
		}
	}
	return "", false
}
