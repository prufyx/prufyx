// Synthetic test fixture written for this repository. It is not
// upstream source; it only has the shape the feature-gate extractor reads.

package featuregate

import "fmt"

// Feature names a feature gate.
type Feature string

// FeatureSpec describes a feature gate.
type FeatureSpec struct {
	Default bool
}

// Check rejects a gate that is not known.
func Check(known map[Feature]FeatureSpec, name string) error {
	if _, ok := known[Feature(name)]; !ok {
		return fmt.Errorf("unrecognized feature gate: %s", name)
	}
	return nil
}
