// Synthetic test fixture written for this repository. It is not
// upstream source; it only has the shape the feature-gate extractor reads.

package features

import "k8s.io/component-base/featuregate"

const (
	AlphaWidgets    featuregate.Feature = "AlphaWidgets"
	BetaSprockets   featuregate.Feature = "BetaSprockets"
	LegacyGizmoMode featuregate.Feature = "LegacyGizmoMode"
	StableThing     featuregate.Feature = "StableThing"
)

var defaultFeatureGates = map[featuregate.Feature]featuregate.FeatureSpec{
	AlphaWidgets:    {Default: false},
	BetaSprockets:   {Default: false},
	LegacyGizmoMode: {Default: false},
	StableThing:     {Default: false},
}
