// Synthetic test fixture written for this repository. It is not
// upstream source; it only has the shape the feature-gate extractor reads.

package features

import "k8s.io/component-base/featuregate"

const (
	AlphaWidgets    featuregate.Feature = "AlphaWidgets"
	CloakedLever    featuregate.Feature = "CloakedLever"
	EchoSwitch      featuregate.Feature = "EchoSwitch"
	LegacyGizmoMode featuregate.Feature = "LegacyGizmoMode"
	MirrorFlag      featuregate.Feature = "MirrorFlag"
	NestedToggle    featuregate.Feature = "NestedToggle"
	OldPortal       featuregate.Feature = "OldPortal"
	RetiredKnob     featuregate.Feature = "RetiredKnob"
	SilentDial      featuregate.Feature = "SilentDial"
	StableThing     featuregate.Feature = "StableThing"
	TwinGateA       featuregate.Feature = "TwinGateA"
	TwinGateB       featuregate.Feature = "TwinGateB"
)

var defaultFeatureGates = map[featuregate.Feature]featuregate.FeatureSpec{
	AlphaWidgets:    {Default: false},
	CloakedLever:    {Default: false},
	EchoSwitch:      {Default: false},
	LegacyGizmoMode: {Default: false},
	MirrorFlag:      {Default: false},
	NestedToggle:    {Default: false},
	OldPortal:       {Default: false},
	RetiredKnob:     {Default: false},
	SilentDial:      {Default: false},
	StableThing:     {Default: false},
	TwinGateA:       {Default: false},
	TwinGateB:       {Default: false},
}
