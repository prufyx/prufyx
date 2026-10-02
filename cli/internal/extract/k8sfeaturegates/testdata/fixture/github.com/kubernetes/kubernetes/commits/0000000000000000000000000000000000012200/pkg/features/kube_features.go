/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package features

import (
	"k8s.io/apimachinery/pkg/util/runtime"
	genericfeatures "k8s.io/apiserver/pkg/features"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/component-base/featuregate"
)

const (
	// owner: @tallclair
	// beta: v1.4
	AppArmor featuregate.Feature = "AppArmor"

	// owner: @jiayingz
	// beta: v1.10
	//
	// Enables support for Device Plugins
	DevicePlugins featuregate.Feature = "DevicePlugins"

	// owner: @mikedanese
	// alpha: v1.13
	// beta: v1.21
	// ga: v1.22
	//
	// Migrate ServiceAccount volumes to use a projected volume consisting of a
	// ServiceAccountTokenVolumeProjection. This feature adds new required flags
	// to the API server.
	BoundServiceAccountTokenVolume featuregate.Feature = "BoundServiceAccountTokenVolume"

	// owner: @matthyx
	// alpha: v1.16
	// beta: v1.18
	// GA: v1.20
	//
	// Enables the startupProbe in kubelet worker.
	StartupProbe featuregate.Feature = "StartupProbe"
)

func init() {
	runtime.Must(utilfeature.DefaultMutableFeatureGate.Add(defaultKubernetesFeatureGates))
}

// defaultKubernetesFeatureGates consists of all known Kubernetes-specific feature keys.
// To add a new feature, define a key for it above and add it here. The features will be
// available throughout Kubernetes binaries.
var defaultKubernetesFeatureGates = map[featuregate.Feature]featuregate.FeatureSpec{
	AppArmor:                                {Default: true, PreRelease: featuregate.Beta},
	DevicePlugins:                           {Default: true, PreRelease: featuregate.Beta},
	BoundServiceAccountTokenVolume:          {Default: true, PreRelease: featuregate.GA, LockToDefault: true}, // remove in 1.23
	StartupProbe:                            {Default: true, PreRelease: featuregate.GA, LockToDefault: true}, // remove in 1.23
	genericfeatures.StreamingProxyRedirects: {Default: false, PreRelease: featuregate.Deprecated},             // remove in 1.24
	genericfeatures.APIListChunking:         {Default: true, PreRelease: featuregate.Beta},
}
