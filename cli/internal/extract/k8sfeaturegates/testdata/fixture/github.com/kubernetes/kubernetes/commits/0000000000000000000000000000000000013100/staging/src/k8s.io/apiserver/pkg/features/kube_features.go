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
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/component-base/featuregate"
)

const (
	// owner: @aramase
	// kep: https://kep.k8s.io/3299
	// alpha: v1.25
	// beta: v1.27
	// stable: v1.29
	//
	// Enables KMS v2 API for encryption at rest.
	KMSv2 featuregate.Feature = "KMSv2"

	// owner: @apelisse, @lavalamp
	// alpha: v1.14
	// beta: v1.16
	// stable: v1.22
	//
	// Server-side apply. Merging happens on the server.
	ServerSideApply featuregate.Feature = "ServerSideApply"

	// owner: @p0lyn0mial
	// alpha: v1.27
	//
	// Allow the API server to stream individual items instead of chunking
	WatchList featuregate.Feature = "WatchList"
)

func init() {
	runtime.Must(utilfeature.DefaultMutableFeatureGate.Add(defaultKubernetesFeatureGates))
	runtime.Must(utilfeature.DefaultMutableFeatureGate.AddVersioned(defaultVersionedKubernetesFeatureGates))
}

// defaultVersionedKubernetesFeatureGates consists of all known Kubernetes-specific feature keys with VersionedSpecs.
// To add a new feature, define a key for it above and add it here. The features will be
// available throughout Kubernetes binaries.
var defaultVersionedKubernetesFeatureGates = map[featuregate.Feature]featuregate.VersionedSpecs{}

// defaultKubernetesFeatureGates consists of all known Kubernetes-specific feature keys.
// To add a new feature, define a key for it above and add it here. The features will be
// available throughout Kubernetes binaries.
var defaultKubernetesFeatureGates = map[featuregate.Feature]featuregate.FeatureSpec{
	KMSv2:           {Default: true, PreRelease: featuregate.GA, LockToDefault: true}, // remove in 1.31
	ServerSideApply: {Default: true, PreRelease: featuregate.GA, LockToDefault: true}, // remove in 1.29
	WatchList:       {Default: false, PreRelease: featuregate.Alpha},
}
