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
	apiextensionsfeatures "k8s.io/apiextensions-apiserver/pkg/features"
	"k8s.io/apimachinery/pkg/util/runtime"
	genericfeatures "k8s.io/apiserver/pkg/features"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	clientfeatures "k8s.io/client-go/features"
	"k8s.io/component-base/featuregate"
)

const (
	// owner: @bswartz
	// alpha: v1.18
	// beta: v1.24
	//
	// Enables usage of any object for volume data source in PVCs
	AnyVolumeDataSource featuregate.Feature = "AnyVolumeDataSource"

	// owner: @danwinship
	// alpha: v1.27
	// beta: v1.29
	// GA: v1.30
	//
	// Enables dual-stack --node-ip in kubelet with external cloud providers
	CloudDualStackNodeIPs featuregate.Feature = "CloudDualStackNodeIPs"

	// owner: @arjunrn @mwielgus @josephburnett @sanposhiho
	// kep: https://kep.k8s.io/1610
	// alpha: v1.20
	// beta:  v1.27
	// GA:  v1.30
	//
	// Add support for the HPA to scale based on metrics from individual containers
	// in target pods
	HPAContainerMetrics featuregate.Feature = "HPAContainerMetrics"

	// owner: @gjkim42 @SergeyKanzhelev @matthyx @tzneal
	// kep: http://kep.k8s.io/753
	// alpha: v1.28
	// beta: v1.29
	//
	// Introduces sidecar containers, a new type of init container that starts
	// before other containers but remains running for the full duration of the
	// pod's lifecycle and will not block pod termination.
	SidecarContainers featuregate.Feature = "SidecarContainers"
)

func init() {
	runtime.Must(utilfeature.DefaultMutableFeatureGate.Add(defaultKubernetesFeatureGates))
	runtime.Must(utilfeature.DefaultMutableFeatureGate.AddVersioned(defaultVersionedKubernetesFeatureGates))

	// Register all client-go features with kube's feature gate instance and make all client-go
	// feature checks use kube's instance. The effect is that for kube binaries, client-go
	// features are wired to the existing --feature-gates flag just as all other features
	// are. Further, client-go features automatically support the existing mechanisms for
	// feature enablement metrics and test overrides.
	ca := &clientAdapter{utilfeature.DefaultMutableFeatureGate}
	runtime.Must(clientfeatures.AddFeaturesToExistingFeatureGates(ca))
	clientfeatures.ReplaceFeatureGates(ca)
}

// defaultKubernetesFeatureGates consists of all known Kubernetes-specific feature keys.
// To add a new feature, define a key for it above and add it here. The features will be
// available throughout Kubernetes binaries.
//
// Entries are separated from each other with blank lines to avoid sweeping gofmt changes
// when adding or removing one entry.
var defaultKubernetesFeatureGates = map[featuregate.Feature]featuregate.FeatureSpec{
	AnyVolumeDataSource:             {Default: true, PreRelease: featuregate.Beta},                    // on by default in 1.24
	CloudDualStackNodeIPs:           {Default: true, PreRelease: featuregate.GA, LockToDefault: true}, // remove in 1.32
	HPAContainerMetrics:             {Default: true, PreRelease: featuregate.GA, LockToDefault: true}, // remove in 1.32
	SidecarContainers:               {Default: true, PreRelease: featuregate.Beta},
	genericfeatures.KMSv2:           {Default: true, PreRelease: featuregate.GA, LockToDefault: true}, // remove in 1.31
	genericfeatures.ServerSideApply: {Default: true, PreRelease: featuregate.GA, LockToDefault: true}, // remove in 1.29
	genericfeatures.WatchList:       {Default: false, PreRelease: featuregate.Alpha},
}
