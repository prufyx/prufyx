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
	clientfeatures "k8s.io/client-go/features"
	"k8s.io/component-base/featuregate"
	zpagesfeatures "k8s.io/component-base/zpages/features"
)

const (
	// owner: @bswartz
	//
	// Enables usage of any object for volume data source in PVCs
	AnyVolumeDataSource featuregate.Feature = "AnyVolumeDataSource"

	// owner: @gjkim42 @SergeyKanzhelev @matthyx @tzneal
	// kep: http://kep.k8s.io/753
	//
	// Introduces sidecar containers, a new type of init container that starts
	// before other containers but remains running for the full duration of the
	// pod's lifecycle and will not block pod termination.
	SidecarContainers featuregate.Feature = "SidecarContainers"
)

func init() {
	runtime.Must(utilfeature.DefaultMutableFeatureGate.Add(defaultKubernetesFeatureGates))
	runtime.Must(utilfeature.DefaultMutableFeatureGate.AddVersioned(defaultVersionedKubernetesFeatureGates))
	runtime.Must(zpagesfeatures.AddFeatureGates(utilfeature.DefaultMutableFeatureGate))

	// Register all client-go features with kube's feature gate instance and make all client-go
	// feature checks use kube's instance. The effect is that for kube binaries, client-go
	// features are wired to the existing --feature-gates flag just as all other features
	// are. Further, client-go features automatically support the existing mechanisms for
	// feature enablement metrics and test overrides.
	ca := &clientAdapter{utilfeature.DefaultMutableFeatureGate}
	runtime.Must(clientfeatures.AddFeaturesToExistingFeatureGates(ca))
	clientfeatures.ReplaceFeatureGates(ca)
}
