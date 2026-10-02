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
	"k8s.io/apimachinery/pkg/util/version"
	genericfeatures "k8s.io/apiserver/pkg/features"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	clientfeatures "k8s.io/client-go/features"
	"k8s.io/component-base/featuregate"
	zpagesfeatures "k8s.io/component-base/zpages/features"
	kcmfeatures "k8s.io/controller-manager/pkg/features"
)

// Every feature gate should have an entry here following this template:
//
// // owner: @username
// // kep: https://kep.k8s.io/NNN
// MyFeature featuregate.Feature = "MyFeature"
//
// Feature gates should be listed in alphabetical, case-sensitive
// (upper before any lower case character) order. This reduces the risk
// of code conflicts because changes are more likely to be scattered
// across the file.
const (
	// owner: @aojea
	//
	// Allow kubelet to request a certificate without any Node IP available, only
	// with DNS names.
	AllowDNSOnlyNodeCSR featuregate.Feature = "AllowDNSOnlyNodeCSR"
)

// defaultVersionedKubernetesFeatureGates consists of all known Kubernetes-specific feature keys with VersionedSpecs.
// To add a new feature, define a key for it in pkg/features/kube_features.go and add it here. The features will be
// available throughout Kubernetes binaries.
// For features available via specific kubernetes components like apiserver,
// cloud-controller-manager, etc find the respective kube_features.go file
// (eg:staging/src/apiserver/pkg/features/kube_features.go), define the versioned
// feature gate there, and reference it in this file.
// To support n-3 compatibility version, features may only be removed 3 releases after graduation.
//
// Entries are alphabetized.
var defaultVersionedKubernetesFeatureGates = map[featuregate.Feature]featuregate.VersionedSpecs{
	AllowDNSOnlyNodeCSR: {
		{Version: version.MustParse("1.0"), Default: true, PreRelease: featuregate.GA},
		{Version: version.MustParse("1.31"), Default: false, PreRelease: featuregate.Deprecated},
	},

	genericfeatures.WatchList: {
		{Version: version.MustParse("1.27"), Default: false, PreRelease: featuregate.Alpha},
		{Version: version.MustParse("1.32"), Default: true, PreRelease: featuregate.Beta},
		// switch this back to false because the json and proto streaming encoders appear to work better.
		{Version: version.MustParse("1.33"), Default: false, PreRelease: featuregate.Beta},
		{Version: version.MustParse("1.34"), Default: true, PreRelease: featuregate.Beta},
	},

	zpagesfeatures.ComponentStatusz: {
		{Version: version.MustParse("1.32"), Default: false, PreRelease: featuregate.Alpha},
		{Version: version.MustParse("1.36"), Default: true, PreRelease: featuregate.Beta},
	},
}

// defaultKubernetesFeatureGateDependencies enumerates the dependencies of any feature gate that
// depends on another. Dependencies ensure that a dependent feature gate can only be enabled if all
// of its dependencies are also enabled, and ensures a feature at a higher stability level cannot
// depend on a less stable feature.
//
// Entries are alphabetized.
var defaultKubernetesFeatureGateDependencies = map[featuregate.Feature][]featuregate.Feature{
	AllowDNSOnlyNodeCSR:             {},
	genericfeatures.WatchList:       {},
	zpagesfeatures.ComponentStatusz: {},
}

func init() {
	// Register all client-go features with kube's feature gate instance and make all client-go
	// feature checks use kube's instance. The effect is that for kube binaries, client-go
	// features are wired to the existing --feature-gates flag just as all other features
	// are. Further, client-go features automatically support the existing mechanisms for
	// feature enablement metrics and test overrides.
	ca := &clientAdapter{utilfeature.DefaultMutableFeatureGate}
	runtime.Must(clientfeatures.AddVersionedFeaturesToExistingFeatureGates(ca))
	clientfeatures.ReplaceFeatureGates(ca)

	runtime.Must(utilfeature.DefaultMutableFeatureGate.AddVersioned(defaultVersionedKubernetesFeatureGates))
	runtime.Must(utilfeature.DefaultMutableFeatureGate.AddDependencies(defaultKubernetesFeatureGateDependencies))
	runtime.Must(zpagesfeatures.AddFeatureGates(utilfeature.DefaultMutableFeatureGate))
}
