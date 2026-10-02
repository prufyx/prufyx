/*
Copyright 2024 The Kubernetes Authors.

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
	"k8s.io/apimachinery/pkg/util/version"
)

// Every feature gate should have an entry here following this template:
//
// // owner: @username
// // alpha: v1.4
// MyFeature featuregate.Feature = "MyFeature"
//
// Feature gates should be listed in alphabetical, case-sensitive
// (upper before any lower case character) order. This reduces the risk
// of code conflicts because changes are more likely to be scattered
// across the file.
const (
	// owner: @p0lyn0mial
	// beta: v1.30
	//
	// Allow the client to get a stream of individual items instead of chunking from the server.
	WatchListClient Feature = "WatchListClient"
)

// defaultVersionedKubernetesFeatureGates consists of all known Kubernetes-specific feature keys.
//
// To add a new feature, define a key for it above and add it here.
// After registering with the binary, the features are, by default, controllable using environment variables.
// For more details, please see envVarFeatureGates implementation.
var defaultVersionedKubernetesFeatureGates = map[Feature]VersionedSpecs{
	WatchListClient: {
		{Version: version.MustParse("1.30"), Default: false, PreRelease: Beta},
		{Version: version.MustParse("1.35"), Default: true, PreRelease: Beta},
	},
}
