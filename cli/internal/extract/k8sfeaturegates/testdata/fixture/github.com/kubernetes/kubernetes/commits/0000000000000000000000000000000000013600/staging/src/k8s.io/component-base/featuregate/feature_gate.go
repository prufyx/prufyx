/*
Copyright 2016 The Kubernetes Authors.

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

package featuregate

import (
	"context"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/spf13/pflag"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/naming"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/version"
	featuremetrics "k8s.io/component-base/metrics/prometheus/feature"
	baseversion "k8s.io/component-base/version"
	"k8s.io/klog/v2"
)

type Feature string

const (
	// allAlphaGate is a global toggle for alpha features. Per-feature key
	// values override the default set by allAlphaGate. Examples:
	//   AllAlpha=false,NewFeature=true  will result in newFeature=true
	//   AllAlpha=true,NewFeature=false  will result in newFeature=false
	allAlphaGate Feature = "AllAlpha"

	// allBetaGate is a global toggle for beta features. Per-feature key
	// values override the default set by allBetaGate. Examples:
	//   AllBeta=false,NewFeature=true  will result in NewFeature=true
	//   AllBeta=true,NewFeature=false  will result in NewFeature=false
	allBetaGate Feature = "AllBeta"
)

// unsafeSetFromMap stores flag gates for known features from a map[string]bool into an enabled map.
func (f *featureGate) unsafeSetFromMap(logger klog.Logger, enabled map[Feature]bool, m map[string]bool, emulationVersion, minCompatibilityVersion *version.Version) []error {
	helper, logger := logger.WithCallStackHelper()
	helper()

	var errs []error
	// Copy existing state
	known := map[Feature]VersionedSpecs{}
	for k, v := range f.known.Load().(map[Feature]VersionedSpecs) {
		known[k] = v
	}

	for k, v := range m {
		key := Feature(k)
		versionedSpecs, ok := known[key]
		if !ok {
			// early return if encounters an unknown feature.
			errs = append(errs, fmt.Errorf("unrecognized feature gate: %s", k))
			return errs
		}
		featureSpec := featureSpecAtEmulationAndMinCompatVersion(versionedSpecs, emulationVersion, minCompatibilityVersion)
		if featureSpec.LockToDefault && featureSpec.Default != v {
			errs = append(errs, fmt.Errorf("cannot set feature gate %v to %v, feature is locked to %v", k, v, featureSpec.Default))
			continue
		}
		// Handle "special" features like "all alpha gates"
		if fn, found := f.special[key]; found {
			fn(known, enabled, v, emulationVersion, minCompatibilityVersion)
			enabled[key] = v
			continue
		}
		if featureSpec.PreRelease == PreAlpha {
			errs = append(errs, fmt.Errorf("cannot set feature gate %v to %v, feature is PreAlpha at emulated version %s, min compatibility version %s", k, v, emulationVersion, minCompatibilityVersion))
			continue
		}
		enabled[key] = v

		if featureSpec.PreRelease == Deprecated {
			logger.Info("Warning: setting deprecated feature gate. It will be removed in a future release.", "featureGate", k, "value", v)
		} else if featureSpec.PreRelease == GA {
			logger.Info("Warning: setting GA feature gate. It will be removed in a future release.", "featureGate", k, "value", v)
		}
	}

	if len(errs) > 0 {
		return errs
	}

	// If enabled features were set successfully, validate them against the dependencies.
	dependencies := *f.dependencies.Load()
	for feature, deps := range dependencies {
		if !featureEnabled(feature, enabled, known, emulationVersion, minCompatibilityVersion) {
			continue
		}

		var disabledDeps []Feature
		for _, dep := range deps {
			if !featureEnabled(dep, enabled, known, emulationVersion, minCompatibilityVersion) {
				disabledDeps = append(disabledDeps, dep)
			}
		}
		if len(disabledDeps) > 0 {
			errs = append(errs, fmt.Errorf("%s is enabled, but depends on features that are disabled: %v", feature, disabledDeps))
		}
	}

	return errs
}
