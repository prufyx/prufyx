// SPDX-License-Identifier: AGPL-3.0-only

package currentbundle

import (
	"context"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/observation"
)

func buildTestPath(t testing.TB, path string, options Options) (Artifact, error) {
	t.Helper()
	root, err := observation.OpenPath(path)
	if err != nil {
		return Artifact{}, err
	}
	defer root.Close()
	return BuildObservation(context.Background(), root, options)
}

func importTestPath(t testing.TB, path string, options Options) (CurrentBundle, error) {
	t.Helper()
	root, err := observation.OpenPath(path)
	if err != nil {
		return CurrentBundle{}, err
	}
	defer root.Close()
	return ImportObservation(context.Background(), root, options)
}
