// SPDX-License-Identifier: AGPL-3.0-only

package onecommand

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/imageidentity"
)

// Once every image-source record is past validUntil, a project known only
// through the image registry is INDETERMINATE: no version is read from its
// image, and it is neither applicable nor reported absent.
func TestLapsedImageRecordsLeaveProjectsIndeterminate(t *testing.T) {
	images := []string{"ghcr.io/cloudnative-pg/cloudnative-pg:1.29.0", "mariadb:10.11.8"}
	registry := imageidentity.ObservableComponents(time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC))
	for _, project := range []string{"cloudnativepg", "mariadb"} {
		if _, ok := registry[project]; !ok {
			t.Fatalf("control: %s has no current image record", project)
		}
	}
	lapsed := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, image := range images {
		if got := imageidentity.Match(image, lapsed); got.Version != "" || got.Component != "" || !strings.Contains(got.Reason, "past validUntil") {
			t.Fatalf("%s: %+v", image, got)
		}
	}

	options := baseTestOptions(t, &imagesRunner{fakeRunner: fakeRunner{t: t}, images: images})
	options.Now = func() time.Time { return lapsed }
	var stdout, stderr bytes.Buffer
	report, code := Run(context.Background(), options, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	seen := 0
	for _, c := range report.Contexts[0].Checks {
		if _, registryOnly := registry[c.Project]; !registryOnly {
			continue
		}
		seen++
		if c.Applicability != IndeterminateNotObservable || c.ObservedVersion != "" || c.Reason == "" || len(c.Command) == 0 {
			t.Fatalf("%s %s: %+v", c.Project, c.RuleID, c)
		}
	}
	if seen == 0 {
		t.Fatal("no registry-only check was assessed")
	}
}
