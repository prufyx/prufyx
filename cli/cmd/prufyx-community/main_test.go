// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRunRoutesPublicHelpWithoutLegacyApp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "prufyx check cert-manager-values") || strings.Contains(stdout.String(), "prufyx-community") {
		t.Fatalf("help=%q", stdout.String())
	}
}
