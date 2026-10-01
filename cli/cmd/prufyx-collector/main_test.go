// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRunRequiresCollectAndExplicitAuthority(t *testing.T) {
	for _, args := range [][]string{
		nil, {"status"}, {"collect"}, {"collect", "/tmp/out"},
		{"collect", "/tmp/out", "--component-configuration-profile", "v3", "context"},
		{"collect", "/tmp/out", "--kubeconfig", "a", "--kubeconfig", "b", "context"},
	} {
		var out, err bytes.Buffer
		code := run(context.Background(), args, &out, &err)
		if code != 2 {
			t.Fatalf("args=%q exit=%d", args, code)
		}
		if strings.Contains(err.String(), "token=") {
			t.Fatal("unexpected private diagnostic")
		}
	}
}

func TestRunRedactsInvalidOptionAndProvidesHelp(t *testing.T) {
	const canary = "PRIVATE_OPTION_VALUE_NEVER_PRINT"
	var out, stderr bytes.Buffer
	if code := run(context.Background(), []string{"collect", "/tmp/out", "--unknown=" + canary}, &out, &stderr); code != 2 {
		t.Fatalf("invalid option exit=%d", code)
	}
	if strings.Contains(out.String()+stderr.String(), canary) {
		t.Fatal("invalid raw option value escaped")
	}
	out.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"collect", "--help"}, &out, &stderr); code != 0 || !strings.Contains(out.String(), "Usage:") {
		t.Fatalf("help exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
}

func TestRunRecognizesSingleDashSingletonDuplicates(t *testing.T) {
	var out, stderr bytes.Buffer
	args := []string{"collect", "/tmp/out", "-kubeconfig", "first-private", "--kubeconfig", "second-private", "context"}
	if code := run(context.Background(), args, &out, &stderr); code != 2 || !strings.Contains(stderr.String(), "singleton") {
		t.Fatalf("duplicate exit=%d stderr=%q", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "first-private") || strings.Contains(stderr.String(), "second-private") {
		t.Fatal("duplicate option values escaped")
	}
}
