// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/scanconfig"
)

const checkCNCFArgumentError = "invalid CNCF check arguments; use --help"

// parsesAsRouteFlags reports whether `check cncf` gets past flag parsing with
// these arguments. A flag that does not exist, a missing value and a value of
// the wrong type all fail parsing with the generic argument error; once the
// flags parse, the route reports a different, mode-specific error.
func parsesAsRouteFlags(args ...string) bool {
	var stdout, stderr bytes.Buffer
	full := append([]string{"check", "cncf", "--project", "kubernetes"}, args...)
	Run(context.Background(), full, &stdout, &stderr, "test")
	return !strings.Contains(stderr.String(), checkCNCFArgumentError)
}

func TestDeclarationsMapToRouteFlags(t *testing.T) {
	t.Parallel()
	if !parsesAsRouteFlags("--native-resource=x") || parsesAsRouteFlags("--no-such-flag-zz") || parsesAsRouteFlags("--no-such-flag-zz=true") {
		t.Fatal("the flag-parsing probe does not tell an unknown flag from a known route")
	}
	var help bytes.Buffer
	Run(context.Background(), []string{"check", "cncf", "--help"}, &help, &bytes.Buffer{}, "test")
	var kubernetesUsage string
	for _, line := range strings.Split(help.String(), "\n") {
		if strings.Contains(line, "--project kubernetes --native-resource") {
			kubernetesUsage = line
		}
	}
	if kubernetesUsage == "" {
		t.Fatal("usage text has no Kubernetes native-resource line")
	}
	declarations := scanconfig.Declarations()
	if len(declarations) == 0 {
		t.Fatal("no declarations")
	}
	for _, d := range declarations {
		if d.Project != "kubernetes" {
			t.Errorf("%s: v1 declarations map to the Kubernetes route only", d.Key)
			continue
		}
		flag := "--" + d.Flag
		if !strings.Contains(kubernetesUsage, flag) {
			t.Errorf("%s: %s is not in the Kubernetes native-resource usage", d.Key, flag)
		}
		switch d.Kind {
		case scanconfig.FlagBool:
			// A boolean flag stands alone and takes only true or false.
			if !parsesAsRouteFlags(flag) || !parsesAsRouteFlags(flag+"=true") || !parsesAsRouteFlags(flag+"=false") || parsesAsRouteFlags(flag+"=maybe") {
				t.Errorf("%s: %s is not a boolean flag", d.Key, flag)
			}
		case scanconfig.FlagString:
			// A string flag needs a value and takes any text.
			if parsesAsRouteFlags(flag) || !parsesAsRouteFlags(flag+"=maybe") || !parsesAsRouteFlags(flag, "maybe") {
				t.Errorf("%s: %s is not a string flag", d.Key, flag)
			}
		default:
			t.Errorf("%s: unknown flag kind %q", d.Key, d.Kind)
		}
		for _, value := range d.Values {
			if !parsesAsRouteFlags(flag + "=" + value) {
				t.Errorf("%s: value %q is not accepted", d.Key, value)
			}
		}
	}
}
