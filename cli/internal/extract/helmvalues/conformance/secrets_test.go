// SPDX-License-Identifier: AGPL-3.0-only

package conformance

// Values supplied through a Helm release Secret are not read. A release is
// stored by Helm in a Secret of type helm.sh/release.v1 whose payload holds
// the release (values included). Two guards: the manifest reader drops every
// Secret payload before any value is kept, and no Go source of the module
// decodes a Helm release.

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/intake"
)

const releaseSecret = `apiVersion: v1
kind: Secret
metadata:
  name: sh.helm.release.v1.keda.v3
  namespace: keda
  labels: {owner: helm, name: keda, status: deployed, version: "3"}
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: '{"data":{"release":"canary-last-applied"}}'
type: helm.sh/release.v1
data:
  release: canary-release-payload
stringData:
  release: canary-release-string
`

func TestReleaseSecretPayloadIsDropped(t *testing.T) {
	ws, err := intake.Decode("release.yaml", []byte(releaseSecret))
	if err != nil {
		t.Fatal(err)
	}
	if len(ws.Documents) != 1 || ws.Documents[0].Kind != "Secret" {
		t.Fatalf("documents %+v", ws.Documents)
	}
	doc := ws.Documents[0].Value
	for _, k := range []string{"data", "stringData"} {
		if _, ok := doc[k]; ok {
			t.Errorf("%s kept", k)
		}
	}
	if all := fmt.Sprintf("%#v", ws); strings.Contains(all, "canary-") {
		t.Errorf("a payload survives in the decoded workspace")
	}
}

// No non-test Go source of the module names a Helm release Secret or a
// Secret-reading helper, so no code path can take values from one. Adding
// such a path makes this test fail until it is reviewed.
func TestNoSourceDecodesAHelmRelease(t *testing.T) {
	root := filepath.Join("..", "..", "..", "..") // cli/
	tokens := []string{"sh.helm.release", "helm.sh/release", "release.v1", "ReadSecret"}
	checked := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" || d.Name() == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		checked++
		for _, tok := range tokens {
			if strings.Contains(string(raw), tok) {
				t.Errorf("%s names %q", path, tok)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 300 {
		t.Fatalf("walked %d source files; the path to cli/ is wrong", checked)
	}
}
