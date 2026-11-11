package extractcli

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/customresources"
)

// ownedArgoFixture gives these CLI tests owned identities without changing the
// shared extractor fixture or its synthetic version transitions.
func ownedArgoFixture(t *testing.T) (string, string) {
	t.Helper()
	for _, kind := range []string{"Application", "AppProject"} {
		owner, attribution := customresources.DefaultIndex().OwnerOf("argoproj.io", kind)
		if owner != "argo-cd" || attribution != customresources.Owned {
			t.Fatalf("argoproj.io/%s: owner=%q attribution=%v", kind, owner, attribution)
		}
	}
	source := "../crdversions/testdata/fixture"
	dest := filepath.Join(t.TempDir(), "fixture")
	err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dest, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		switch entry.Name() {
		case "widget-crd.yaml":
			data = []byte(strings.NewReplacer("fixture.argoproj.io", "argoproj.io", "Widget", "Application", "widgets", "applications", "widget", "application").Replace(string(data)))
		case "gadget-crd.yaml":
			data = []byte(strings.NewReplacer("fixture.argoproj.io", "argoproj.io", "Gadget", "AppProject", "gadgets", "appprojects", "gadget", "appproject").Replace(string(data)))
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	oracle, err := os.ReadFile("../crdversions/testdata/oracle-fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	oracle = []byte(strings.NewReplacer("fixture.argoproj.io/v1alpha2/Widget", "argoproj.io/v1alpha2/Application", "fixture.argoproj.io/v1beta1/Gadget", "argoproj.io/v1beta1/AppProject").Replace(string(oracle)))
	oraclePath := filepath.Join(t.TempDir(), "oracle.json")
	if err := os.WriteFile(oraclePath, oracle, 0o644); err != nil {
		t.Fatal(err)
	}
	return dest, oraclePath
}
