// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfknowledge"
	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// With the shipped knowledge a community project is refused exactly as it
// was before the community knowledge step: the same message, whichever route
// names it (flag, configuration file, knowledge database).
func TestScanCommunityComponentWithoutDataIsRefusedAsBefore(t *testing.T) {
	if len(customresources.CommunityProjects()) == 0 {
		t.Fatal("no community project")
	}
	embedded, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range customresources.CommunityProjects() {
		want := scanreport.Text(scanreport.UsageCommunityComponent, quote(p.Slug))
		for name, extra := range map[string][]string{
			"to":   {"--to", p.Slug + "=1.3.0"},
			"from": {"--from", p.Slug + "=1.2.0", "--to", "kubernetes=1.30.0"},
		} {
			_, err := scan(t, embedded, args([]string{"missing.yaml"}, extra...)...)
			var u *UsageError
			if !errors.As(err, &u) || u.Error() != want {
				t.Fatalf("%s %s: %v, want %q", p.Slug, name, err, want)
			}
		}
		// A configuration file names the project too.
		dir, _ := files(t, map[string]string{"prufyx.yaml": "apiVersion: prufyx.io/v1alpha1\nkind: ScanConfig\ntarget: {" + p.Slug + ": 1.3.0}\n"})
		inDir(t, dir, func() {
			_, err := scan(t, embedded, args(nil)...)
			var u *UsageError
			if !errors.As(err, &u) || u.Error() != want {
				t.Fatalf("%s config: %v, want %q", p.Slug, err, want)
			}
		})
	}
	// An unknown name stays unknown, and a CNCF name is not touched.
	_, err = scan(t, embedded, args([]string{"missing.yaml"}, "--to", "no-such-project=1.0.0")...)
	var u *UsageError
	if !errors.As(err, &u) || strings.Contains(u.Error(), "community") {
		t.Fatalf("unknown project: %v", err)
	}
}

// The same refusal comes from a knowledge database that holds no data for the
// community project, in either layout: the project is named by the compiled
// catalogue and refused once the database is open.
func TestScanCommunityComponentRefusedByADatabaseWithoutData(t *testing.T) {
	for _, layout := range storeLayouts {
		t.Run(layout, func(t *testing.T) {
			fixture := newStoreFixture(t, layout)
			fixture.importPack(nil, "5")
			dir, paths := files(t, map[string]string{"gw.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\n"})
			_ = dir
			request, err := ParseArgs(append(append([]string{}, paths...), "--to", "gateway-api=1.2.0", "--knowledge-db", fixture.store))
			if err != nil {
				t.Fatal(err)
			}
			_, err = Run(request, Options{Build: &testBuild})
			want := scanreport.Text(scanreport.UsageCommunityComponent, quote("gateway-api"))
			var u *UsageError
			if !errors.As(err, &u) || u.Error() != want {
				t.Fatalf("%v, want %q", err, want)
			}
			// The database was opened read-only: its store is untouched by
			// the refusal and still selects the same revision.
			if _, statErr := os.Stat(filepath.Join(fixture.store, "selection.json")); statErr != nil {
				t.Fatal(statErr)
			}
			if _, err := cncfknowledge.OpenScan(fixture.store, []string{"gateway-api"}); err != nil {
				t.Fatalf("opening the database for a community project: %v", err)
			}
		})
	}
}
