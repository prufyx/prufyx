// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"testing"

	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// ageClocks are evaluation instants before, inside and after the last
// 30 days of the embedded knowledge's rules.
var ageClocks = []struct{ name, now string }{
	{"before", "2026-10-04T00:00:00Z"},
	{"inside", "2026-11-20T00:00:00Z"},
	{"after", "2026-12-10T00:00:00Z"},
}

// TestScanOutputUnchangedNearExpiry: stdout in every format and the exit
// code of a scan do not depend on how close the knowledge is to its end: the
// golden files were written before the age note existed and only the clock
// they record differs between them.
func TestScanOutputUnchangedNearExpiry(t *testing.T) {
	dir, _ := files(t, map[string]string{"applyset.yaml": cronjobV1beta1})
	extensions := map[string]string{"human": "txt", "json": "json", "sarif": "sarif", "markdown": "md", "csv": "csv"}
	inDir(t, dir, func() {
		for _, clock := range ageClocks {
			result := mustScan(t, nil, append(append([]string{"applyset.yaml"}, declared...), "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3", "--now", clock.now)...)
			if result.Exit != scanreport.ExitBlocked && result.Exit != scanreport.ExitUnknown {
				t.Fatalf("%s: exit %d", clock.name, result.Exit)
			}
			for _, format := range scanreport.Formats() {
				out, err := scanreport.Render(result.Report, format, scanreport.RenderOptions{Verbose: true, ShowPasses: true})
				if err != nil {
					t.Fatal(err)
				}
				golden(t, "knowledge-age-"+clock.name+"."+extensions[format], out)
			}
			golden(t, "knowledge-age-"+clock.name+".exit", []byte{byte('0' + result.Exit/10), byte('0' + result.Exit%10), '\n'})
		}
	})
}
