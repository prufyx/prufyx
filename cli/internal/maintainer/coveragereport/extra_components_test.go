// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// A reviewed extra component of a catalog project attributes its pairs to
// the owning project, adds no project row and never overrides another
// source. Nil or empty extras change nothing.
func TestExtraComponentAttribution(t *testing.T) {
	const other = "pkg:github/example/other"
	atts := []string{crdAttJSON("0.50", "0.49.0", "0.50.0"), crdAttJSON("0.51", "0.50.0", "0.51.0")}
	releases := `"releases":{"0.49":["0.49.0"],"0.50":["0.50.0"],"0.51":["0.51.0"]}`
	ruleless := fmt.Sprintf(`{"schema":%q,"projects":{"strimzi":{"lines":["0.49","0.50","0.51"],%s}}}`, LinesSchema, releases)
	owned := fmt.Sprintf(`{"schema":%q,"projects":{"strimzi":{"component":%q,"lines":["0.49","0.50","0.51"],%s}}}`, LinesSchema, strimzi, releases)
	for _, tc := range []struct {
		name  string
		lines string
		extra map[string]string
		want  string
	}{
		{"listed component of the project", ruleless, map[string]string{strimzi: "strimzi"}, "AA"},
		{"nil extras", ruleless, nil, "GG"},
		{"empty extras", ruleless, map[string]string{}, "GG"},
		{"component listed for another project", ruleless, map[string]string{strimzi: "dup"}, "GG"},
		{"other component listed", ruleless, map[string]string{other: "strimzi"}, "GG"},
		{"empty owner", ruleless, map[string]string{strimzi: ""}, "GG"},
		{"empty component", ruleless, map[string]string{"": "strimzi"}, "GG"},
		{"snapshot owner wins", owned, map[string]string{strimzi: "dup"}, "AA"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report, err := Compute(Input{Pack: pack(nil, atts), Lines: []byte(tc.lines), Now: baselineNow, ExtraComponents: tc.extra})
			if err != nil {
				t.Fatal(err)
			}
			if len(report.Projects) != 1 || report.Fleet.Projects != 1 {
				t.Fatalf("project rows %d / %d", len(report.Projects), report.Fleet.Projects)
			}
			if got := statuses(report.Projects[0]); got != tc.want {
				t.Fatalf("statuses = %s, want %s", got, tc.want)
			}
		})
	}
	// Absent, nil and empty extras give byte-identical reports.
	base := Input{Pack: pack(nil, atts), Lines: []byte(ruleless), Now: baselineNow}
	a, _ := Compute(base)
	base.ExtraComponents = map[string]string{}
	b, _ := Compute(base)
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) || strings.Contains(string(jb), "extraComponents") {
		t.Fatal("empty extras changed the report")
	}
	base.ExtraComponents = map[string]string{strimzi: "strimzi", "": "strimzi", other: ""}
	c, _ := Compute(base)
	if c.ExtraComponents != 1 || len(c.Projects) != 1 {
		t.Fatalf("component count %d rows %d", c.ExtraComponents, len(c.Projects))
	}
}
