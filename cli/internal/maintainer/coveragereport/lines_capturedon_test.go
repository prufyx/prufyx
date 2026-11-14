// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func linesWith(file, proj string) []byte {
	return []byte(fmt.Sprintf(`{"schema":%q,%s"projects":{"other":{"lines":["1.0","1.1"]},"kubernetes":{%s"lines":["1.30","1.31"]}}}`, LinesSchema, file, proj))
}

func TestProjectCapturedOnParse(t *testing.T) {
	t.Parallel()
	ok := linesWith(`"capturedOn":"2026-10-31","pinnedOn":"2026-11-10",`, `"capturedOn":"2026-11-10",`)
	f, err := ParseLines(ok)
	if err != nil || f.Projects["kubernetes"].CapturedOn != "2026-11-10" || f.Projects["other"].CapturedOn != "" {
		t.Fatalf("%+v %v", f, err)
	}
	if _, err := ParseLines(linesWith(`"capturedOn":"2026-10-31",`, "")); err != nil {
		t.Fatal(err)
	}
	bad := map[string][]byte{
		"malformed":        linesWith(`"capturedOn":"2026-10-31","pinnedOn":"2026-11-10",`, `"capturedOn":"10-11-2026",`),
		"impossible date":  linesWith(`"capturedOn":"2026-10-31","pinnedOn":"2026-11-10",`, `"capturedOn":"2026-02-31",`),
		"after pinnedOn":   linesWith(`"capturedOn":"2026-10-31","pinnedOn":"2026-11-10",`, `"capturedOn":"2026-11-11",`),
		"after capturedOn": linesWith(`"capturedOn":"2026-10-31",`, `"capturedOn":"2026-11-01",`),
		"file undated":     linesWith("", `"capturedOn":"2026-11-01",`),
	}
	for name, raw := range bad {
		if _, err := ParseLines(raw); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestProjectCapturedOnMarshalRoundTrip(t *testing.T) {
	t.Parallel()
	raw := linesWith(`"capturedOn":"2026-10-31","pinnedOn":"2026-11-10",`, `"capturedOn":"2026-11-10",`)
	f, err := ParseLines(raw)
	if err != nil {
		t.Fatal(err)
	}
	out, err := MarshalLines(f)
	if err != nil {
		t.Fatal(err)
	}
	g, err := ParseLines(out)
	if err != nil || !reflect.DeepEqual(f, g) {
		t.Fatalf("round trip: %v", err)
	}
	out2, _ := MarshalLines(g)
	if !bytes.Equal(out, out2) {
		t.Fatal("marshal not stable")
	}
	// Absent field: omitted from the bytes.
	old, _ := ParseLines(linesWith(`"capturedOn":"2026-10-31",`, ""))
	oldOut, _ := MarshalLines(old)
	if strings.Count(string(oldOut), "capturedOn") != 1 {
		t.Fatalf("old format gained a member: %s", oldOut)
	}
}

// The per-project date and the additions' own date give the same report for
// the same data.
func TestProjectCapturedOnEqualsAdditionCapture(t *testing.T) {
	t.Parallel()
	e := sealed(t, "kubernetes", "v1.30.0\nv1.31.0\n", "2026-10-08")
	add := additionsJSON(t, map[string]AdditionEntry{"kubernetes": e})
	viaAdd, err := Compute(Input{Pack: pack(nil, nil), Lines: pinnedLines("2026-09-01", "2026-10-08"), Additions: add, Now: allNow, All: true})
	if err != nil {
		t.Fatal(err)
	}
	// Same data, carried in the lines file.
	var f LinesFile
	if err := json.Unmarshal(pinnedLines("2026-09-01", "2026-10-08"), &f); err != nil {
		t.Fatal(err)
	}
	pl := e.ProjectLines
	pl.CapturedOn = "2026-10-08"
	f.Projects["kubernetes"] = pl
	merged, err := MarshalLines(f)
	if err != nil {
		t.Fatal(err)
	}
	viaLines, err := Compute(Input{Pack: pack(nil, nil), Lines: merged, Now: allNow, All: true})
	if err != nil {
		t.Fatal(err)
	}
	pick := func(r Report) *Completion {
		for _, p := range r.Projects {
			if p.Project == "kubernetes" {
				return p.Completion
			}
		}
		t.Fatal("no project")
		return nil
	}
	if !reflect.DeepEqual(pick(viaAdd), pick(viaLines)) || !reflect.DeepEqual(viaAdd.Fleet, viaLines.Fleet) {
		t.Fatalf("differs: %+v vs %+v", pick(viaAdd), pick(viaLines))
	}
}
