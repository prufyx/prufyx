package coveragereport_test

import (
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/coveragereport"
	impl "github.com/prufyx/prufyx/cli/internal/maintainer/coveragereport"
)

func TestComputeMatchesImplementation(t *testing.T) {
	dir := "../internal/maintainer/coveragereport/testdata/"
	pack, err := os.ReadFile(dir + "pack-cncf-2026-09-13.4-reduced.json")
	if err != nil {
		t.Fatal(err)
	}
	lines, err := os.ReadFile(dir + "lines-2026-10-08.json")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	got, err := coveragereport.Compute(coveragereport.Input{Pack: pack, Lines: lines, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	want, err := impl.Compute(impl.Input{Pack: pack, Lines: lines, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Projects) == 0 || got.Fleet.Pairs == 0 {
		t.Fatal("empty report")
	}
	if got.Schema != coveragereport.SchemaReport {
		t.Fatalf("schema %q", got.Schema)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("public Compute differs from the implementation")
	}
}

func TestCRDHelpersMatchImplementation(t *testing.T) {
	got, want := coveragereport.CRDProjectComponents(), impl.CRDProjectComponents()
	if len(got) == 0 || !reflect.DeepEqual(got, want) {
		t.Fatalf("components differ: %d vs %d", len(got), len(want))
	}
	if coveragereport.CRDProjectCount() != impl.CRDProjectCount() {
		t.Fatal("count differs")
	}
	in := coveragereport.DefaultInput([]byte("p"), []byte("c"), []byte("l"), time.Unix(0, 0))
	if !in.All || in.Window != 0 || in.Declared != nil || in.CRDVersionProjects != len(got) || !reflect.DeepEqual(in.CRDTargetComponents, got) || string(in.CommunityPack) != "c" {
		t.Fatalf("DefaultInput: %+v", in)
	}
}
