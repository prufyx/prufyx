// SPDX-License-Identifier: AGPL-3.0-only

package supersedeids

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The shipped pack is wholly one generation.
func TestShippedPackIsOneGeneration(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "cncfcheck", "data", "rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	superseded, err := Generation(raw)
	if err != nil {
		t.Fatal(err)
	}
	if superseded != Superseded() {
		t.Fatalf("Superseded() = %v, Generation = %v", Superseded(), superseded)
	}
	if len(ReviewedIDs()) != 25 || len(AddedIDs()) != 4 || len(ReplacementIDs()) != 25 {
		t.Fatalf("id sets %d/%d/%d", len(ReviewedIDs()), len(AddedIDs()), len(ReplacementIDs()))
	}
	for _, id := range ReviewedIDs() {
		if want := ReplacementIDs()[id]; superseded && ID(id) != want || !superseded && ID(id) != id {
			t.Fatalf("ID(%s) = %s", id, ID(id))
		}
	}
}

// A pack holding only part of a generation, or both, is refused.
func TestGenerationRefusesMixedPacks(t *testing.T) {
	for _, pack := range []string{
		`{"entries":[]}`,
		`{"entries":[{"rule":{"id":"kubernetes.served-api-removal.x"}}]}`,
		`{"entries":[{"rule":{"id":"kubernetes.pdb-v1beta1-removed.1-24-0-to-1-25-0"}}]}`,
	} {
		if _, err := Generation([]byte(pack)); err == nil {
			t.Errorf("accepted %s", pack)
		}
	}
}

// packOf renders a pack of rules {id, reviewedAt, validUntil}.
func packOf(rules ...[3]string) []byte {
	var entries []string
	for _, r := range rules {
		entries = append(entries, fmt.Sprintf(`{"rule":{"id":%q,"evidence":{"state":"active","reviewedAt":%q,"validUntil":%q}}}`, r[0], r[1], r[2]))
	}
	return []byte(`{"entries":[` + strings.Join(entries, ",") + `]}`)
}

// The shared clock is derived from the pack: 17 days before the day of the
// earliest expiry, but after every Kubernetes review, and before every
// Kubernetes expiry.
func TestClockOf(t *testing.T) {
	other := [3]string{"other.rule", "2026-09-08T12:07:56Z", "2026-12-07T12:07:56Z"}
	cases := []struct {
		name string
		pack []byte
		want string // "" for an error
	}{
		{"reviewed pack (today)", packOf(other, [3]string{"kubernetes.pdb-v1beta1-removed.1-24-0-to-1-25-0", "2026-09-23T13:55:00Z", "2026-12-22T13:55:00Z"}), "2026-11-20T00:00:00Z"},
		{"mechanical rules derived on 2026-11-12", packOf(other, [3]string{"kubernetes.served-api-removal.x", "2026-11-12T08:45:25Z", "2027-01-27T08:45:25Z"}), "2026-11-20T00:00:00Z"},
		{"derived the day of the clock", packOf(other, [3]string{"kubernetes.served-api-removal.x", "2026-11-20T08:45:25Z", "2027-02-03T08:45:25Z"}), "2026-11-21T00:00:00Z"},
		// Derived after the other rules expired: no instant holds both (the error
		// says to renew the other rules first, checked below).
		{"derived after the earliest expiry", packOf(other, [3]string{"kubernetes.served-api-removal.x", "2026-12-10T08:45:25Z", "2027-03-03T08:45:25Z"}), ""},
		{"derived the day before the earliest expiry", packOf(other, [3]string{"kubernetes.served-api-removal.x", "2026-12-05T08:45:25Z", "2027-03-03T08:45:25Z"}), "2026-12-06T00:00:00Z"},
		{"derived on the day of the earliest expiry", packOf(other, [3]string{"kubernetes.served-api-removal.x", "2026-12-07T08:45:25Z", "2027-03-03T08:45:25Z"}), ""},
		// The same day with every other rule renewed too: the clock follows.
		{"everything renewed on 2026-12-10", packOf([3]string{"other.rule", "2026-12-10T00:00:00Z", "2027-03-10T00:00:00Z"}, [3]string{"kubernetes.served-api-removal.x", "2026-12-10T08:45:25Z", "2027-03-03T08:45:25Z"}), "2027-02-14T00:00:00Z"},
		{"lease shorter than the clock", packOf(other, [3]string{"kubernetes.served-api-removal.x", "2026-11-19T00:00:00Z", "2026-11-19T12:00:00Z"}), ""},
		// A Kubernetes rule that is not an API removal does not bound the clock.
		{"other Kubernetes rule", packOf(other, [3]string{"kubernetes.other", "2026-12-20T00:00:00Z", "2026-12-21T00:00:00Z"}), "2026-11-20T00:00:00Z"},
		{"no active rule", []byte(`{"entries":[]}`), ""},
		{"bad date", packOf([3]string{"other.rule", "2026-09-08T12:07:56Z", "soon"}), ""},
	}
	for _, c := range cases {
		got, err := ClockOf(c.pack)
		if c.want == "" {
			if err == nil {
				t.Errorf("%s: accepted, clock %s", c.name, got)
			} else if strings.HasPrefix(c.name, "derived ") && strings.Contains(c.name, "earliest expiry") && !strings.Contains(err.Error(), "renew the other rules first") {
				t.Errorf("%s: error %q does not say to renew the other rules first", c.name, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		want, _ := time.Parse(time.RFC3339, c.want)
		if !got.Equal(want) {
			t.Errorf("%s: clock %s, want %s", c.name, got.Format(time.RFC3339), c.want)
		}
	}
}

// The clock of the shipped pack, inside the age window of its earliest expiry
// and after every Kubernetes review.
func TestClockOfTheShippedPack(t *testing.T) {
	before, inside, after := AgeClocks()
	if !inside.Equal(Clock()) || ClockString() != inside.Format(time.RFC3339) || !before.Before(inside) || !inside.Before(after) {
		t.Fatalf("%s %s %s", before, inside, after)
	}
	raw, err := shippedPack()
	if err != nil {
		t.Fatal(err)
	}
	if again, err := ClockOf(raw); err != nil || !again.Equal(Clock()) {
		t.Fatalf("%v %v", again, err)
	}
}

// goList runs `go list` in the module root and returns its output lines. env
// adds environment entries such as GOOS=darwin. The go tool is the one on the
// PATH: `go test` puts $GOROOT/bin first there.
func goList(t *testing.T, env []string, args ...string) []string {
	t.Helper()
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("no go tool to list packages: %v", err)
	}
	cmd := exec.Command(goTool, append([]string{"list", "-buildvcs=false"}, args...)...)
	cmd.Dir = filepath.Join("..", "..", "..")
	cmd.Env = append(append(os.Environ(), "GOFLAGS=-mod=vendor"), env...)
	out, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			t.Fatalf("go list %v %v: %v\n%s", env, args, err, exit.Stderr)
		}
		t.Fatal(err)
	}
	return strings.Fields(string(out))
}

const (
	supersedeidsPath     = "github.com/prufyx/prufyx/cli/internal/extract/supersedeids"
	supersedefixturePath = "github.com/prufyx/prufyx/cli/internal/extract/supersedefixture"
	goldenfilePath       = "github.com/prufyx/prufyx/cli/internal/goldenfile"
)

// testOnly are the packages that exist for tests only.
var testOnly = []string{supersedeidsPath, supersedefixturePath, goldenfilePath}

// targets are the platforms the release builds, as GOOS/GOARCH.
var targets = []string{"linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64"}

// tagSets are the build-tag sets the binaries and the CI jobs use.
var tagSets = []string{"", "prufyx_synthetic_knowledge", "parityreview"}

func withTags(tags string, args ...string) []string {
	if tags == "" {
		return args
	}
	return append([]string{"-tags", tags}, args...)
}

// The test-only packages (supersedeids, supersedefixture, goldenfile) must not
// reach a binary: supersedeids reads the pack from the source tree through
// runtime.Caller and panics without it, and supersedefixture rebuilds a pack
// that was never shipped. Neither is a dependency of anything under cmd, for
// any release platform (linux and darwin, both architectures) and with or
// without the synthetic-knowledge and parityreview build tags, and no package
// imports them outside its tests.
func TestTestOnlyPackagesAreNotInAnyBinary(t *testing.T) {
	for _, target := range targets {
		goos, goarch, _ := strings.Cut(target, "/")
		env := []string{"GOOS=" + goos, "GOARCH=" + goarch, "CGO_ENABLED=0"}
		for _, tags := range tagSets {
			label := fmt.Sprintf("%s tags %q", target, tags)
			deps := goList(t, env, withTags(tags, "-deps", "./cmd/...")...)
			if len(deps) < 50 {
				t.Fatalf("%s: only %d dependencies listed, the guard is not looking at the binaries", label, len(deps))
			}
			for _, dep := range deps {
				for _, forbidden := range testOnly {
					if dep == forbidden {
						t.Errorf("%s: %s is a dependency of a binary", label, dep)
					}
				}
			}
			// Imports without _test files: a non-test importer anywhere, even of
			// a package no binary links today, is the first step to a binary.
			for _, forbidden := range testOnly {
				for _, importer := range goList(t, env, withTags(tags, "-f", `{{range .Imports}}{{if eq . "`+forbidden+`"}}{{$.ImportPath}} {{end}}{{end}}`, "./...")...) {
					// The fixture package builds on the id package.
					if importer != supersedefixturePath || forbidden != supersedeidsPath {
						t.Errorf("%s: %s imports %s outside its tests", label, importer, forbidden)
					}
				}
			}
		}
	}
}

// The guard sees an import when there is one: the test packages of a package
// that uses supersedeids list it among their dependencies.
func TestTestOnlyPackageGuardSeesTestImports(t *testing.T) {
	found := false
	for _, dep := range goList(t, nil, "-deps", "-test", "./internal/checkroutemetadata") {
		if dep == supersedeidsPath {
			found = true
		}
	}
	if !found {
		t.Fatal("go list -deps -test does not show the supersedeids import of checkroutemetadata's tests")
	}
}

// Window brackets the clock, and on today's pack is the window the fixtures
// always used.
func TestWindowBracketsTheClock(t *testing.T) {
	reviewed, until := Window(58, 30)
	r, err1 := time.Parse(time.RFC3339, reviewed)
	u, err2 := time.Parse(time.RFC3339, until)
	if err1 != nil || err2 != nil || !r.Before(Clock()) || !u.After(Clock()) || u.Sub(r) != 88*24*time.Hour {
		t.Fatalf("%s %s %v %v", reviewed, until, err1, err2)
	}
}

// The age instants follow the earliest expiry only; a Kubernetes rule derived
// late moves the shared clock, not the age window of the other rules.
func TestAgeInstantsDoNotFollowTheKubernetesDerivation(t *testing.T) {
	other := [3]string{"other.rule", "2026-09-08T12:07:56Z", "2026-12-07T12:07:56Z"}
	early, err := ClocksOf(packOf(other, [3]string{"kubernetes.served-api-removal.x", "2026-11-12T08:45:25Z", "2027-01-27T08:45:25Z"}))
	if err != nil {
		t.Fatal(err)
	}
	late, err := ClocksOf(packOf(other, [3]string{"kubernetes.served-api-removal.x", "2026-12-05T08:45:25Z", "2027-03-03T08:45:25Z"}))
	if err != nil {
		t.Fatal(err)
	}
	if early.Before != late.Before || early.Inside != late.Inside || early.After != late.After {
		t.Fatalf("age instants moved: %+v vs %+v", early, late)
	}
	for name, got := range map[string]time.Time{"before": early.Before, "inside": early.Inside, "after": early.After} {
		want := map[string]string{"before": "2026-11-06T00:00:00Z", "inside": "2026-11-20T00:00:00Z", "after": "2026-12-10T00:00:00Z"}[name]
		if got.Format(time.RFC3339) != want {
			t.Errorf("%s = %s, want %s", name, got.Format(time.RFC3339), want)
		}
	}
	if early.Clock.Equal(late.Clock) || late.Clock.Format(time.RFC3339) != "2026-12-06T00:00:00Z" {
		t.Fatalf("clocks %s %s", early.Clock, late.Clock)
	}
}
