// SPDX-License-Identifier: AGPL-3.0-only

// Package testclock derives evaluation clocks for tests from the shipped rule
// data. Tests that evaluate the real embedded rules must not pin a clock
// before the newest review of those rules: renewing rules is a data-only
// change and would otherwise make every such test report
// RULE_EVIDENCE_CLOCK_BEFORE_REVIEW. It is a test helper: no production
// package imports it, and it reads the rule files from the source tree.
package testclock

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sync"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract/supersedeids"
)

var (
	once   sync.Once
	newest time.Time
	failed error

	latestEnd time.Time
)

// Newest is one hour after the newest reviewedAt of every embedded rule (the
// CNCF and the community packs). Every lease is far longer than an hour, so
// no rule is stale at this instant.
func Newest() time.Time {
	once.Do(func() {
		_, file, _, ok := runtime.Caller(0)
		if !ok {
			failed = fmt.Errorf("testclock: source location unknown")
			return
		}
		internal := filepath.Dir(filepath.Dir(file))
		for _, pack := range []string{"cncfcheck", "projectcheck"} {
			raw, err := os.ReadFile(filepath.Join(internal, pack, "data", "rules.json"))
			if err != nil {
				failed = err
				return
			}
			var doc any
			if err := json.Unmarshal(raw, &doc); err != nil {
				failed = fmt.Errorf("testclock: %s: %w", pack, err)
				return
			}
			if err := walk(doc, &newest); err != nil {
				failed = err
				return
			}
			if err := walkEnd(doc, &latestEnd); err != nil {
				failed = err
				return
			}
		}
		if newest.IsZero() {
			failed = fmt.Errorf("testclock: the packs hold no review time")
			return
		}
		newest = newest.UTC().Add(time.Hour)
	})
	if failed != nil {
		panic(failed)
	}
	return newest
}

func walk(node any, newest *time.Time) error {
	switch v := node.(type) {
	case map[string]any:
		for key, child := range v {
			if text, ok := child.(string); ok && key == "reviewedAt" {
				at, err := time.Parse(time.RFC3339, text)
				if err != nil {
					return fmt.Errorf("testclock: reviewedAt %q: %w", text, err)
				}
				if at.After(*newest) {
					*newest = at
				}
				continue
			}
			if err := walk(child, newest); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range v {
			if err := walk(child, newest); err != nil {
				return err
			}
		}
	}
	return nil
}

// Floor returns at, or Newest when at is earlier: a clock that is never
// before the review of any shipped rule. A later at (an expiry premise) is
// returned unchanged.
func Floor(at time.Time) time.Time {
	if n := Newest(); at.Before(n) {
		return n
	}
	return at
}

// FloorText is Floor for a canonical RFC 3339 UTC text; any other text is
// returned as it is, so the command under test still judges it.
func FloorText(text string) string {
	at, err := time.Parse(time.RFC3339, text)
	if err != nil || at.UTC().Format(time.RFC3339) != text {
		// Not a canonical whole-second UTC text: kept as it is, so a test of
		// the command's own time validation still sees its input.
		return text
	}
	return Floor(at).Format(time.RFC3339)
}

func walkEnd(node any, latest *time.Time) error {
	switch v := node.(type) {
	case map[string]any:
		for key, child := range v {
			if text, ok := child.(string); ok && key == "validUntil" {
				at, err := time.Parse(time.RFC3339, text)
				if err != nil {
					return fmt.Errorf("testclock: validUntil %q: %w", text, err)
				}
				if at.After(*latest) {
					*latest = at
				}
				continue
			}
			if err := walkEnd(child, latest); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range v {
			if err := walkEnd(child, latest); err != nil {
				return err
			}
		}
	}
	return nil
}

// AfterAllExpiry is one day after the latest validUntil of any embedded rule:
// every shipped rule is expired at this instant, however the rules are renewed.
func AfterAllExpiry() time.Time {
	Newest()
	if latestEnd.IsZero() {
		panic("testclock: the packs hold no validUntil")
	}
	return latestEnd.UTC().Add(24 * time.Hour)
}

// MaskClocks replaces the shared test clock and the three knowledge-age
// instants (supersedeids.Clock, supersedeids.AgeClocks), which follow the
// shipped rules' review and end dates, with fixed placeholder instants (valid RFC 3339, so a JSON golden stays
// valid) in a golden file's text, so a golden does not move when rules are renewed. Only the
// instants' RFC 3339 text is replaced; every verdict, status and exit code
// stays in the golden. The reviewedAt, validUntil and derivedAt fields of a
// JSON report, which restate the rules' own dates, are masked the same way.
func MaskClocks(got []byte) []byte {
	before, inside, after := supersedeids.AgeClocks()
	for _, r := range []struct {
		at   time.Time
		name string
	}{
		{supersedeids.Clock(), "2001-01-01T00:00:00Z"},
		{Newest(), "2001-06-01T00:00:00Z"},
		{before, "2001-02-01T00:00:00Z"},
		{inside, "2001-03-01T00:00:00Z"},
		{after, "2001-04-01T00:00:00Z"},
	} {
		got = bytes.ReplaceAll(got, []byte(r.at.UTC().Format(time.RFC3339)), []byte(r.name))
	}
	return maskEvidenceTimes(got)
}

// evidenceTimeField is a report field that restates a rule's or line
// attestation's own review or end time (data that a renewal moves).
var evidenceTimeField = regexp.MustCompile(`"(reviewedAt|validUntil|derivedAt)":"[0-9T:.Z+-]+"`)

func maskEvidenceTimes(got []byte) []byte {
	return evidenceTimeField.ReplaceAll(got, []byte(`"$1":"2001-05-01T00:00:00Z"`))
}

var (
	projectOnce   sync.Once
	projectNewest map[string]time.Time
	projectErr    error
)

func loadProjects() {
	projectOnce.Do(func() {
		_, file, _, ok := runtime.Caller(0)
		if !ok {
			projectErr = fmt.Errorf("testclock: source location unknown")
			return
		}
		internal := filepath.Dir(filepath.Dir(file))
		projectNewest = map[string]time.Time{}
		for _, pack := range []string{"cncfcheck", "projectcheck"} {
			raw, err := os.ReadFile(filepath.Join(internal, pack, "data", "rules.json"))
			if err != nil {
				projectErr = err
				return
			}
			var doc struct {
				Entries []json.RawMessage `json:"entries"`
			}
			if err := json.Unmarshal(raw, &doc); err != nil {
				projectErr = fmt.Errorf("testclock: %s: %w", pack, err)
				return
			}
			for _, entry := range doc.Entries {
				var head struct {
					Project string `json:"project"`
				}
				var tree any
				if err := json.Unmarshal(entry, &head); err != nil || head.Project == "" {
					projectErr = fmt.Errorf("testclock: %s: entry without a project", pack)
					return
				}
				if err := json.Unmarshal(entry, &tree); err != nil {
					projectErr = err
					return
				}
				latest := projectNewest[head.Project]
				if err := walk(tree, &latest); err != nil {
					projectErr = err
					return
				}
				projectNewest[head.Project] = latest
			}
		}
	})
	if projectErr != nil {
		panic(projectErr)
	}
}

// ProjectNewest is one hour after the newest reviewedAt of the named project's
// rules (the CNCF and community packs), or the zero time when the project has
// none. It is the earliest instant at which every one of that project's rules
// is in force, so a test of one project is not tied to another project's
// renewal.
func ProjectNewest(project string) time.Time {
	loadProjects()
	latest := projectNewest[project]
	if latest.IsZero() {
		return time.Time{}
	}
	return latest.UTC().Add(time.Hour)
}

// FloorTextFor is FloorText against the named project's own newest review. An
// unknown project leaves the text as it is.
func FloorTextFor(project, text string) string {
	at, err := time.Parse(time.RFC3339, text)
	floor := ProjectNewest(project)
	if err != nil || at.UTC().Format(time.RFC3339) != text || floor.IsZero() || !at.Before(floor) {
		return text
	}
	return floor.Format(time.RFC3339)
}
