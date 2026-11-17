// SPDX-License-Identifier: AGPL-3.0-only

package changelogattest

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	ce "github.com/prufyx/prufyx/cli/internal/extract/changelogentries"
)

const component = "prometheus"

var repo = extract.RepoRef{Key: "github.com/prometheus/prometheus"}

var target = ce.Target{
	Component: component, Repo: repo, Form: ce.FormFile, Path: "CHANGELOG.md",
	HeadingPattern:   `^(?P<version>[0-9]+\.[0-9]+\.[0-9]+) / [0-9]{4}-[0-9]{2}-[0-9]{2}$`,
	BoundaryPatterns: []string{`^(main|master) / unreleased$`},
}

func commit(n int) string { return fmt.Sprintf("%039d%d", 0, n) }

// memReader serves one file per commit and path and records every read.
type memReader struct {
	mu    sync.Mutex
	files map[string]string
	reads []string
}

func (m *memReader) Read(r extract.RepoRef, c, p string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reads = append(m.reads, c+":"+p)
	b, ok := m.files[c+":"+p]
	if !ok {
		return nil, fmt.Errorf("%w: %s", extract.ErrNotFound, p)
	}
	return []byte(b), nil
}

func (m *memReader) List(extract.RepoRef, string, string) ([]extract.TreeEntry, error) {
	return nil, errors.New("no list")
}

func (m *memReader) Tags(extract.RepoRef) ([]extract.Tag, error) { return tags(), nil }

func (m *memReader) readAt(c string) bool {
	for _, r := range m.reads {
		if strings.HasPrefix(r, c+":") {
			return true
		}
	}
	return false
}

// The tags of the fixture: line 3.4 (3.4.0, 3.4.1) and line 3.5 (3.5.0, 3.5.1).
func tags() []extract.Tag {
	return []extract.Tag{
		{Name: "v3.3.0", Commit: commit(0)},
		{Name: "v3.4.0", Commit: commit(1)}, {Name: "v3.4.1", Commit: commit(2)},
		{Name: "v3.5.0", Commit: commit(3)}, {Name: "v3.5.1", Commit: commit(4)},
	}
}

// bodies are the items of each version's entry.
var bodies = map[string]string{
	"3.5.1": "* [BUGFIX] Fix a crash. #51\n",
	"3.5.0": "* [FEATURE] Add `a`. #50\n* [CHANGE] Remove flag `--b`. #52\n  continued\n",
	"3.4.1": "* [BUGFIX] Fix a leak. #41\n",
	"3.4.0": "* [FEATURE] Add `c`. #40\n",
	"3.3.0": "* [FEATURE] Add `d`. #30\n",
}

var order = []string{"3.5.1", "3.5.0", "3.4.1", "3.4.0", "3.3.0"}

// fileUpTo is the changelog as it stands at the commit of tag version v:
// every entry from v down.
func fileUpTo(v string, override map[string]string) string {
	var b strings.Builder
	b.WriteString("# Changelog\n\n## main / unreleased\n\n")
	on := false
	for _, ver := range order {
		if ver == v {
			on = true
		}
		if !on {
			continue
		}
		body := bodies[ver]
		if o, ok := override[ver]; ok {
			body = o
		}
		fmt.Fprintf(&b, "## %s / 2025-01-01\n\n%s\n", ver, body)
	}
	return b.String()
}

func newReader(override map[string]string) *memReader {
	m := &memReader{files: map[string]string{}}
	for i, v := range []string{"3.3.0", "3.4.0", "3.4.1", "3.5.0", "3.5.1"} {
		m.files[commit(i)+":CHANGELOG.md"] = fileUpTo(v, override)
	}
	return m
}

var pair = extract.VersionPair{Repo: repo, From: "3.4.0", FromTag: "v3.4.0", FromCommit: commit(1), To: "3.5.0", ToTag: "v3.5.0", ToCommit: commit(3)}

func entry(t *testing.T, r extract.PinnedReader, ver string) *ce.Entry {
	t.Helper()
	for _, tg := range tags() {
		if tg.Name == "v"+ver {
			e, err := ce.Locate(r, target, tg)
			if err != nil {
				t.Fatal(err)
			}
			return e
		}
	}
	t.Fatalf("no tag %s", ver)
	return nil
}

func neutralMark(tag string, it ce.Item) Mark {
	return Mark{ItemDigest: it.Digest, Occurrence: it.Occurrence, Tag: tag, Kind: KindNotOperatorFacing, ReasonClass: "docs",
		State: StateReviewed, ReviewedAt: "2026-11-01T00:00:00Z", ProposedBy: ProposedByPerson}
}

// marksFor marks every item of the window tags not-operator-facing, except
// the items in skip (keyed "tag#line").
func marksFor(t *testing.T, r extract.PinnedReader, skip ...string) []Mark {
	t.Helper()
	var out []Mark
	for _, ver := range []string{"3.4.1", "3.5.0", "3.5.1"} {
		e := entry(t, r, ver)
		for _, it := range e.Items {
			skipped := false
			for _, s := range skip {
				if s == fmt.Sprintf("v%s#%d", ver, it.StartLine) {
					skipped = true
				}
			}
			if !skipped {
				out = append(out, neutralMark("v"+ver, it))
			}
		}
	}
	return out
}

func dispositions(marks []Mark) *Dispositions {
	if marks == nil {
		marks = []Mark{}
	}
	return &Dispositions{Component: component, Marks: marks}
}

const horizon = `"horizon":{"lt":"3.9.0","basis":"REVIEWED_THROUGH_MINOR_LINE","sourceId":"s"}`

// ruleJSON is a release-note shaped crossing rule of the component, from
// 3.4.0 to to, changing at change, citing lines start..end of the file at
// commit c with the given digest and state.
func ruleJSON(id, to, change, state, c, digest string, start, end int) []byte {
	return []byte(fmt.Sprintf(`{"id":%q,"operator":"forbid_set_member","subject":{"component":%q,"from":"3.4.0","to":%q},"crossing":{"change":{"version":%q,"basis":"CHANGED_IN_RELEASE","sourceId":"s"},%s},"evidence":{"state":%q,"sources":[{"id":"changelog","url":%q,"revision":%q,"contentDigest":"sha256:%s","startLine":%d,"endLine":%d}]}}`,
		id, component, to, change, horizon, state, repo.BlobURL(c, "CHANGELOG.md"), c, digest, start, end))
}

func attest(t *testing.T, r extract.PinnedReader, d *Dispositions, rules [][]byte, cl Classifier) (*Result, error) {
	t.Helper()
	cfg := Config{Target: target, Dispositions: d, Classifier: cl}
	for _, x := range rules {
		cfg.PackRules = append(cfg.PackRules, x)
	}
	return Attest(r, cfg, tags(), pair)
}

func wantCode(t *testing.T, err error, want ce.Code) {
	t.Helper()
	got, ok := ce.CodeOf(err)
	if !ok || got != want {
		t.Fatalf("want %s, got %v", want, err)
	}
}
