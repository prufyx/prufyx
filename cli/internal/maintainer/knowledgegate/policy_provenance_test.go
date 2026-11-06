// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyCommitListBounds(t *testing.T) {
	for name, edit := range map[string]func(*CommitList){
		"ahead mismatch": func(l *CommitList) { l.AheadBy = 2 },
		"invalid sha":    func(l *CommitList) { l.Commits[0].SHA = strings.Repeat("A", 40) },
		"duplicate":      func(l *CommitList) { l.Commits = append(l.Commits, l.Commits[0]); l.AheadBy = 2; l.TotalCommits = 2 },
		"over api limit": func(l *CommitList) {
			for len(l.Commits) < 101 {
				l.Commits = append(l.Commits, l.Commits[0])
			}
			l.AheadBy = 101
			l.TotalCommits = 101
		},
	} {
		t.Run(name, func(t *testing.T) {
			l := botCommits()
			edit(l)
			o := Options{Commits: l, HeadSHA: testHeadSHA, BotLogin: DefaultBotLogin}
			if len(commitReasons(o)) == 0 {
				t.Fatal("invalid list accepted")
			}
			if len(commitListReasons(o, DefaultBotLogin, false, "owner")) == 0 {
				t.Fatal("shared owner provenance accepted invalid list")
			}
		})
	}
}

func TestBatchPolicyGuards(t *testing.T) {
	f := newBatchFixture(t, 1)
	f.signAndWrite(t, f.record(t))
	o := Options{Base: f.base, Head: f.head, Author: DefaultBotLogin}
	r := runGate(t, o)
	if !r.AutoMerge.Eligible {
		t.Fatalf("valid batch: %v", r.AutoMerge.Reasons)
	}
	zero := 0
	o = Options{Base: f.base, Head: f.head, Layout: DefaultLayout(), Author: DefaultBotLogin, Sender: DefaultBotLogin, BotLogin: DefaultBotLogin, HeadSHA: testHeadSHA, Commits: botCommits(), DailyLoosening: &zero}
	for name, change := range map[string]func(*Report, *Options){
		"missing batch": func(r *Report, _ *Options) { r.batch = nil },
		"refused batch": func(r *Report, _ *Options) { b := *r.batch; b.ok = false; r.batch = &b },
		"wrong bot":     func(_ *Report, o *Options) { o.BotLogin = "other" },
		"shadow":        func(_ *Report, o *Options) { o.Shadow = true },
		"paused":        func(_ *Report, o *Options) { o.BotSignerPaused = true },
		"kill switch":   func(r *Report, _ *Options) { r.Paused = true },
		"unknown daily": func(_ *Report, o *Options) { o.DailyLoosening = nil },
		"extra markdown": func(r *Report, _ *Options) {
			r.ChangedPaths = append(append([]string{}, r.ChangedPaths...), "other.md")
		},
	} {
		t.Run(name, func(t *testing.T) {
			report := *r
			opts := o
			change(&report, &opts)
			report.autoMerge(opts)
			if report.AutoMerge.Eligible {
				t.Fatal("invalid candidate accepted")
			}
		})
	}
}

func TestPolicyDataModes(t *testing.T) {
	root := t.TempDir()
	tr := Tree{Root: root}
	path := filepath.Join(root, "data")
	if !tr.regularDataOrAbsent("data") {
		t.Fatal("absence refused")
	}
	if err := os.WriteFile(path, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	if !tr.regularDataOrAbsent("data") {
		t.Fatal("regular data refused")
	}
	if err := os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
	if tr.regularDataOrAbsent("data") {
		t.Fatal("executable accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing", path); err != nil {
		t.Fatal(err)
	}
	if tr.regularDataOrAbsent("data") {
		t.Fatal("symlink accepted")
	}
}
