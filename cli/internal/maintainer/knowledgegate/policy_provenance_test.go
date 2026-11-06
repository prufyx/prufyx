// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func policyCommits(n int) *CommitList {
	l := botCommits()
	original := l.Commits[0]
	l.Commits = make([]CommitRecord, n)
	for i := 0; i < n-1; i++ {
		l.Commits[i] = original
		l.Commits[i].SHA = fmt.Sprintf("%040x", i+1)
	}
	l.Commits[n-1] = original
	l.AheadBy, l.TotalCommits = n, n
	return l
}

func TestPolicyCommitListBounds(t *testing.T) {
	l := policyCommits(100)
	o := Options{Commits: l, HeadSHA: testHeadSHA, BotLogin: DefaultBotLogin}
	if reasons := commitReasons(o); len(reasons) != 0 {
		t.Fatalf("100 bot commits: %v", reasons)
	}
	if reasons := commitListReasons(o, DefaultBotLogin, false, "owner"); len(reasons) != 0 {
		t.Fatalf("100 owner commits: %v", reasons)
	}
	for name, edit := range map[string]func(*CommitList){
		"ahead mismatch": func(l *CommitList) { l.AheadBy = 2 },
		"invalid sha":    func(l *CommitList) { l.Commits[0].SHA = strings.Repeat("A", 40) },
		"duplicate":      func(l *CommitList) { l.Commits = append(l.Commits, l.Commits[0]); l.AheadBy = 2; l.TotalCommits = 2 },
		"over api limit": func(l *CommitList) { *l = *policyCommits(101) },
	} {
		t.Run(name, func(t *testing.T) {
			l := botCommits()
			edit(l)
			o := Options{Commits: l, HeadSHA: testHeadSHA, BotLogin: DefaultBotLogin}
			botReasons := commitReasons(o)
			ownerReasons := commitListReasons(o, DefaultBotLogin, false, "owner")
			if len(botReasons) == 0 || len(ownerReasons) == 0 {
				t.Fatalf("invalid list accepted: bot=%v owner=%v", botReasons, ownerReasons)
			}
			if name == "over api limit" && (len(botReasons) != 1 || len(ownerReasons) != 1 || !strings.Contains(botReasons[0], "incomplete") || !strings.Contains(ownerReasons[0], "incomplete")) {
				t.Fatalf("limit masked by another failure: bot=%v owner=%v", botReasons, ownerReasons)
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
	var out bytes.Buffer
	printChecks(&out, r)
	if !strings.Contains(out.String(), "auto-merge policy candidacy: eligible") {
		t.Fatalf("eligible batch output: %s", out.String())
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
