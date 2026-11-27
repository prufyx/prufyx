// SPDX-License-Identifier: AGPL-3.0-only

package rangepropose

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A cited file that cannot be compared at its own revision sends the rule to
// review with the reason, even when the same path is readable elsewhere.
func TestAnUncomparableCitedFileNeedsReview(t *testing.T) {
	for name, tc := range map[string]struct{ content, why string }{
		"symlink":     {"->flags.go", fileNotRegular},
		"binary":      {"a\x00\n", fileBinary},
		"lfs pointer": {"version https://git-lfs.github.com/spec/v1\noid sha256:0\n", filePointer},
		"too large":   {strings.Repeat("x\n", maxFileBytes/2+1), fileTooLarge},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, with(standard(), "v1.5.0", "extra.go", tc.content))
			sources := append(f.both(), f.source("extra", "v1.5.0", "extra.go", 1, 1))
			v := wantReview(t, run(t, options(t, f.bare(), rule("flag-removed", "1.4.1", "1.5.0", sources))), ReasonUncheckedSource)
			if len(v.Listed) != 1 || v.Listed[0].CitedSourceID != "extra" || v.Listed[0].Why != tc.why || len(v.Reasons) != 1 {
				t.Fatalf("review: %s", marshal(t, v))
			}
		})
	}
}

func TestAnExecutableCitedFileIsCompared(t *testing.T) {
	script := "#!/bin/sh\necho a\n"
	f := newFixture(t, with(with(standard(), "v1.5.0", "run.sh", script), "v1.5.1", "run.sh", script))
	clone := f.bare()
	if entry := git(t, clone, "ls-tree", f.commits["v1.5.0"], "run.sh"); !strings.HasPrefix(entry, "100755 ") {
		t.Fatalf("fixture entry: %s", entry)
	}
	sources := append(f.both(), f.source("script", "v1.5.0", "run.sh", 1, 2))
	p := wantProposal(t, run(t, options(t, clone, rule("flag-removed", "1.4.1", "1.5.0", sources))))
	if len(p.Sources) != 3 || len(p.Listed) != 0 {
		t.Fatalf("evaluated: %s", marshal(t, p))
	}
}

// A revision must be a commit: git would read a tree or an annotated tag
// object as if it were one.
func TestACitedRevisionThatIsNotACommitIsRefused(t *testing.T) {
	f := newFixture(t, standard())
	clone := f.bare()
	git(t, clone, "tag", "-a", "-m", "note", "note", f.commits["v1.5.0"])
	for name, id := range map[string]string{
		"tree":       git(t, clone, "rev-parse", f.commits["v1.5.0"]+"^{tree}"),
		"tag object": git(t, clone, "rev-parse", "refs/tags/note"),
		"missing":    strings.Repeat("b", 40),
	} {
		t.Run(name, func(t *testing.T) {
			sources := f.both()
			sources[1] = sourceAt("new-flags", "acme/demo", id, "flags.go", newCode, 3, 5)
			no := wantRefused(t, run(t, options(t, clone, rule("flag-removed", "1.4.1", "1.5.0", sources))), CodeObjectMissing)
			if no.Detail != "commit "+id+" is not in the clone" {
				t.Fatalf("detail: %s", no.Detail)
			}
		})
	}
}

func TestTheRulesCommitMustBeACommit(t *testing.T) {
	f := newFixture(t, standard())
	clone := f.bare()
	repo, commit := rulesRepo(t, packJSON(t, standardRule(f)))
	git(t, repo, "tag", "-a", "-m", "note", "note", commit)
	for name, id := range map[string]string{
		"tree":       git(t, repo, "rev-parse", commit+"^{tree}"),
		"tag object": git(t, repo, "rev-parse", "refs/tags/note"),
		"missing":    strings.Repeat("b", 40),
	} {
		_, err := Run(context.Background(), Options{RulesRepo: repo, RulesCommit: id, Config: config(clone)})
		if err == nil || err.Error() != "the rules commit is not in the rules repository" {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A path that makes the tree listing answer for other entries is not read.
func TestATreeAnswerForAnotherPathIsRefused(t *testing.T) {
	f := newFixture(t, []release{{"v1.4.0", files{"dir/a.go": "a\n"}}, {"v1.4.1", files{"dir/a.go": "a\n", "dir/b.go": "b\n"}}})
	clone := f.bare()
	for _, tag := range []string{"v1.4.0", "v1.4.1"} {
		file, err := readTreeFile(context.Background(), clone, f.commits[tag], "dir/")
		want := CodeGit + ": unexpected tree answer at commit " + f.commits[tag]
		if file != nil || err == nil || err.Error() != want {
			t.Errorf("%s: %+v %v", tag, file, err)
		}
	}
}

func TestStrictDecodingNamesItsRefusal(t *testing.T) {
	nested := func(n int) string {
		return `{"deep":` + strings.Repeat("[", n) + strings.Repeat("]", n) + `}`
	}
	var v map[string]any
	if err := strictUnmarshal([]byte(nested(128)), &v, false); err != nil {
		t.Fatalf("at the depth limit: %v", err)
	}
	for name, tc := range map[string]struct{ raw, want string }{
		"too deep":         {nested(129), "nesting too deep"},
		"invalid UTF-8":    {"{\"a\":\"\xff\"}", "invalid UTF-8"},
		"duplicate key":    {`{"a":1,"a":2}`, `duplicate key "a"`},
		"nested duplicate": {`{"x":[{"a":1,"a":2}]}`, `duplicate key "a"`},
		"case variant":     {`{"x":{"a":1,"A":2}}`, `duplicate key "A"`},
		"trailing data":    {`{}{}`, "trailing data"},
	} {
		if err := strictUnmarshal([]byte(tc.raw), &v, false); err == nil || err.Error() != tc.want {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestInputRefusalsNameTheirCause(t *testing.T) {
	f := newFixture(t, standard())
	clone := f.bare()
	good := packJSON(t, rule("a", "1.4.1", "1.5.0", f.both()))
	extra := func(member string) string { return "{" + member + "," + strings.TrimPrefix(good, "{") }
	for name, tc := range map[string]struct{ pack, want string }{
		"duplicate key":    {strings.Replace(good, `"id":"a"`, `"id":"a","id":"a"`, 1), `duplicate key "id"`},
		"case variant key": {strings.Replace(good, `"id":"a"`, `"ID":"z","id":"a"`, 1), `duplicate key "id"`},
		"trailing data":    {good + "{}", "trailing data"},
		"invalid UTF-8":    {extra("\"x\":\"\xff\""), "invalid UTF-8"},
		"too deep":         {extra(`"x":` + strings.Repeat("[", 129) + strings.Repeat("]", 129)), "nesting too deep"},
	} {
		repo, commit := rulesRepo(t, tc.pack)
		_, err := Run(context.Background(), Options{RulesRepo: repo, RulesCommit: commit, Config: config(clone)})
		if err == nil || err.Error() != "the rule pack is not strict JSON: "+tc.want {
			t.Errorf("pack %s: %v", name, err)
		}
	}
	for name, tc := range map[string]struct{ raw, want string }{
		"invalid UTF-8": {"{\"projects\":{\"demo\":{\"repo\":\"a/b\",\"path\":\"/x\xff\"}}}", "invalid UTF-8"},
		"duplicate":     {`{"projects":{"demo":{"repo":"a/b","path":"/x","path":"/y"}}}`, `duplicate key "path"`},
		"trailing":      {`{"projects":{"demo":{"repo":"a/b","path":"/x"}}}[]`, "trailing data"},
	} {
		if _, err := DecodeConfig([]byte(tc.raw)); err == nil || err.Error() != "projects file: "+tc.want {
			t.Errorf("config %s: %v", name, err)
		}
	}
}

// refusedCodes maps each refused rule to its code.
func refusedCodes(r Report) map[string]Refused {
	out := map[string]Refused{}
	for _, v := range r.Refused {
		out[v.RuleID] = v
	}
	return out
}

func TestOverlapIsScopedToTheSubjectComponent(t *testing.T) {
	f := newFixture(t, standard())
	b := rule("b", "1.4.1", "1.5.0", f.both())
	b["subject"].(map[string]any)["component"] = "pkg:github/acme/other"
	r := run(t, options(t, f.bare(), rule("a", "1.4.1", "1.5.0", f.both()), b))
	if len(r.Proposals) != 2 || len(r.Refused) != 0 {
		t.Fatalf("another subject component: %s", marshal(t, r))
	}
}

// A same-key rule whose region the tool cannot compare counts as overlapping,
// although its anchors alone are apart from the candidate or unreadable.
func TestARuleTheToolCannotCompareOverlaps(t *testing.T) {
	f := newFixture(t, standard())
	clone := f.bare()
	a := rule("a", "1.4.1", "1.5.0", f.both())
	crossing := rule("b", "2.0.0", "3.0.0", f.both())
	// Control: without the crossing the two regions are apart.
	if r := run(t, options(t, clone, a, crossing)); len(r.Proposals) != 1 || r.Proposals[0].RuleID != "a" {
		t.Fatalf("control: %s", marshal(t, r))
	}
	crossing["crossing"] = map[string]any{"at": "3.0.0"}
	for name, other := range map[string]map[string]any{
		"crossing":        crossing,
		"unparsed from":   rule("b", "latest", "1.5.1", f.both()),
		"unparsed to":     rule("b", "1.4.2", "latest", f.both()),
		"two part anchor": rule("b", "1.4", "1.5.1", f.both()),
	} {
		t.Run(name, func(t *testing.T) {
			r := run(t, options(t, clone, a, other))
			no := refusedCodes(r)["a"]
			if len(r.Proposals) != 0 || len(r.Refused) != 2 || no.Code != CodeOverlap ||
				no.Detail != "the candidate range overlaps, on the same constraint key, with b" {
				t.Fatalf("report: %s", marshal(t, r))
			}
		})
	}
}

// The output directory is checked once and written later. A link planted in
// between is neither followed nor overwritten.
func TestAFilePlantedAfterTheDirectoryCheckIsNotFollowed(t *testing.T) {
	// Large documents keep the writer busy while the link is planted.
	big := Report{Refused: []Refused{{Detail: strings.Repeat("x", 16<<20)}}}
	for attempt := 0; attempt < 50; attempt++ {
		root := t.TempDir()
		victim := filepath.Join(root, "victim")
		write(t, victim, "keep")
		out := filepath.Join(root, "out")
		done, planted := make(chan struct{}), make(chan bool, 1)
		go func() {
			for {
				if _, err := os.Lstat(filepath.Join(out, ProposalsFile)); err == nil {
					planted <- os.Symlink(victim, filepath.Join(out, SummaryFile)) == nil
					return
				}
				select {
				case <-done:
					planted <- false
					return
				default:
				}
			}
		}()
		err := Write(out, big)
		close(done)
		// A link that could be created existed before the summary was opened.
		if !<-planted {
			continue
		}
		got, readErr := os.ReadFile(victim)
		if err == nil || err.Error() != SummaryFile+" cannot be created" {
			t.Fatalf("write over a planted link: %v", err)
		}
		if readErr != nil || string(got) != "keep" {
			t.Fatalf("the link target changed: %d bytes, %v", len(got), readErr)
		}
		return
	}
	t.Fatal("the link was never planted before the summary was written")
}
