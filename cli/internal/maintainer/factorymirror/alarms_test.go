// SPDX-License-Identifier: AGPL-3.0-only

package factorymirror

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func (e *env) repoDir(key string) string {
	return filepath.Join(e.state, filepath.FromSlash(mustRepo(e.t, key).RelPath()))
}

func (e *env) alarmKinds() []string {
	var kinds []string
	for _, a := range e.index().Alarms {
		kinds = append(kinds, a.Kind+":"+a.Tag)
	}
	return kinds
}

func TestTagDeletedThenRecreatedElsewhereRaisesAlarm(t *testing.T) {
	e := newEnv(t, k1)
	u := e.remote[k1]
	c1 := u.commit("one", map[string]string{"a.txt": "1\n"})
	u.tag("v1", false)
	e.run()
	u.deleteTag("v1")
	if res := e.run(); res.NewAlarms != 1 {
		t.Fatalf("deletion: %+v", res)
	}
	if _, err := Acknowledge(e.state, k1, "", "upstream removed a bad tag", fixedNow()); err != nil {
		t.Fatal(err)
	}
	// The tombstone survives quiet runs.
	e.run()
	e.run()
	if tomb := e.index().Repos[k1].Tombstones; tomb["v1"] != c1 {
		t.Fatalf("tombstone lost: %+v", tomb)
	}
	c2 := u.commit("two", map[string]string{"a.txt": "2\n"})
	u.tag("v1", false)
	res := e.run()
	if res.NewAlarms != 1 || res.OpenAlarms != 1 {
		t.Fatalf("recreated tag at another commit raised no alarm: %+v", res)
	}
	idx := e.index()
	var got Alarm
	for _, a := range idx.OpenAlarms() {
		got = a
	}
	if got.Kind != AlarmTagReappeared || got.Tag != "v1" || got.OldCommit != c1 || got.NewCommit != c2 {
		t.Fatalf("bad alarm: %+v", got)
	}
	if !idx.Repos[k1].Frozen || len(idx.Repos[k1].Tombstones) != 0 {
		t.Fatalf("frozen=%v tombstones=%v", idx.Repos[k1].Frozen, idx.Repos[k1].Tombstones)
	}
	// Re-running does not repeat it.
	if res := e.run(); res.NewAlarms != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestTagDeletedThenRecreatedAtSameCommitIsQuiet(t *testing.T) {
	e := newEnv(t, k1)
	u := e.remote[k1]
	u.commit("one", map[string]string{"a.txt": "1\n"})
	u.tag("v1", false)
	e.run()
	u.deleteTag("v1")
	e.run()
	if _, err := Acknowledge(e.state, k1, "", "flap", fixedNow()); err != nil {
		t.Fatal(err)
	}
	u.tag("v1", false)
	if res := e.run(); res.NewAlarms != 0 {
		t.Fatalf("same commit must not alarm: %+v", res)
	}
	if tomb := e.index().Repos[k1].Tombstones; len(tomb) != 0 {
		t.Fatalf("tombstone should be cleared: %v", tomb)
	}
}

func TestFrozenRepositoryRefusesTagResolution(t *testing.T) {
	e := newEnv(t, k1)
	u := e.remote[k1]
	c1 := u.commit("one", map[string]string{"a.txt": "1\n"})
	u.tag("v1", false)
	e.run()
	c2 := u.commit("two", map[string]string{"a.txt": "2\n"})
	u.tag("v1", false)
	e.run()

	r, err := OpenReader(e.state)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := r.ResolveTag(k1, "v1"); !errors.Is(err, ErrRepoFrozen) || got != "" {
		t.Fatalf("moved tag consumed while frozen: %q %v", got, err)
	}
	if tags, err := r.Tags(k1); !errors.Is(err, ErrRepoFrozen) || tags != nil {
		t.Fatalf("tags consumed while frozen: %v %v", tags, err)
	}
	// Pinned bytes by commit remain readable; they do not depend on tags.
	if !r.HasCommit(k1, c1) {
		t.Fatal("old commit must stay available")
	}
	if _, err := Acknowledge(e.state, k1, "", "reviewed", fixedNow()); err != nil {
		t.Fatal(err)
	}
	r, _ = OpenReader(e.state)
	if got, err := r.ResolveTag(k1, "v1"); err != nil || got != c2 {
		t.Fatalf("after acknowledgement: %q %v", got, err)
	}
	if tags, err := r.Tags(k1); err != nil || tags["v1"].Commit != c2 {
		t.Fatalf("after acknowledgement: %v %v", tags, err)
	}
}

func TestAlarmsAreAlsoWrittenToDatedFiles(t *testing.T) {
	e := newEnv(t, k1)
	u := e.remote[k1]
	c1 := u.commit("one", map[string]string{"a.txt": "1\n"})
	u.tag("v1", false)
	u.tag("v2", false)
	e.run()
	if _, err := os.Stat(filepath.Join(e.state, "alarms")); err == nil {
		t.Fatal("no alarm, no alarm file")
	}
	c2 := u.commit("two", map[string]string{"a.txt": "2\n"})
	u.tag("v1", false)
	e.run()
	path := filepath.Join(e.state, "alarms", "2030-01-02.json")
	read := func() alarmsFile {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var doc alarmsFile
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		return doc
	}
	doc := read()
	if doc.Schema != AlarmsSchema || doc.Date != "2030-01-02" || len(doc.Alarms) != 1 {
		t.Fatalf("%+v", doc)
	}
	if a := doc.Alarms[0]; a.Kind != AlarmTagMoved || a.Tag != "v1" || a.OldCommit != c1 || a.NewCommit != c2 || a.Repo != k1 {
		t.Fatalf("%+v", a)
	}
	// Quiet runs and acknowledgements do not rewrite or duplicate.
	e.run()
	if _, err := Acknowledge(e.state, k1, "", "ok", fixedNow()); err != nil {
		t.Fatal(err)
	}
	e.run()
	if doc = read(); len(doc.Alarms) != 1 || doc.Alarms[0].Acknowledged {
		t.Fatalf("%+v", doc)
	}
	// A second alarm the same day is appended.
	u.deleteTag("v2")
	e.run()
	if doc = read(); len(doc.Alarms) != 2 {
		t.Fatalf("%+v", doc)
	}
	entries, _ := os.ReadDir(filepath.Join(e.state, "alarms"))
	for _, ent := range entries {
		if strings.HasPrefix(ent.Name(), ".") {
			t.Fatalf("temporary file left behind: %s", ent.Name())
		}
	}
}

func TestTagMovePreservesTheOldCommitUnderARef(t *testing.T) {
	e := newEnv(t, k1)
	u := e.remote[k1]
	c1 := u.commit("one", map[string]string{"a.txt": "1\n"})
	u.tag("v1", false)
	u.tag("gone", false)
	e.run()
	u.commit("two", map[string]string{"a.txt": "2\n"})
	u.tag("v1", false)
	u.deleteTag("gone")
	e.run()
	refs := runGit(t, e.repoDir(k1), "for-each-ref", "--format=%(refname) %(objectname)", "refs/prufyx/preserved/")
	if !strings.Contains(refs, "refs/prufyx/preserved/"+c1+" "+c1) {
		t.Fatalf("old commit not pinned by a ref: %q", refs)
	}
	// The pin survives later fetches that prune and force-update.
	u.commit("three", map[string]string{"a.txt": "3\n"})
	e.run()
	if out := runGit(t, e.repoDir(k1), "for-each-ref", "refs/prufyx/preserved/"); !strings.Contains(out, c1) {
		t.Fatalf("pin lost after a later fetch: %q", out)
	}
}

// A fetch that fails after the alarm was recorded is retried; the retry sees
// the same difference again and must not record a second alarm.
func TestAlarmIsNotDuplicatedWhenTheFetchIsRetried(t *testing.T) {
	e := newEnv(t, k1)
	u := e.remote[k1]
	u.commit("one", map[string]string{"a.txt": "1\n"})
	u.tag("v1", false)
	e.run()
	u.commit("two", map[string]string{"a.txt": "2\n"})
	u.tag("v1", false)
	e.git.failFirst = func(args []string) bool { return args[0] == "fetch" }
	res := e.run()
	if res.Failed != 1 || res.NewAlarms != 1 {
		t.Fatalf("%+v", res)
	}
	res = e.run()
	if res.Failed != 0 || res.NewAlarms != 0 || res.OpenAlarms != 1 {
		t.Fatalf("retry duplicated the alarm: %+v", res)
	}
	if kinds := e.alarmKinds(); len(kinds) != 1 {
		t.Fatalf("%v", kinds)
	}
	raw, err := os.ReadFile(filepath.Join(e.state, "alarms", "2030-01-02.json"))
	if err != nil || strings.Count(string(raw), `"id"`) != 1 {
		t.Fatalf("dated file duplicated: %s %v", raw, err)
	}
}

func TestDetectTagChangesCases(t *testing.T) {
	old := map[string]TagInfo{"a": {Commit: "1"}, "b": {Commit: "2"}, "c": {Commit: "3"}}
	cur := map[string]TagInfo{"a": {Commit: "1", Object: "x"}, "b": {Commit: "9"}, "d": {Commit: "4"}, "e": {Commit: "6"}}
	tomb := map[string]string{"d": "4", "e": "5", "f": "7"}
	got := detectTagChanges("r", old, tomb, cur, "now")
	var kinds []string
	for _, a := range got {
		kinds = append(kinds, a.Kind+":"+a.Tag)
	}
	want := "tag_moved:b,tag_deleted:c,tag_reappeared:e"
	if strings.Join(kinds, ",") != want {
		t.Fatalf("got %v want %s", kinds, want)
	}
	next := nextTombstones(old, tomb, cur)
	if len(next) != 2 || next["c"] != "3" || next["f"] != "7" {
		t.Fatalf("%v", next)
	}
}
