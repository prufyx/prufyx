// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// memStore serves synthetic git objects built from in-memory trees, so the
// bundle tests need no git checkout.
type memStore struct{ objs map[string]rawObj }

func (m memStore) Raw(kind, id string) ([]byte, error) {
	o, ok := m.objs[id]
	if !ok || o.kind != kind {
		return nil, fmt.Errorf("no %s %s", kind, id)
	}
	return o.body, nil
}

func hexToRaw(id string) []byte {
	b := make([]byte, 20)
	for i := range b {
		fmt.Sscanf(id[2*i:2*i+2], "%02x", &b[i])
	}
	return b
}

type synthEnt struct{ mode, id string }

func (m memStore) put(kind string, body []byte) string {
	id := objectID(kind, body)
	m.objs[id] = rawObj{kind: kind, body: body}
	return id
}

func (m memStore) tree(files map[string]synthEnt) string {
	groups := map[string]map[string]synthEnt{}
	var ents []treeEnt
	for p, e := range files {
		head, rest, nested := strings.Cut(p, "/")
		if !nested {
			ents = append(ents, treeEnt{mode: e.mode, name: head, id: e.id})
			continue
		}
		if groups[head] == nil {
			groups[head] = map[string]synthEnt{}
		}
		groups[head][rest] = e
	}
	for name, g := range groups {
		ents = append(ents, treeEnt{mode: "40000", name: name, id: m.tree(g)})
	}
	sort.Slice(ents, func(i, j int) bool { return entryKey(ents[i]) < entryKey(ents[j]) })
	var body []byte
	for _, e := range ents {
		body = append(body, []byte(e.mode+" "+e.name)...)
		body = append(body, 0)
		body = append(body, hexToRaw(e.id)...)
	}
	return m.put("tree", body)
}

// synthRepo builds objects and commit ids for every tag.
func synthRepo(trees map[string]*memTree) (memStore, map[string]string) {
	st := memStore{objs: map[string]rawObj{}}
	commits := map[string]string{}
	for tag, mt := range trees {
		files := map[string]synthEnt{}
		for p, b := range mt.files {
			files[p] = synthEnt{"100644", st.put("blob", b)}
		}
		for p, l := range mt.links {
			files[p] = synthEnt{"120000", st.put("blob", []byte(l))}
		}
		root := st.tree(files)
		commits[tag] = st.put("commit", []byte("tree "+root+"\nauthor t <t@example.invalid> 0 +0000\ncommitter t <t@example.invalid> 0 +0000\n\n"+tag+"\n"))
	}
	return st, commits
}

// commitSource serves the memTrees under the synthetic commit ids.
type commitSource struct {
	memSource
	commits map[string]string
}

func (c commitSource) Open(tag string) (Tree, string, error) {
	t, _, err := c.memSource.Open(tag)
	return t, c.commits[tag], err
}

// recordBundle runs the generator over the trees through a recording source
// and returns the minimal bundle plus the direct (unrecorded) result.
func recordBundle(t *testing.T, src memSource, mk func(Source) Input) ([]byte, *Result) {
	t.Helper()
	store, commits := synthRepo(src.trees)
	cs := commitSource{src, commits}
	direct := mustGenerate(t, mk(cs))
	rec := &RecordingSource{Inner: cs}
	mustGenerate(t, mk(rec))
	raw, err := rec.buildBundle(store)
	if err != nil {
		t.Fatal(err)
	}
	return raw, direct
}

func sameResult(t *testing.T, a, b *Result) {
	t.Helper()
	ra, _ := marshal(a.Report)
	rb, _ := marshal(b.Report)
	if !bytes.Equal(a.A, b.A) || !bytes.Equal(a.B, b.B) || !bytes.Equal(a.TableRow, b.TableRow) || !bytes.Equal(a.Changelog, b.Changelog) || !bytes.Equal(ra, rb) {
		t.Fatal("results differ byte for byte")
	}
}

func TestRecordThenReplayEqualsDirectRun(t *testing.T) {
	src := collapseSource(nil)
	mk := func(s Source) Input { return collapseInputFor(s, true) }
	raw, direct := recordBundle(t, src, mk)
	b, err := ParseBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	sameResult(t, direct, mustGenerate(t, mk(FactSource{B: b})))
	// Deterministic bundle: the same recording gives the same bytes.
	raw2, _ := recordBundle(t, src, mk)
	if !bytes.Equal(raw, raw2) {
		t.Fatal("bundle bytes are not deterministic")
	}
	// The bundle carries only what was read: README.md is never read.
	tr, _, err := FactSource{B: b}.Open(collapseTags[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Read("README.md"); err == nil || !strings.Contains(err.Error(), "outside the fact bundle") {
		t.Fatalf("read of an uncarried file must be a hard error, got %v", err)
	}
	if _, err := tr.Read("config/crd/a.yaml"); err != nil {
		t.Fatal(err)
	}
	ents, _ := tr.Entries()
	if len(ents) != 3 {
		t.Fatalf("entries come from the trees, got %d", len(ents))
	}
}

func TestFactSourceErrors(t *testing.T) {
	raw, _ := recordBundle(t, collapseSource(nil), func(s Source) Input { return collapseInputFor(s, true) })
	b, _ := ParseBundle(raw)
	if _, _, err := (FactSource{B: b}).Open("v9.9.9"); err == nil {
		t.Fatal("unknown tag must be an error")
	}
	if _, _, err := (FactSource{}).Open("v1.0.0"); err == nil {
		t.Fatal("no bundle must be an error")
	}
	tr, _, _ := FactSource{B: b}.Open("v1.0.0")
	if _, err := tr.Read("config/crd/missing.yaml"); err == nil {
		t.Fatal("missing path must be an error, not empty")
	}
	if _, err := tr.Link("config/crd/a.yaml"); err == nil {
		t.Fatal("a file is not a link")
	}
}

func rebundle(t *testing.T, raw []byte, mut func(d *bundleDoc)) []byte {
	t.Helper()
	var d bundleDoc
	if err := strictDecode(raw, &d); err != nil {
		t.Fatal(err)
	}
	mut(&d)
	out, err := marshalBundle(d)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func objIndex(d *bundleDoc, kind string) int {
	for i, o := range d.Objects {
		if o.Kind == kind {
			return i
		}
	}
	return -1
}

func TestParseBundleNegatives(t *testing.T) {
	raw, _ := recordBundle(t, collapseSource(nil), func(s Source) Input { return collapseInputFor(s, true) })
	if _, err := ParseBundle(raw); err != nil {
		t.Fatal(err)
	}
	flip := func(kind string) func(d *bundleDoc) {
		return func(d *bundleDoc) {
			i := objIndex(d, kind)
			body, _ := base64.StdEncoding.DecodeString(d.Objects[i].Data)
			body[len(body)-1] ^= 1
			d.Objects[i].Data = base64.StdEncoding.EncodeToString(body)
		}
	}
	cases := map[string]func(d *bundleDoc){
		"tampered blob":   flip("blob"),
		"tampered tree":   flip("tree"),
		"tampered commit": flip("commit"),
		"extra object": func(d *bundleDoc) {
			body := []byte("extra\n")
			d.Objects = append(d.Objects, bundleObj{ID: objectID("blob", body), Kind: "blob", Data: base64.StdEncoding.EncodeToString(body)})
			sort.Slice(d.Objects, func(i, j int) bool { return d.Objects[i].ID < d.Objects[j].ID })
		},
		"missing tree": func(d *bundleDoc) {
			i := objIndex(d, "tree")
			d.Objects = append(d.Objects[:i], d.Objects[i+1:]...)
		},
		"missing commit": func(d *bundleDoc) {
			i := objIndex(d, "commit")
			d.Objects = append(d.Objects[:i], d.Objects[i+1:]...)
		},
		"unsorted objects": func(d *bundleDoc) { d.Objects[0], d.Objects[1] = d.Objects[1], d.Objects[0] },
		"duplicate object": func(d *bundleDoc) {
			d.Objects = append(d.Objects, d.Objects[0])
			d.Objects[0], d.Objects[1] = d.Objects[1], d.Objects[0]
		},
		"unsorted tags": func(d *bundleDoc) { d.Tags[0], d.Tags[1] = d.Tags[1], d.Tags[0] },
		"bad schema":    func(d *bundleDoc) { d.Schema = "x" },
		"too many tags": func(d *bundleDoc) {
			for i := 0; i < MaxBundleTags; i++ {
				d.Tags = append(d.Tags, bundleTag{Tag: fmt.Sprintf("w%02d", i), Commit: d.Tags[0].Commit})
			}
		},
		"bad kind":          func(d *bundleDoc) { d.Objects[0].Kind = "tag" },
		"bad base64":        func(d *bundleDoc) { d.Objects[0].Data = "!!" },
		"bad tag name":      func(d *bundleDoc) { d.Tags[0].Tag = "../x" },
		"commit id not hex": func(d *bundleDoc) { d.Tags[0].Commit = strings.ToUpper(d.Tags[0].Commit) },
	}
	for name, mut := range cases {
		if _, err := ParseBundle(rebundle(t, raw, mut)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, bad := range map[string][]byte{
		"not canonical": bytes.ReplaceAll(raw, []byte("\n "), []byte("\n   ")),
		"trailing data": append(append([]byte(nil), raw...), []byte("{}")...),
		"unknown field": bytes.Replace(raw, []byte(`"schema"`), []byte(`"extra": 1, "schema"`), 1),
		"oversize":      bytes.Repeat([]byte(" "), MaxBundleBytes+1),
		"empty":         nil,
	} {
		if _, err := ParseBundle(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseTreeObjectNegatives(t *testing.T) {
	id := strings.Repeat("ab", 20)
	ent := func(mode, name string) []byte {
		return append(append([]byte(mode+" "+name), 0), hexToRaw(id)...)
	}
	join := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	if _, err := parseTreeObject(join(ent("100644", "a"), ent("100644", "b"))); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{
		"duplicate": join(ent("100644", "a"), ent("100644", "a")),
		"unsorted":  join(ent("100644", "b"), ent("100644", "a")),
		"dot-dot":   ent("100644", ".."),
		"dot-git":   ent("100644", ".GIT"),
		"slash":     ent("100644", "a/b"),
		"bad mode":  ent("100664", "a"),
		"truncated": ent("100644", "a")[:10],
		"no space":  []byte("100644"),
	} {
		if _, err := parseTreeObject(body); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A real git checkout: record through GitSource, build the bundle with git,
// replay it and get the same bytes.
func TestBundleFromGitReplaysGitSource(t *testing.T) {
	dir := t.TempDir()
	env := append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid")
	git := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	git("init", "-q")
	for _, tag := range collapseTags {
		for p, b := range collapseBase().files {
			full := filepath.Join(dir, filepath.FromSlash(p))
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, append(b, []byte("# "+tag+"\n")...), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		git("add", "-A")
		git("commit", "-q", "-m", tag)
		git("tag", tag)
	}
	g := GitSource{Dir: dir}
	rec := &RecordingSource{Inner: g}
	direct := mustGenerate(t, collapseInputFor(rec, true))
	raw, err := rec.BundleFromGit(g)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	sameResult(t, direct, mustGenerate(t, collapseInputFor(FactSource{B: b}, true)))
	if _, err := (&RecordingSource{Inner: g}).BundleFromGit(g); err == nil {
		t.Fatal("an empty recording must not produce a bundle")
	}
}

// A doubling DAG: every tree names the next one twice. It verifies (every
// object is distinct and small) but expands to 2^64 paths; the replay must
// refuse it, not walk it.
func TestFactSourceRefusesDoublingTreeDAG(t *testing.T) {
	st := memStore{objs: map[string]rawObj{}}
	entry := func(name, id string) []byte {
		return append(append([]byte("40000 "+name), 0), hexToRaw(id)...)
	}
	leaf := st.put("tree", nil)
	cur := leaf
	for i := 0; i < 64; i++ {
		body := append(entry("a", cur), entry("b", cur)...)
		cur = st.put("tree", body)
	}
	commit := st.put("commit", []byte("tree "+cur+"\n\nx\n"))
	var d bundleDoc
	d.Schema = BundleSchema
	d.Tags = []bundleTag{{Tag: "v1.0.0", Commit: commit}}
	for id, o := range st.objs {
		d.Objects = append(d.Objects, bundleObj{ID: id, Kind: o.kind, Data: base64.StdEncoding.EncodeToString(o.body)})
	}
	sort.Slice(d.Objects, func(i, j int) bool { return d.Objects[i].ID < d.Objects[j].ID })
	raw, err := marshalBundle(d)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseBundle(raw)
	if err != nil {
		t.Fatalf("the bundle itself is small and consistent: %v", err)
	}
	if _, _, err := (FactSource{B: b}).Open("v1.0.0"); err == nil || !strings.Contains(err.Error(), "entry budget") {
		t.Fatalf("want an entry-budget refusal, got %v", err)
	}
}

// doublingStore builds a store whose trees name the next one twice, with
// entry names of nameLen bytes. The objects stay small and distinct.
func doublingStore(nameLen, depth int) (memStore, string) {
	st := memStore{objs: map[string]rawObj{}}
	entry := func(name, id string) []byte {
		return append(append([]byte("40000 "+name), 0), hexToRaw(id)...)
	}
	a, b := strings.Repeat("a", nameLen), strings.Repeat("b", nameLen)
	cur := st.put("tree", nil)
	for i := 0; i < depth; i++ {
		cur = st.put("tree", append(entry(a, cur), entry(b, cur)...))
	}
	return st, st.put("commit", []byte("tree "+cur+"\n\nx\n"))
}

func bundleOfStore(t *testing.T, st memStore, commit string) *Bundle {
	var d bundleDoc
	d.Schema = BundleSchema
	d.Tags = []bundleTag{{Tag: "v1.0.0", Commit: commit}}
	for id, o := range st.objs {
		d.Objects = append(d.Objects, bundleObj{ID: id, Kind: o.kind, Data: base64.StdEncoding.EncodeToString(o.body)})
	}
	sort.Slice(d.Objects, func(i, j int) bool { return d.Objects[i].ID < d.Objects[j].ID })
	raw, err := marshalBundle(d)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseBundle(raw)
	if err != nil {
		t.Fatalf("the bundle itself is small and consistent: %v", err)
	}
	return b
}

// Long names make a small entry count cost gigabytes of path strings; the
// path-byte budget refuses that before the entry budget would.
func TestFactSourceRefusesLongNameDoublingDAGByPathBytes(t *testing.T) {
	st, commit := doublingStore(60, 64)
	b := bundleOfStore(t, st, commit)
	_, _, err := (FactSource{B: b}).Open("v1.0.0")
	if err == nil || !strings.Contains(err.Error(), "bundle-path-budget") {
		t.Fatalf("want a path-byte refusal, got %v", err)
	}
	// Short names trip the entry budget instead, with its own message.
	st, commit = doublingStore(1, 64)
	b = bundleOfStore(t, st, commit)
	if _, _, err := (FactSource{B: b}).Open("v1.0.0"); err == nil || !strings.Contains(err.Error(), "entry budget") {
		t.Fatalf("want an entry-budget refusal, got %v", err)
	}
}

func TestExpandBudgetSpendsEntriesAndPathBytes(t *testing.T) {
	ents := []treeEnt{{name: "abcd"}, {name: "ef"}}
	b := expandBudget{entries: 2, pathBytes: 4 + 2 + 2*3}
	if err := b.spend("xyz", ents); err != nil || b.entries != 0 || b.pathBytes != 0 {
		t.Fatalf("exact fit must pass: %v %+v", err, b)
	}
	b = expandBudget{entries: 2, pathBytes: 4 + 2 + 2*3 - 1}
	if err := b.spend("xyz", ents); err == nil || !strings.Contains(err.Error(), "bundle-path-budget") {
		t.Fatalf("one byte over: %v", err)
	}
	b = expandBudget{entries: 1, pathBytes: 1 << 20}
	if err := b.spend("", ents); err == nil || !strings.Contains(err.Error(), "entry budget") {
		t.Fatalf("one entry over: %v", err)
	}
}

// The bundle builder applies the same two budgets.
func TestBuildBundleRefusesDoublingTreesByEntriesAndPathBytes(t *testing.T) {
	for name, tc := range map[string]struct {
		nameLen int
		want    string
	}{"path bytes": {60, "bundle-path-budget"}, "entries": {1, "entry budget"}} {
		t.Run(name, func(t *testing.T) {
			st, commit := doublingStore(tc.nameLen, 64)
			r := &RecordingSource{commits: map[string]string{"v1.0.0": commit}, reads: map[string]map[string]bool{"v1.0.0": {}}}
			if _, err := r.buildBundle(st); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
}
