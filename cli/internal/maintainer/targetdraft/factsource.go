// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // git object ids are sha1; the bundle verifies exactly those ids
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Fact bundle: the self-verifying replay input of the regenerate check. It
// carries, per tag, the commit object, every tree object reachable from it
// and the raw blobs of exactly the files the generator read. Every object is
// checked against its git object id; the commit names the root tree and every
// tree names its children, so a verified bundle is internally consistent.
// Internal consistency is NOT authenticity: nothing here binds a (repo, tag)
// to the real upstream commit. That binding is a separate, later step.
const (
	BundleSchema = "prufyx.io/target-facts/v1"
	// MaxBundleBytes bounds the bundle file; MaxBundleTags bounds the tags.
	MaxBundleBytes = 8 << 20
	MaxBundleTags  = 12
	// maxBundleEntries bounds the tree entries over all trees of a bundle.
	maxBundleEntries = 400000
	maxTreeDepth     = 64
	maxPathBytes     = 4096
)

var (
	sha1HexRE   = regexp.MustCompile(`^[0-9a-f]{40}$`)
	sha256HexRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type bundleTag struct {
	Tag    string `json:"tag"`
	Commit string `json:"commit"`
}

type bundleObj struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	Data string `json:"data"` // standard base64 of the raw object body
}

type bundleDoc struct {
	Schema  string      `json:"schema"`
	Tags    []bundleTag `json:"tags"`
	Objects []bundleObj `json:"objects"`
}

type rawObj struct {
	kind string
	body []byte
}

// Bundle is a parsed and fully verified fact bundle.
type Bundle struct {
	tags map[string]string
	objs map[string]rawObj
}

// Tags returns the tag names of the bundle, sorted.
func (b *Bundle) Tags() []string {
	out := make([]string, 0, len(b.tags))
	for t := range b.tags {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Commit returns the commit id the bundle holds for a tag.
func (b *Bundle) Commit(tag string) (string, bool) {
	c, ok := b.tags[tag]
	return c, ok
}

func objectID(kind string, body []byte) string {
	h := sha1.New() //nolint:gosec // see import
	fmt.Fprintf(h, "%s %d", kind, len(body))
	h.Write([]byte{0})
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

func marshalBundle(d bundleDoc) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	if err := enc.Encode(d); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type treeEnt struct {
	mode string
	name string
	id   string
}

func (e treeEnt) isDir() bool { return e.mode == "40000" }

func validEntryName(n string) bool {
	if n == "" || n == "." || n == ".." || strings.ContainsAny(n, "/\x00\\") || strings.EqualFold(n, ".git") {
		return false
	}
	return true
}

func entryKey(e treeEnt) string {
	if e.isDir() {
		return e.name + "/"
	}
	return e.name
}

// parseTreeObject decodes a raw git tree body. Entries must be in git order,
// unique, with plain names and a known mode.
func parseTreeObject(body []byte) ([]treeEnt, error) {
	var out []treeEnt
	rest := body
	for len(rest) > 0 {
		sp := bytes.IndexByte(rest, ' ')
		if sp <= 0 {
			return nil, errors.New("malformed tree entry")
		}
		mode := string(rest[:sp])
		rest = rest[sp+1:]
		nul := bytes.IndexByte(rest, 0)
		if nul < 0 || len(rest) < nul+1+20 {
			return nil, errors.New("malformed tree entry")
		}
		e := treeEnt{mode: mode, name: string(rest[:nul]), id: hex.EncodeToString(rest[nul+1 : nul+21])}
		rest = rest[nul+21:]
		switch mode {
		case "40000", "100644", "100755", "120000", "160000":
		default:
			return nil, fmt.Errorf("tree entry mode %q is not accepted", mode)
		}
		if !validEntryName(e.name) {
			return nil, fmt.Errorf("tree entry name %q is not accepted", e.name)
		}
		if n := len(out); n > 0 && entryKey(out[n-1]) >= entryKey(e) {
			return nil, errors.New("tree entries are not in strictly increasing git order")
		}
		out = append(out, e)
	}
	return out, nil
}

func commitTreeID(body []byte) (string, error) {
	line, _, ok := bytes.Cut(body, []byte("\n"))
	if !ok || !bytes.HasPrefix(line, []byte("tree ")) {
		return "", errors.New("commit object does not start with a tree line")
	}
	id := string(line[5:])
	if !sha1HexRE.MatchString(id) {
		return "", errors.New("commit object names a malformed tree id")
	}
	return id, nil
}

// ParseBundle reads a bundle strictly and verifies every object, the commit
// and tree chains and the absence of unreferenced objects. Any problem is an
// error; there is no partial result.
func ParseBundle(raw []byte) (*Bundle, error) {
	if len(raw) > MaxBundleBytes {
		return nil, fmt.Errorf("bundle is over %d bytes", MaxBundleBytes)
	}
	var d bundleDoc
	if err := strictDecode(raw, &d); err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	canon, err := marshalBundle(d)
	if err != nil || !bytes.Equal(canon, raw) {
		return nil, errors.New("bundle: not in canonical form")
	}
	if d.Schema != BundleSchema {
		return nil, fmt.Errorf("bundle: schema %q is not %s", d.Schema, BundleSchema)
	}
	if len(d.Tags) == 0 || len(d.Tags) > MaxBundleTags {
		return nil, fmt.Errorf("bundle: needs 1..%d tags", MaxBundleTags)
	}
	b := &Bundle{tags: map[string]string{}, objs: map[string]rawObj{}}
	for i, t := range d.Tags {
		if !tagNameRE.MatchString(t.Tag) || !sha1HexRE.MatchString(t.Commit) {
			return nil, fmt.Errorf("bundle: tag %q or its commit id is malformed", t.Tag)
		}
		if i > 0 && d.Tags[i-1].Tag >= t.Tag {
			return nil, errors.New("bundle: tags are not sorted and unique")
		}
		b.tags[t.Tag] = t.Commit
	}
	for i, o := range d.Objects {
		if !sha1HexRE.MatchString(o.ID) {
			return nil, fmt.Errorf("bundle: object id %q is malformed", o.ID)
		}
		if i > 0 && d.Objects[i-1].ID >= o.ID {
			return nil, errors.New("bundle: objects are not sorted and unique")
		}
		switch o.Kind {
		case "commit", "tree", "blob":
		default:
			return nil, fmt.Errorf("bundle: object %s has kind %q", o.ID, o.Kind)
		}
		body, err := base64.StdEncoding.Strict().DecodeString(o.Data)
		if err != nil {
			return nil, fmt.Errorf("bundle: object %s: %w", o.ID, err)
		}
		if len(body) > MaxFileBytes {
			return nil, fmt.Errorf("bundle: object %s is over %d bytes", o.ID, MaxFileBytes)
		}
		if objectID(o.Kind, body) != o.ID {
			return nil, fmt.Errorf("bundle: object %s does not match its hash", o.ID)
		}
		b.objs[o.ID] = rawObj{kind: o.Kind, body: body}
	}
	if err := b.verifyChains(); err != nil {
		return nil, err
	}
	return b, nil
}

// verifyChains walks every tag from its commit through all trees, checks the
// kinds, and refuses any object nothing references.
func (b *Bundle) verifyChains() error {
	used := map[string]bool{}
	entries := 0
	visited := map[string]bool{}
	var walk func(id string, depth int) error
	walk = func(id string, depth int) error {
		if depth > maxTreeDepth {
			return errors.New("bundle: tree nesting too deep")
		}
		o, ok := b.objs[id]
		if !ok || o.kind != "tree" {
			return fmt.Errorf("bundle: tree %s is missing", id)
		}
		used[id] = true
		if visited[id] {
			return nil
		}
		visited[id] = true
		ents, err := parseTreeObject(o.body)
		if err != nil {
			return fmt.Errorf("bundle: tree %s: %w", id, err)
		}
		entries += len(ents)
		if entries > maxBundleEntries {
			return errors.New("bundle: too many tree entries")
		}
		for _, e := range ents {
			switch {
			case e.isDir():
				if err := walk(e.id, depth+1); err != nil {
					return err
				}
			case e.mode == "160000":
			default:
				if c, ok := b.objs[e.id]; ok {
					if c.kind != "blob" {
						return fmt.Errorf("bundle: entry %q names a %s, not a blob", e.name, c.kind)
					}
					used[e.id] = true
				}
			}
		}
		return nil
	}
	for tag, commit := range b.tags {
		c, ok := b.objs[commit]
		if !ok || c.kind != "commit" {
			return fmt.Errorf("bundle: commit %s of tag %s is missing", commit, tag)
		}
		used[commit] = true
		tree, err := commitTreeID(c.body)
		if err != nil {
			return fmt.Errorf("bundle: commit %s: %w", commit, err)
		}
		if err := walk(tree, 0); err != nil {
			return err
		}
	}
	for id := range b.objs {
		if !used[id] {
			return fmt.Errorf("bundle: object %s is not referenced by any tag", id)
		}
	}
	return nil
}

type factFile struct {
	id   string
	link bool
}

// FactSource replays a verified bundle as a Source. It never reads anything
// outside the bundle: a read of a file whose blob is not carried is an error,
// never an empty result.
type FactSource struct {
	B *Bundle
}

// Open implements Source.
func (s FactSource) Open(tag string) (Tree, string, error) {
	if s.B == nil {
		return nil, "", errors.New("no fact bundle")
	}
	commit, ok := s.B.tags[tag]
	if !ok {
		return nil, "", fmt.Errorf("tag %s is not in the fact bundle", tag)
	}
	root, err := commitTreeID(s.B.objs[commit].body)
	if err != nil {
		return nil, "", err
	}
	t := &factTree{b: s.B, files: map[string]factFile{}}
	if err := t.collect(root, "", 0); err != nil {
		return nil, "", err
	}
	return t, commit, nil
}

type factTree struct {
	b     *Bundle
	files map[string]factFile
}

func (t *factTree) collect(id, prefix string, depth int) error {
	if depth > maxTreeDepth {
		return errors.New("tree nesting too deep")
	}
	o, ok := t.b.objs[id]
	if !ok || o.kind != "tree" {
		return fmt.Errorf("tree %s is not in the fact bundle", id)
	}
	ents, err := parseTreeObject(o.body)
	if err != nil {
		return err
	}
	for _, e := range ents {
		p := prefix + e.name
		if len(p) > maxPathBytes {
			return errors.New("path too long")
		}
		switch e.mode {
		case "40000":
			if err := t.collect(e.id, p+"/", depth+1); err != nil {
				return err
			}
		case "100644", "100755":
			t.files[p] = factFile{id: e.id}
		case "120000":
			t.files[p] = factFile{id: e.id, link: true}
		}
	}
	return nil
}

func (t *factTree) Entries() ([]Entry, error) {
	out := make([]Entry, 0, len(t.files))
	for p, f := range t.files {
		out = append(out, Entry{Path: p, IsLink: f.link})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func (t *factTree) blob(p string, wantLink bool) ([]byte, error) {
	f, ok := t.files[p]
	if !ok || f.link != wantLink {
		return nil, fmt.Errorf("%s: not found as expected type", p)
	}
	o, ok := t.b.objs[f.id]
	if !ok {
		return nil, fmt.Errorf("%s: read outside the fact bundle", p)
	}
	return o.body, nil
}

func (t *factTree) Read(p string) ([]byte, error) { return t.blob(p, false) }

func (t *factTree) Link(p string) (string, error) {
	b, err := t.blob(p, true)
	return string(b), err
}

// RecordingSource wraps a Source and records the commit of every opened tag
// and every file read or link followed, so the read set of one normal run is
// exactly what a bundle must carry.
type RecordingSource struct {
	Inner Source

	mu      sync.Mutex
	commits map[string]string
	reads   map[string]map[string]bool
}

// Open implements Source.
func (r *RecordingSource) Open(tag string) (Tree, string, error) {
	t, commit, err := r.Inner.Open(tag)
	if err != nil {
		return nil, "", err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.commits == nil {
		r.commits, r.reads = map[string]string{}, map[string]map[string]bool{}
	}
	r.commits[tag] = commit
	if r.reads[tag] == nil {
		r.reads[tag] = map[string]bool{}
	}
	return &recordingTree{r: r, tag: tag, t: t}, commit, nil
}

type recordingTree struct {
	r   *RecordingSource
	tag string
	t   Tree
}

func (t *recordingTree) note(p string) {
	t.r.mu.Lock()
	t.r.reads[t.tag][p] = true
	t.r.mu.Unlock()
}

func (t *recordingTree) Entries() ([]Entry, error) { return t.t.Entries() }

func (t *recordingTree) Read(p string) ([]byte, error) {
	b, err := t.t.Read(p)
	if err == nil {
		t.note(p)
	}
	return b, err
}

func (t *recordingTree) Link(p string) (string, error) {
	l, err := t.t.Link(p)
	if err == nil {
		t.note(p)
	}
	return l, err
}

// objectStore serves raw git objects to the bundle builder.
type objectStore interface {
	Raw(kind, id string) ([]byte, error)
}

type gitStore struct{ g GitSource }

func (s gitStore) Raw(kind, id string) ([]byte, error) {
	if !sha1HexRE.MatchString(id) {
		return nil, errors.New("malformed object id")
	}
	if kind != "commit" && kind != "tree" && kind != "blob" {
		return nil, errors.New("malformed object kind")
	}
	if kind == "blob" {
		size, err := s.g.git("cat-file", "-s", id)
		if err != nil {
			return nil, err
		}
		n, err := strconv.Atoi(strings.TrimSpace(string(size)))
		if err != nil || n < 0 || n > MaxFileBytes {
			return nil, fmt.Errorf("blob %s is over the %d byte bound", id, MaxFileBytes)
		}
	}
	return s.g.git("cat-file", kind, id)
}

// BundleFromGit builds the deterministic fact bundle of everything the recorded run
// read, from a local git checkout. The result is parsed again, so a bundle
// that does not verify is never returned.
func (r *RecordingSource) BundleFromGit(g GitSource) ([]byte, error) {
	return r.buildBundle(gitStore{g})
}

func (r *RecordingSource) buildBundle(store objectStore) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.commits) == 0 {
		return nil, errors.New("nothing was recorded")
	}
	objs := map[string]bundleObj{}
	put := func(kind, id string, body []byte) {
		objs[id] = bundleObj{ID: id, Kind: kind, Data: base64.StdEncoding.EncodeToString(body)}
	}
	var tags []bundleTag
	for tag, commit := range r.commits {
		tags = append(tags, bundleTag{Tag: tag, Commit: commit})
		cbody, err := store.Raw("commit", commit)
		if err != nil {
			return nil, err
		}
		put("commit", commit, cbody)
		root, err := commitTreeID(cbody)
		if err != nil {
			return nil, err
		}
		blobs := map[string]string{} // path -> blob id
		var walk func(id, prefix string, depth int) error
		walk = func(id, prefix string, depth int) error {
			if depth > maxTreeDepth {
				return errors.New("tree nesting too deep")
			}
			body, err := store.Raw("tree", id)
			if err != nil {
				return err
			}
			put("tree", id, body)
			ents, err := parseTreeObject(body)
			if err != nil {
				return err
			}
			for _, e := range ents {
				switch {
				case e.isDir():
					if err := walk(e.id, prefix+e.name+"/", depth+1); err != nil {
						return err
					}
				case e.mode == "160000":
				default:
					blobs[prefix+e.name] = e.id
				}
			}
			return nil
		}
		if err := walk(root, "", 0); err != nil {
			return nil, err
		}
		for p := range r.reads[tag] {
			id, ok := blobs[p]
			if !ok {
				return nil, fmt.Errorf("tag %s: read path %s is not in its tree", tag, p)
			}
			body, err := store.Raw("blob", id)
			if err != nil {
				return nil, err
			}
			put("blob", id, body)
		}
	}
	sort.Slice(tags, func(i, j int) bool { return tags[i].Tag < tags[j].Tag })
	doc := bundleDoc{Schema: BundleSchema, Tags: tags}
	for _, o := range objs {
		doc.Objects = append(doc.Objects, o)
	}
	sort.Slice(doc.Objects, func(i, j int) bool { return doc.Objects[i].ID < doc.Objects[j].ID })
	raw, err := marshalBundle(doc)
	if err != nil {
		return nil, err
	}
	if _, err := ParseBundle(raw); err != nil {
		return nil, err
	}
	return raw, nil
}
