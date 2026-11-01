// SPDX-License-Identifier: AGPL-3.0-only

// Package crdschema derives, from the CRD files of a project at two pinned
// commits, which CRD fields and enum values the newer commit no longer
// accepts. The result is a pair of set fact values (members plus a complete
// flag) and a ledger of everything the extractor could not decide.
//
// The extractor is deliberately one-sided: it only ever names a removal it
// can prove. Everything else (version-specific changes, possible renames,
// preserved-unknown subtrees, conversion webhooks, documents it cannot prove
// it parsed, members it cannot encode exactly) is withheld, which makes the
// facts incomplete, so a withheld item can never turn into "nothing changed".
//
// Scope. A removal under status is a scope exclusion (ReasonStatusPath): users
// do not write status, so it is listed in the ledger, never emitted and never
// blocks completeness. Required-added is out of scope as well. These
// exclusions belong to the definition of the crd.schema family in the design,
// not to any free text: nothing here describes them to a user.
//
// Members carry no API version. A field is reported removed only when no
// version served by the newer commit has it.
package crdschema

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/membercode"
)

// ResultSchema identifies the canonical JSON of a Result.
const ResultSchema = "prufyx.io/crd-schema-removal/v1"

// Target names where the CRD files of a project live. Paths are
// repository-relative. A directory is read one level deep (files ending in
// .yaml or .yml); a CRD that moves into a subdirectory is therefore seen as
// absent and withheld, never as removed.
type Target struct {
	Repo  extract.RepoRef
	Files []string
	Dirs  []string
}

func (t Target) validate() error {
	if len(t.Files)+len(t.Dirs) == 0 {
		return errors.New("crdschema: target names no file or directory")
	}
	for _, p := range append(append([]string(nil), t.Files...), t.Dirs...) {
		if p == "" || p != path.Clean(p) || strings.HasPrefix(p, "/") || p == ".." || strings.HasPrefix(p, "../") {
			return fmt.Errorf("crdschema: target path %q is not a clean repository-relative path", p)
		}
	}
	return nil
}

// Omission is one ledger line: a reason, the subject it concerns (a group/Kind
// or a configured repository path, never document content) and how many items
// it covers.
type Omission struct {
	Reason  string `json:"reason"`
	Subject string `json:"subject"`
	Count   int    `json:"count"`
}

// Result is what Derive returns.
type Result struct {
	Schema string `json:"schema"`
	// Fields and Enums are the set fact values: the removed members, and
	// complete only when the withhold set is empty.
	Fields constraintengine.SetValue `json:"fields"`
	Enums  constraintengine.SetValue `json:"enums"`
	// Omissions are the withheld items. They are report text, not part of
	// the facts.
	Omissions []Omission `json:"omissions"`
	// Exclusions are scope exclusions that do not make the facts incomplete.
	Exclusions []Omission `json:"exclusions"`
}

// Canonical returns the canonical JSON of the result.
func (r *Result) Canonical() ([]byte, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// guards are switched off only by tests, to prove each guard is load bearing.
type guards struct {
	parse           parseGuards
	servedOnly      bool
	webhook         bool
	versionSpecific bool
	preserve        bool
	status          bool
	rename          bool
	presence        bool
	collisions      bool
	fieldEnc        func(group, kind string, p []membercode.Seg) (string, error)
	enumEnc         func(group, kind string, p []membercode.Seg, v string) (string, error)
}

func defaultGuards() guards {
	return guards{
		parse:      parseGuards{strict: true, secret: true, nonCRD: true, limits: true, unmodel: true},
		servedOnly: true, webhook: true, versionSpecific: true, preserve: true, status: true,
		rename: true, presence: true, collisions: true,
		fieldEnc: membercode.Field, enumEnc: membercode.Enum,
	}
}

// Derive compares the CRD files of target at from and to (full 40-character
// commits). A non-nil error means the run could not read pinned bytes
// (reader failure, bad input); anything the extractor cannot decide is in the
// result's omissions instead.
func Derive(ctx context.Context, r extract.PinnedReader, t Target, from, to string) (*Result, error) {
	return derive(ctx, r, t, from, to, defaultGuards())
}

func derive(ctx context.Context, r extract.PinnedReader, t Target, from, to string, g guards) (*Result, error) {
	if err := t.validate(); err != nil {
		return nil, err
	}
	if !extract.IsCommitSHA(from) || !extract.IsCommitSHA(to) {
		return nil, errors.New("crdschema: from and to must be full 40-character commit SHAs")
	}
	a, err := readSide(ctx, r, t, from, g)
	if err != nil {
		return nil, err
	}
	b, err := readSide(ctx, r, t, to, g)
	if err != nil {
		return nil, err
	}
	return compare(a, b, g), nil
}

type side struct {
	crds   map[string]*crdDoc
	blocks map[string]bool
	faults []fault
}

func readSide(ctx context.Context, r extract.PinnedReader, t Target, commit string, g guards) (*side, error) {
	s := &side{crds: map[string]*crdDoc{}, blocks: map[string]bool{}}
	files := append([]string(nil), t.Files...)
	for _, d := range t.Dirs {
		entries, err := r.List(t.Repo, commit, d)
		if errors.Is(err, extract.ErrNotFound) {
			s.faults = append(s.faults, fault{reason: ReasonPathMissing, file: d})
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("crdschema: list %s: %w", d, err)
		}
		if len(entries) > maxDirEntries {
			s.faults = append(s.faults, fault{reason: ReasonTooLarge, file: d})
			continue
		}
		for _, e := range entries {
			ext := path.Ext(e.Path)
			if ext != ".yaml" && ext != ".yml" {
				continue
			}
			if e.Type != "blob" || e.Mode == "120000" {
				s.faults = append(s.faults, fault{reason: ReasonSourceKind, file: e.Path})
				continue
			}
			files = append(files, e.Path)
		}
	}
	sort.Strings(files)
	for i, f := range files {
		if i > 0 && files[i-1] == f {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data, err := r.Read(t.Repo, commit, f)
		if errors.Is(err, extract.ErrNotFound) {
			s.faults = append(s.faults, fault{reason: ReasonPathMissing, file: f})
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("crdschema: read %s: %w", f, err)
		}
		docs, faults := parseFile(f, data, g.parse)
		s.faults = append(s.faults, faults...)
		for _, fl := range faults {
			if fl.key != "" {
				s.blocks[fl.key] = true
			}
		}
		for _, d := range docs {
			if _, dup := s.crds[d.key()]; dup {
				s.faults = append(s.faults, fault{reason: ReasonParseUnproven, file: f, key: d.key()})
				s.blocks[d.key()] = true
				continue
			}
			s.crds[d.key()] = d
		}
	}
	for k := range s.blocks {
		delete(s.crds, k)
	}
	return s, nil
}

type ledger map[Omission]int

func (l ledger) add(reason, subject string) { l[Omission{Reason: reason, Subject: subject}]++ }

func (l ledger) list() []Omission {
	out := make([]Omission, 0, len(l))
	for k, n := range l {
		k.Count = n
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Reason != out[j].Reason {
			return out[i].Reason < out[j].Reason
		}
		return out[i].Subject < out[j].Subject
	})
	return out
}

// subjectOf is the public name of a CRD for the ledger, or the configured
// file path when the group/Kind cannot be encoded.
func subjectOf(group, kind, file string) string {
	if _, err := membercode.Field(group, kind, []membercode.Seg{{Kind: membercode.Prop, Name: "x"}}); err != nil {
		return file
	}
	return group + "/" + kind
}

type out struct {
	fields, enums   map[string]string // member -> internal path key
	dropped         map[string]bool
	omit, exclusion ledger
}

func compare(a, b *side, g guards) *Result {
	o := &out{
		fields: map[string]string{}, enums: map[string]string{}, dropped: map[string]bool{},
		omit: ledger{}, exclusion: ledger{},
	}
	for _, f := range append(append([]fault(nil), a.faults...), b.faults...) {
		subject := f.file
		if f.key != "" {
			if parts := strings.SplitN(f.key, "\x00", 2); len(parts) == 2 {
				subject = subjectOf(parts[0], parts[1], f.file)
			}
		}
		o.omit.add(f.reason, subject)
	}
	keys := make([]string, 0, len(a.crds))
	for k := range a.crds {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		da := a.crds[k]
		subject := subjectOf(da.group, da.kind, da.file)
		db, ok := b.crds[k]
		if !ok {
			if b.blocks[k] {
				continue // already in the ledger
			}
			if g.presence {
				o.omit.add(ReasonPresence, subject)
			}
			continue
		}
		if g.webhook && (da.webhook || db.webhook) {
			o.omit.add(ReasonConversion, subject)
			continue
		}
		diffCRD(o, da, db, subject, g)
	}
	res := &Result{Schema: ResultSchema, Omissions: o.omit.list(), Exclusions: o.exclusion.list()}
	complete := len(res.Omissions) == 0
	fm, over := capped(o.fields, o.dropped, "f")
	if over {
		res.Omissions = append(res.Omissions, Omission{Reason: ReasonSetTooLarge, Subject: "fields", Count: 1})
		complete = false
	}
	em, over := capped(o.enums, o.dropped, "e")
	if over {
		res.Omissions = append(res.Omissions, Omission{Reason: ReasonSetTooLarge, Subject: "enums", Count: 1})
		complete = false
	}
	res.Fields = constraintengine.SetValue{Members: fm, Complete: complete}
	res.Enums = constraintengine.SetValue{Members: em, Complete: complete}
	return res
}

func capped(m map[string]string, dropped map[string]bool, setName string) ([]string, bool) {
	list := make([]string, 0, len(m))
	for k := range m {
		if !dropped[setName+k] {
			list = append(list, k)
		}
	}
	sort.Strings(list)
	if len(list) > constraintengine.MaxSetMembers {
		return list[:constraintengine.MaxSetMembers], true
	}
	return list, false
}

type served struct {
	name string
	t    *tree
}

func servedOf(d *crdDoc, g guards) (out []served) {
	for _, v := range d.versions {
		if g.servedOnly && !v.served {
			continue
		}
		if v.tree == nil {
			continue
		}
		out = append(out, served{v.name, v.tree})
	}
	return out
}

func isStatus(segs []membercode.Seg) bool {
	return len(segs) > 0 && segs[0].Kind == membercode.Prop && segs[0].Name == "status"
}

func parentKey(segs []membercode.Seg) (string, bool) {
	if len(segs) <= 1 {
		return "", false
	}
	return segKey(segs[:len(segs)-1]), true
}

// union returns the paths of all versions, keyed by path key.
func union(vs []served) map[string][]membercode.Seg {
	u := map[string][]membercode.Seg{}
	for _, v := range vs {
		for k, n := range v.t.nodes {
			if len(n.segs) > 0 {
				u[k] = n.segs
			}
		}
	}
	return u
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// roots keeps the paths of set whose parent is not in set.
func roots(set map[string][]membercode.Seg) []string {
	var out []string
	for _, k := range sortedKeys(set) {
		if pk, ok := parentKey(set[k]); ok {
			if _, in := set[pk]; in {
				continue
			}
		}
		out = append(out, k)
	}
	return out
}

func hasPrefix(segs, prefix []membercode.Seg) bool {
	if len(segs) < len(prefix) {
		return false
	}
	for i := range prefix {
		if segs[i] != prefix[i] {
			return false
		}
	}
	return true
}

func diffCRD(o *out, da, db *crdDoc, subject string, g guards) {
	va, vb := servedOf(da, g), servedOf(db, g)
	if len(va) == 0 || len(vb) == 0 {
		o.omit.add(ReasonParseUnproven, subject)
		return
	}
	statusScoped := g.status
	ua, ub := union(va), union(vb)

	// Removed field paths: in a served version of A, in no served version of B.
	removed := map[string][]membercode.Seg{}
	for k, segs := range ua {
		if _, in := ub[k]; !in {
			removed[k] = segs
		}
	}
	// Version-specific: gone from one served version of B that had it in the
	// same-named version of A, but still present in another served version.
	specific := map[string][]membercode.Seg{}
	for k, segs := range ua {
		if _, in := ub[k]; !in {
			continue
		}
		for _, bv := range vb {
			if _, has := bv.t.nodes[k]; has {
				continue
			}
			for _, av := range va {
				if av.name == bv.name {
					if _, had := av.t.nodes[k]; had {
						specific[k] = segs
					}
				}
			}
		}
	}

	// Names of properties that exist in B at a path A did not have: where a
	// moved or renamed field would have gone.
	bNames := map[string]bool{}
	for k, segs := range ub {
		if _, old := ua[k]; old {
			continue
		}
		if last := segs[len(segs)-1]; last.Kind == membercode.Prop {
			bNames[last.Name] = true
		}
	}

	handle := func(k string, segs []membercode.Seg, reasons []string, subtree map[string][]membercode.Seg) {
		if statusScoped && isStatus(segs) {
			o.exclusion.add(ReasonStatusPath, subject)
			return
		}
		if len(reasons) > 0 {
			for _, r := range reasons {
				o.omit.add(r, subject)
			}
			return
		}
		for _, dk := range sortedKeys(subtree) {
			if hasPrefix(subtree[dk], segs) {
				o.addField(da.group, da.kind, subtree[dk], dk, subject, g)
			}
		}
	}

	for _, k := range roots(removed) {
		segs := removed[k]
		var reasons []string
		if last := segs[len(segs)-1]; last.Kind != membercode.Prop {
			reasons = append(reasons, ReasonParseUnproven)
		} else if g.rename && bNames[last.Name] {
			reasons = append(reasons, ReasonRename)
		}
		reasons = append(reasons, chainReasons(segs, va, vb, g)...)
		handle(k, segs, dedup(reasons), removed)
	}
	for _, k := range roots(specific) {
		if g.versionSpecific {
			handle(k, specific[k], []string{ReasonVersionSpecific}, specific)
		} else {
			handle(k, specific[k], nil, specific)
		}
	}
	diffEnums(o, da, db, subject, va, vb, ub, statusScoped, g)
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// chainReasons checks the schema above a removed path. In A every version
// that has the path is checked from the path up; in B the nearest ancestor
// that still exists in each served version is.
func chainReasons(segs []membercode.Seg, va, vb []served, g guards) []string {
	var r []string
	flag := func(n *pnode) {
		if g.preserve && n.chainPreserve() {
			r = append(r, ReasonPreserveUnknown)
		}
		if g.parse.unmodel && n.chainUnmodel() {
			r = append(r, ReasonParseUnproven)
		}
	}
	key := segKey(segs)
	for _, v := range va {
		if n, ok := v.t.nodes[key]; ok {
			flag(n)
		}
	}
	for _, v := range vb {
		for i := len(segs) - 1; i >= 0; i-- {
			if n, ok := v.t.nodes[segKey(segs[:i])]; ok {
				flag(n)
				break
			}
		}
	}
	return r
}

func (o *out) addField(group, kind string, segs []membercode.Seg, pathKey, subject string, g guards) {
	m, err := g.fieldEnc(group, kind, segs)
	o.encoded(m, err, pathKey, subject, "f", g)
}

// encoded records a member or its failure, and reports whether it was kept.
func (o *out) encoded(m string, err error, pathKey, subject, setName string, g guards) bool {
	set := o.fields
	if setName == "e" {
		set = o.enums
	}
	switch {
	case errors.Is(err, membercode.ErrCharset):
		o.omit.add(ReasonMemberCharset, subject)
		return false
	case errors.Is(err, membercode.ErrTooLong):
		o.omit.add(ReasonMemberTooLong, subject)
		return false
	case errors.Is(err, membercode.ErrAmbiguous):
		o.omit.add(ReasonMemberAmbiguous, subject)
		return false
	case err != nil:
		o.omit.add(ReasonMemberCharset, subject)
		return false
	}
	if g.collisions {
		if prev, dup := set[m]; dup && prev != pathKey {
			o.omit.add(ReasonMemberAmbiguous, subject)
			o.dropped[setName+m] = true
			return false
		}
		if o.dropped[setName+m] {
			return false
		}
	}
	set[m] = pathKey
	return true
}

func diffEnums(o *out, da, db *crdDoc, subject string, va, vb []served, ub map[string][]membercode.Seg, statusScoped bool, g guards) {
	// Where each value is listed in B at a place A did not list it, for the
	// rename check.
	aListed := map[string]bool{}
	for _, v := range va {
		for k, n := range v.t.nodes {
			for val := range n.enum.vals {
				aListed[k+"\x00"+val] = true
			}
		}
	}
	bValues := map[string]map[string]bool{}
	for _, v := range vb {
		for k, n := range v.t.nodes {
			for val := range n.enum.vals {
				if aListed[k+"\x00"+val] {
					continue
				}
				if bValues[val] == nil {
					bValues[val] = map[string]bool{}
				}
				bValues[val][k] = true
			}
		}
	}
	ua := union(va)
	for _, k := range sortedKeys(ua) {
		segs := ua[k]
		if _, in := ub[k]; !in {
			continue // the field itself is gone: a field removal
		}
		vals := map[string]bool{}
		nonString, any := false, false
		for _, v := range va {
			if n, ok := v.t.nodes[k]; ok && n.enum.present {
				any = true
				nonString = nonString || n.enum.nonString
				for x := range n.enum.vals {
					vals[x] = true
				}
			}
		}
		if !any {
			continue
		}
		var common []string
		for _, v := range vb {
			if n, ok := v.t.nodes[k]; ok {
				if n.enum.nonString {
					nonString = true
				}
				if g.preserve && n.chainPreserve() {
					common = append(common, ReasonPreserveUnknown)
				}
				if g.parse.unmodel && n.chainUnmodel() {
					common = append(common, ReasonParseUnproven)
				}
			}
		}
		for _, v := range va {
			if n, ok := v.t.nodes[k]; ok {
				if g.preserve && n.chainPreserve() {
					common = append(common, ReasonPreserveUnknown)
				}
				if g.parse.unmodel && n.chainUnmodel() {
					common = append(common, ReasonParseUnproven)
				}
			}
		}
		if nonString {
			o.omit.add(ReasonParseUnproven, subject)
			continue
		}
		for _, val := range sortedKeys(vals) {
			rejectAll, rejectSome := true, false
			for _, bv := range vb {
				n, ok := bv.t.nodes[k]
				if !ok {
					continue
				}
				if !n.enum.present || n.enum.vals[val] {
					rejectAll = false
					continue
				}
				// B rejects the value here; was it accepted by A's same-named version?
				for _, av := range va {
					if av.name != bv.name {
						continue
					}
					an, ok := av.t.nodes[k]
					if ok && (!an.enum.present || an.enum.vals[val]) {
						rejectSome = true
					}
				}
			}
			if rejectAll {
				rejectSome = false
			} else if !rejectSome {
				continue
			}
			reasons := append([]string(nil), common...)
			if rejectSome && g.versionSpecific {
				reasons = append(reasons, ReasonVersionSpecific)
			}
			if g.rename {
				for other := range bValues[val] {
					if other != k {
						reasons = append(reasons, ReasonRename)
						break
					}
				}
			}
			if statusScoped && isStatus(segs) {
				o.exclusion.add(ReasonStatusPath, subject)
				continue
			}
			if len(reasons) > 0 {
				for _, r := range dedup(reasons) {
					o.omit.add(r, subject)
				}
				continue
			}
			m, err := g.enumEnc(da.group, da.kind, segs, val)
			o.encoded(m, err, k+"\x00"+val, subject, "e", g)
		}
	}
}
