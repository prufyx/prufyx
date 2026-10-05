// SPDX-License-Identifier: AGPL-3.0-only

// Package extractpack merges the output of an extractor run into a rule
// pack file, and withdraws the rules an extractor no longer produces.
//
// It lives beside the extractor framework, not in it: the framework's
// source is covered by every extractor's code digest, and editing a pack is
// not part of deriving a rule. Everything here is deterministic and offline.
//
// The merge is canonical. The output pack lists its top-level members in
// the fixed order of lineattest.PackMembers, its entries sorted by project
// and rule id, each entry rendered as canonical JSON (keys in byte order),
// two-space indentation and a final newline, so merging a run that adds
// nothing reproduces the pack byte for byte.
package extractpack

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/strictjson"
)

// Errors a caller can test for.
var (
	// ErrRun means the run directory is not an intact, consistent run.
	ErrRun = errors.New("extract apply: the run directory is not an intact extractor run")
	// ErrCollision means a rule or attestation of the run has the identity
	// of one in the pack but different content.
	ErrCollision = errors.New("extract apply: identity collision with different content")
	// ErrForeignChange means the result would change a rule the run did not
	// produce (or change a rule other than by withdrawing it).
	ErrForeignChange = errors.New("extract apply: the result changes a rule the run did not produce")
	// ErrAdmission means the merged pack is not admitted by rulecheck or the
	// engine loader.
	ErrAdmission = errors.New("extract apply: the merged pack is not admitted")
	// ErrStale means a withdrawal would rest on a run that is older than a
	// rule, built by other code, or pinned to other commits; nothing is
	// written.
	ErrStale = errors.New("extract apply: the run does not supersede the rule it would withdraw")
	// ErrPack means the pack file cannot be read as a rule pack.
	ErrPack = errors.New("extract apply: the pack file is not a readable rule pack")
)

// Pack is a rule pack as a list of members in canonical order plus its
// entries.
type Pack struct {
	// Members are the top-level members other than entries, as raw JSON.
	Members map[string]json.RawMessage
	// Entries are the pack entries, raw.
	Entries []json.RawMessage
}

// ParsePack reads a rule pack. Member names must be exactly the known pack
// members and no object anywhere may repeat or case-fold a member (the
// checks the pack loaders apply).
func ParsePack(raw []byte) (*Pack, error) {
	if _, _, err := lineattest.PackSection(raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPack, err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPack, err)
	}
	p := &Pack{Members: members}
	rawEntries, ok := members["entries"]
	if !ok {
		return nil, fmt.Errorf("%w: no entries member", ErrPack)
	}
	delete(p.Members, "entries")
	if err := json.Unmarshal(rawEntries, &p.Entries); err != nil {
		return nil, fmt.Errorf("%w: entries: %v", ErrPack, err)
	}
	return p, nil
}

// entryView is what apply needs to know about an entry.
type entryView struct {
	Project string `json:"project"`
	Rule    struct {
		ID       string `json:"id"`
		Subject  extract.Subject
		Evidence struct {
			State     string `json:"state"`
			Basis     string `json:"basis"`
			DerivedAt string `json:"derivedAt"`
			Extractor *struct {
				ID         string `json:"id"`
				CodeDigest string `json:"codeDigest"`
			} `json:"extractor"`
			Sources []struct {
				Revision string `json:"revision"`
			} `json:"sources"`
		} `json:"evidence"`
	} `json:"rule"`
}

func viewOf(raw json.RawMessage) (entryView, error) {
	var v entryView
	if err := json.Unmarshal(raw, &v); err != nil || v.Rule.ID == "" {
		return entryView{}, fmt.Errorf("%w: an entry has no rule id", ErrPack)
	}
	return v, nil
}

// canon renders a raw JSON value as canonical JSON.
func canon(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return extract.Canonical(v)
}

func compact(raw []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Render writes the pack: members in lineattest.PackMembers order, entries
// sorted by project and rule id, two-space indentation, a final newline.
// Each entry keeps the member order it was read with, so an entry the run
// did not touch keeps its bytes; entries a run adds are canonical JSON.
func (p *Pack) Render() ([]byte, error) {
	type item struct {
		project, id string
		raw         []byte
	}
	items := make([]item, 0, len(p.Entries))
	for _, e := range p.Entries {
		v, err := viewOf(e)
		if err != nil {
			return nil, err
		}
		cc, err := compact(e)
		if err != nil {
			return nil, err
		}
		items = append(items, item{v.Project, v.Rule.ID, cc})
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].project != items[j].project {
			return items[i].project < items[j].project
		}
		return items[i].id < items[j].id
	})
	entries := make([]json.RawMessage, len(items))
	for i, it := range items {
		entries[i] = it.raw
	}
	entriesRaw := joinArray(entries)
	var buf bytes.Buffer
	buf.WriteString("{\n")
	first := true
	for _, name := range lineattest.PackMembers {
		var value []byte
		switch {
		case name == "entries":
			value = entriesRaw
		case p.Members[name] != nil:
			value = p.Members[name]
		default:
			continue
		}
		cv, err := compact(value)
		if err != nil {
			return nil, err
		}
		var ind bytes.Buffer
		if err := json.Indent(&ind, cv, "  ", "  "); err != nil {
			return nil, err
		}
		if !first {
			buf.WriteString(",\n")
		}
		first = false
		key, _ := json.Marshal(name)
		buf.WriteString("  ")
		buf.Write(key)
		buf.WriteString(": ")
		buf.Write(ind.Bytes())
	}
	buf.WriteString("\n}\n")
	return buf.Bytes(), nil
}

// Run is a loaded, checked extractor run directory.
type Run struct {
	Manifest     extract.Manifest
	Entries      []json.RawMessage // candidates.json
	Attestations []lineattest.LineAttestation
}

// LoadRun reads a run directory written by "extract run". It requires the
// manifest's recorded digests to match the files, every candidate to carry
// the manifest's extractor identity, and the candidates' rule ids to be
// exactly the ids the manifest's derived pairs list.
func LoadRun(dir string) (*Run, error) {
	m, err := extract.ReadManifest(dir)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRun, err)
	}
	read := func(name string) ([]byte, error) {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrRun, err)
		}
		want, ok := m.Outputs[name]
		if !ok {
			return nil, fmt.Errorf("%w: the manifest does not list %s", ErrRun, name)
		}
		if got := digestOf(raw); got != want {
			return nil, fmt.Errorf("%w: %s differs from the digest the manifest records", ErrRun, name)
		}
		return raw, nil
	}
	if _, err := read(extract.FileVectors); err != nil {
		return nil, err
	}
	raw, err := read(extract.FileCandidates)
	if err != nil {
		return nil, err
	}
	if err := strictjson.Check(raw); err != nil {
		return nil, fmt.Errorf("%w: candidates: %v", ErrRun, err)
	}
	r := &Run{Manifest: m}
	if err := json.Unmarshal(raw, &r.Entries); err != nil {
		return nil, fmt.Errorf("%w: candidates: %v", ErrRun, err)
	}
	if _, has := m.Outputs[extract.FileAttestations]; has {
		araw, err := read(extract.FileAttestations)
		if err != nil {
			return nil, err
		}
		if r.Attestations, err = lineattest.Parse(araw); err != nil {
			return nil, fmt.Errorf("%w: attestations: %v", ErrRun, err)
		}
	} else if _, err := os.Stat(filepath.Join(dir, extract.FileAttestations)); err == nil {
		return nil, fmt.Errorf("%w: %s is not listed by the manifest", ErrRun, extract.FileAttestations)
	}
	listed := map[string]bool{}
	for _, pr := range m.Pairs {
		if pr.Status != extract.PairDerived {
			if len(pr.Rules) > 0 {
				return nil, fmt.Errorf("%w: a withheld pair lists rules", ErrRun)
			}
			continue
		}
		for _, id := range pr.Rules {
			listed[id] = true
		}
	}
	have := map[string]bool{}
	for _, e := range r.Entries {
		v, err := viewOf(e)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrRun, err)
		}
		if v.Rule.Evidence.Extractor == nil || v.Rule.Evidence.Extractor.ID != m.Extractor.ID || v.Rule.Evidence.Basis != "mechanical" || v.Rule.Evidence.State != "active" {
			return nil, fmt.Errorf("%w: rule %s is not an active mechanical rule of %s", ErrRun, v.Rule.ID, m.Extractor.ID)
		}
		if !listed[v.Rule.ID] || have[v.Rule.ID] {
			return nil, fmt.Errorf("%w: rule %s is not one the manifest's derived pairs list exactly once", ErrRun, v.Rule.ID)
		}
		have[v.Rule.ID] = true
	}
	if len(have) != len(listed) {
		return nil, fmt.Errorf("%w: the manifest lists %d rules, candidates.json holds %d", ErrRun, len(listed), len(have))
	}
	return r, nil
}

func digestOf(b []byte) string {
	return extractDigest(b)
}

// Report says what an apply did.
type Report struct {
	Added        []string // rule ids added
	Unchanged    []string // rule ids already present with identical content
	Withdrawn    []string // rule ids set to withdrawn
	AttAdded     []string // attestation keys added
	AttUnchanged []string
	SchemaFrom   string
	SchemaTo     string
	Changed      bool
}

// Options configures Apply.
type Options struct {
	// PackPath is the pack file, rewritten in place when something changes.
	PackPath string
	// RunDir is the extractor run directory.
	RunDir string
	// Withdraw switches to withdrawal mode.
	Withdraw bool
	// ExistingRules are further published pack files whose rule ids a new
	// rule must not reuse.
	ExistingRules []string
	// Admit admits a merged pack as the engine loaders do. Nil uses
	// AdmitFiles. It must be set for any real use; tests inject their own.
	Admit func(packPath string, raw []byte) error
	// RulesOnly applies the run's rules without its attestations and without
	// any change to the pack schema.
	RulesOnly bool
	// SchemaLevels bounds how many schema levels above the pack's own a merge
	// may move to (default 12).
	SchemaLevels int
}

// mergeStep and withdrawStep are the steps Apply runs. They are variables
// only so a test can make one misbehave and show the final audit refuses it.
var (
	mergeStep    = merge
	withdrawStep = withdraw
)

// Apply merges (or, with Withdraw, withdraws) and rewrites the pack file.
func Apply(opts Options) (*Report, error) {
	run, err := LoadRun(opts.RunDir)
	if err != nil {
		return nil, err
	}
	baseRaw, err := os.ReadFile(opts.PackPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPack, err)
	}
	base, err := ParsePack(baseRaw)
	if err != nil {
		return nil, err
	}
	if opts.RulesOnly {
		if opts.Withdraw {
			return nil, errors.New("extract apply: --rules-only does not combine with --withdraw")
		}
		run.Attestations = nil
	}
	var head *Pack
	var allowed map[string]bool
	rep := &Report{}
	if opts.Withdraw {
		head, allowed, err = withdrawStep(base, run, rep)
	} else {
		head, allowed, err = mergeStep(base, run, rep)
	}
	if err != nil {
		return nil, err
	}
	if len(allowed) == 0 && len(rep.AttAdded) == 0 {
		return rep, nil
	}
	admit := opts.Admit
	if admit == nil {
		admit = AdmitFiles
	}
	if !opts.Withdraw {
		if err := checkCandidates(base, head, allowed, opts, baseRaw); err != nil {
			return nil, err
		}
	}
	rep.SchemaFrom = schemaOf(base)
	out, err := head.Render()
	if err != nil {
		return nil, err
	}
	if err := admit(opts.PackPath, out); err != nil && opts.RulesOnly {
		return nil, fmt.Errorf("%w: the engine loader refuses the merged pack at its own schema (--rules-only never changes it): %v%s", ErrAdmission, err, newFactsHint(base, head, allowed))
	} else if err != nil {
		levels := opts.SchemaLevels
		if levels == 0 {
			levels = 12
		}
		out, err = bumpToAdmitted(head, opts.PackPath, admit, levels, err)
		if err != nil {
			return nil, fmt.Errorf("%w%s", err, newFactsHint(base, head, allowed))
		}
	}
	if err := checkAttestations(out); err != nil {
		return nil, err
	}
	final, err := ParsePack(out)
	if err != nil {
		return nil, err
	}
	rep.SchemaTo = schemaOf(final)
	if err := audit(base, final, allowed, attAllowed(rep), opts.Withdraw); err != nil {
		return nil, err
	}
	rep.Changed = !bytes.Equal(out, baseRaw)
	sort.Strings(rep.Added)
	sort.Strings(rep.Unchanged)
	sort.Strings(rep.Withdrawn)
	sort.Strings(rep.AttAdded)
	sort.Strings(rep.AttUnchanged)
	if rep.Changed {
		if err := writeAtomic(opts.PackPath, out); err != nil {
			return nil, err
		}
	}
	return rep, nil
}

func schemaOf(p *Pack) string {
	var s string
	_ = json.Unmarshal(p.Members["schema"], &s)
	return s
}

func setSchema(p *Pack, schema string) *Pack {
	cp := &Pack{Members: map[string]json.RawMessage{}, Entries: p.Entries}
	for k, v := range p.Members {
		cp.Members[k] = v
	}
	raw, _ := json.Marshal(schema)
	cp.Members["schema"] = raw
	return cp
}

func writeAtomic(path string, data []byte) error {
	info, err := os.Stat(path)
	mode := os.FileMode(0o644)
	if err == nil {
		mode = info.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".extract-apply-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := io.Copy(tmp, bytes.NewReader(data)); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// joinArray joins raw values into a JSON array without re-encoding them (a
// marshal of raw messages would rewrite "<" as \u003c).
func joinArray(items []json.RawMessage) []byte {
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, it := range items {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(it)
	}
	buf.WriteByte(']')
	return buf.Bytes()
}
