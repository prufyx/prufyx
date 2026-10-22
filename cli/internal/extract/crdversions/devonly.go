// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Dev-only Makefile targets (see DevOnlyMake). An entry (Makefile M, target
// T) is applied at one tag only when the files of the tag show that T is
// reached from nowhere else:
//
//   - M is read and has a rule header that names T;
//   - T occurs as a word (tokenize) nowhere in a Makefile, shell script or
//     container build of the tag, except in T's own rule headers and recipe
//     lines in M, in the headers of special targets (those that start with
//     "." other than .DEFAULT_GOAL), and in rules whose every target is an
//     applied entry. Documents that name T do not void the entry: the proof
//     lists them;
//   - nothing runs make with a word it cannot read (a variable reference, a
//     "$" or a "%"), and no rule of a target that is not an applied entry has
//     a prerequisite that holds one (such a word may expand to T);
//   - every include names a literal, clean path of a Makefile that was read;
//   - T is not the default goal and no .DEFAULT_GOAL or first rule leaves
//     the default goal open (an include before the first rule, a first
//     target with a variable or "%");
//   - no .RECIPEPREFIX is set, and no GNUmakefile or Makefile next to M
//     could be read instead of it.
//
// The entries are decided together: an applied entry may be named by
// another applied entry, so the set is the greatest one in which every
// entry holds (all start applied, one that fails is dropped, repeat). Where
// the data cannot be read in full (a file over a bound, an unreadable
// install surface) no entry is applied. What an applied entry changes: the
// recipe lines of M whose every target is an applied entry are not counted
// by the Makefile check of the guard. The check never reads the tag's
// continuous integration configuration or other build systems (NotRead).

// maxDevUses bounds the distinct (word, rule) pairs kept for one file.
// Over it the file is incomplete for this check, so no entry is applied;
// the file is still read by the guard as before.
const maxDevUses = 50000

// maxDevDocs bounds the documents listed in a proof record.
const maxDevDocs = 20

// devUse is one word of a file in the rule it occurs in (ctx indexes
// devInfo.ctxs; -1: outside a rule or a file that has none), in the header
// of the rule or in its recipe.
type devUse struct {
	word   string
	ctx    int
	recipe bool
}

// devRule is one rule header of a Makefile.
type devRule struct {
	targets []string
	// dynPrereq: a prerequisite word holds "$" or "%".
	dynPrereq bool
}

// devInfo is what the dev-only check needs of one file. It depends only on
// the bytes and the kind of the file.
type devInfo struct {
	// over: a bound was passed; the record is incomplete.
	over bool
	// ctxs are the distinct target lists of the rules the words occur in.
	ctxs [][]string
	// uses are sorted by word.
	uses  []devUse
	rules []devRule
	// goal indexes the first rule with a target that does not start with
	// "." (-1: none).
	goal int
	// includes are the operands of the include lines.
	includes []string
	// includeBeforeGoal: an include precedes the first goal rule.
	includeBeforeGoal bool
	// dynMake: a line runs make with a word that holds "$" or "%".
	dynMake bool
	// hasGoal: .DEFAULT_GOAL occurs; dynGoal: on a line with "$" or "%".
	hasGoal, dynGoal bool
	// recipePrefix: .RECIPEPREFIX occurs.
	recipePrefix bool
}

var (
	// makeInvokeRE finds a word that runs make.
	makeInvokeRE  = regexp.MustCompile(`(?:^|[^A-Za-z0-9_.-])g?make(?:$|[^A-Za-z0-9_./-])|\$[({]MAKE[)}]`)
	makeIncludeRE = regexp.MustCompile(`^ *(?:-include|sinclude|include)(?:[ \t]+(.*))?$`)
	makeDefineRE  = regexp.MustCompile(`^ *(?:define|endef)(?:[ \t]|$)`)
)

// dynamicWord reports a word that may expand to a name: it holds a variable
// or automatic variable reference ("$") or a pattern ("%").
func dynamicWord(w string) bool { return strings.ContainsAny(w, "$%") }

// dynamicMake reports a line that runs make (make, gmake, $(MAKE), ${MAKE})
// with a word after it that holds "$" or "%". The words after the command
// are not cut at a pipe or a separator: more is read, never less.
func dynamicMake(line string) bool {
	for _, loc := range makeInvokeRE.FindAllStringIndex(line, -1) {
		for _, w := range strings.Fields(line[loc[1]:]) {
			if dynamicWord(w) {
				return true
			}
		}
	}
	return false
}

// devBuilder collects a devInfo. A nil builder collects nothing.
type devBuilder struct {
	info  *devInfo
	seen  map[devUse]bool
	ctxOf map[string]int
}

func newDevBuilder() *devBuilder {
	return &devBuilder{info: &devInfo{goal: -1}, seen: map[devUse]bool{}, ctxOf: map[string]int{}}
}

// ctx returns the index of a rule's target list (-1 for none).
func (b *devBuilder) ctx(targets []string) int {
	if b == nil || len(targets) == 0 {
		return -1
	}
	key := strings.Join(targets, "\x00")
	if i, ok := b.ctxOf[key]; ok {
		return i
	}
	b.ctxOf[key] = len(b.info.ctxs)
	b.info.ctxs = append(b.info.ctxs, append([]string(nil), targets...))
	return b.ctxOf[key]
}

// words records the words of text.
func (b *devBuilder) words(text string, ctx int, recipe bool) {
	if b == nil || b.info.over {
		return
	}
	for _, w := range tokenize(text) {
		u := devUse{word: w, ctx: ctx, recipe: recipe}
		if b.seen[u] {
			continue
		}
		if b.seen[u] = true; len(b.seen) > maxDevUses {
			b.info.over = true
			return
		}
	}
}

// note reads the whole-line facts: make runs with a word that is not
// literal, .DEFAULT_GOAL and .RECIPEPREFIX.
func (b *devBuilder) note(line string, makefile bool) {
	if b == nil {
		return
	}
	if dynamicMake(line) {
		b.info.dynMake = true
	}
	if !makefile {
		return
	}
	for _, w := range tokenize(line) {
		switch w {
		case ".RECIPEPREFIX":
			b.info.recipePrefix = true
		case ".DEFAULT_GOAL":
			b.info.hasGoal = true
			if strings.ContainsAny(line, "$%") {
				b.info.dynGoal = true
			}
		}
	}
}

func (b *devBuilder) include(operands []string) {
	if b == nil {
		return
	}
	if b.info.goal < 0 {
		b.info.includeBeforeGoal = true
	}
	if b.info.includes = append(b.info.includes, operands...); len(b.info.includes) > maxSurfaceLines {
		b.info.over = true
	}
}

// rule records a rule header line: the targets, the header text (before a
// ";") and the recipe text after it.
func (b *devBuilder) rule(targets []string, line string) {
	if b == nil {
		return
	}
	head, recipe := line, ""
	if i := strings.Index(line, ";"); i >= 0 {
		head, recipe = line[:i], line[i+1:]
	}
	dyn := true
	if c := strings.Index(head, ":"); c >= 0 {
		dyn = false
		for _, w := range strings.Fields(head[c+1:]) {
			dyn = dyn || dynamicWord(w)
		}
	}
	b.info.rules = append(b.info.rules, devRule{targets: append([]string(nil), targets...), dynPrereq: dyn})
	if len(b.info.rules) > maxSurfaceLines {
		b.info.over = true
	}
	if b.info.goal < 0 {
		for _, t := range targets {
			if !strings.HasPrefix(t, ".") {
				b.info.goal = len(b.info.rules) - 1
				break
			}
		}
	}
	ctx := b.ctx(targets)
	b.words(head, ctx, false)
	b.words(recipe, ctx, true)
}

func (b *devBuilder) finish() *devInfo {
	if b == nil {
		return nil
	}
	for u := range b.seen {
		b.info.uses = append(b.info.uses, u)
	}
	sort.Slice(b.info.uses, func(i, j int) bool {
		x, y := b.info.uses[i], b.info.uses[j]
		if x.word != y.word {
			return x.word < y.word
		}
		if x.ctx != y.ctx {
			return x.ctx < y.ctx
		}
		return !x.recipe && y.recipe
	})
	return b.info
}

// devWords reads a shell script, container build or document: every word,
// outside any rule, and (not for a document) the lines that run make.
func devWords(data []byte, runsMake bool) *devInfo {
	b := newDevBuilder()
	for _, line := range logicalLines(data) {
		if runsMake {
			b.note(line, false)
		}
		b.words(line, -1, false)
	}
	return b.finish()
}

// find returns the uses of a word.
func (d *devInfo) find(word string) []devUse {
	i := sort.Search(len(d.uses), func(i int) bool { return d.uses[i].word >= word })
	j := i
	for j < len(d.uses) && d.uses[j].word == word {
		j++
	}
	return d.uses[i:j]
}

// devFile is one file the dev-only check reads.
type devFile struct {
	path string
	kind int
	info *devInfo
}

func devKey(file, target string) string { return file + "\x00" + target }

func containsWord(list []string, w string) bool {
	for _, x := range list {
		if x == w {
			return true
		}
	}
	return false
}

// dotRule reports the targets of a special rule: every one starts with "."
// (.PHONY, .SUFFIXES) and none is .DEFAULT_GOAL.
func dotRule(targets []string) bool {
	if len(targets) == 0 {
		return false
	}
	for _, t := range targets {
		if !strings.HasPrefix(t, ".") || t == ".DEFAULT_GOAL" {
			return false
		}
	}
	return true
}

// evalDevOnly decides the entries against the files of one tag (sorted by
// path): which are applied (by devKey(makefile, target)) and the proof
// record of each. blocked, when set, says why no entry can be applied (an
// install surface that cannot be checked). blobs are all the paths of the
// tree.
func evalDevOnly(entries []DevOnlyMake, files []devFile, blobs map[string]bool, blocked string) (map[string]bool, []DevOnlyMakeRecord) {
	byPath := map[string]devFile{}
	makePaths := map[string]bool{}
	for _, f := range files {
		byPath[f.path] = f
		if f.kind == surfMake {
			makePaths[f.path] = true
		}
	}
	// Facts that hold for every entry.
	global := blocked
	pick := func(why string) {
		if global == "" {
			global = why
		}
	}
	for _, f := range files {
		if f.kind == surfDoc {
			continue
		}
		switch {
		case f.info == nil:
			pick("a file was not read in full: " + f.path)
			continue
		case f.info.over:
			pick("a file is too large to check in full: " + f.path)
		case f.info.dynMake:
			pick("make is run with a variable or % in " + f.path)
		}
		if f.kind != surfMake || f.info == nil {
			continue
		}
		if f.info.dynGoal {
			pick(".DEFAULT_GOAL holds a variable or % in " + f.path)
		}
		if f.info.recipePrefix {
			pick(".RECIPEPREFIX in " + f.path)
		}
		dir := path.Dir(f.path)
		for _, op := range f.info.includes {
			if !literalInclude(op, dir, makePaths) {
				pick(fmt.Sprintf("include of %q in %s is not a literal path of a Makefile that was read", clipWord(op), f.path))
			}
		}
	}
	applied := map[string]bool{}
	recs := make([]DevOnlyMakeRecord, len(entries))
	for i, en := range entries {
		recs[i] = DevOnlyMakeRecord{Makefile: en.Makefile, Target: en.Target}
		if why := staticDevWhy(en, byPath, blobs, global); why != "" {
			recs[i].WhyNot = why
			continue
		}
		applied[devKey(en.Makefile, en.Target)] = true
	}
	allApplied := func(file string, targets []string) bool {
		if len(targets) == 0 {
			return false
		}
		for _, t := range targets {
			if !applied[devKey(file, t)] {
				return false
			}
		}
		return true
	}
	// The greatest set of entries in which every entry holds.
	for changed := true; changed; {
		changed = false
		for i, en := range entries {
			k := devKey(en.Makefile, en.Target)
			if !applied[k] {
				continue
			}
			if why := devVoidedBy(en, files, allApplied); why != "" {
				delete(applied, k)
				recs[i].WhyNot = why
				changed = true
			}
		}
	}
	for i, en := range entries {
		recs[i].Applied = applied[devKey(en.Makefile, en.Target)]
		for _, f := range files {
			if f.kind == surfDoc && f.info != nil && len(f.info.find(en.Target)) > 0 && len(recs[i].Docs) < maxDevDocs {
				recs[i].Docs = append(recs[i].Docs, f.path)
			}
		}
	}
	return applied, recs
}

func clipWord(s string) string {
	if len(s) > 80 {
		return s[:80]
	}
	return s
}

// literalInclude reports an include operand that is a clean relative path
// of a Makefile that was read (from the repository root or from the
// directory of the including file).
func literalInclude(op, dir string, makePaths map[string]bool) bool {
	if op == "" || strings.ContainsAny(op, "$%*?[]{}()\\\"'`") || strings.HasPrefix(op, "/") || path.Clean(op) != op || op == ".." || strings.HasPrefix(op, "../") {
		return false
	}
	return makePaths[op] || makePaths[path.Join(dir, op)]
}

// staticDevWhy checks what does not depend on the other entries ("" when
// it holds).
func staticDevWhy(en DevOnlyMake, byPath map[string]devFile, blobs map[string]bool, global string) string {
	mf, ok := byPath[en.Makefile]
	if !ok || mf.kind != surfMake || mf.info == nil {
		return "the Makefile is missing at this release or is not read"
	}
	named := false
	for _, r := range mf.info.rules {
		named = named || containsWord(r.targets, en.Target)
	}
	if !named {
		return "no rule header of " + en.Makefile + " names the target"
	}
	if global != "" {
		return global
	}
	dir := path.Dir(en.Makefile)
	if b := path.Base(en.Makefile); b == "GNUmakefile" || b == "makefile" || b == "Makefile" {
		for _, other := range []string{"GNUmakefile", "makefile", "Makefile"} {
			if other != b && blobs[path.Join(dir, other)] {
				return "make may read " + path.Join(dir, other) + " instead of " + en.Makefile
			}
		}
	}
	if !mf.info.hasGoal {
		switch g := mf.info.goal; {
		case mf.info.includeBeforeGoal:
			return "an include precedes the first rule of " + en.Makefile + ": the default goal is not known"
		case g < 0:
			return "the default goal of " + en.Makefile + " is not known"
		case containsWord(mf.info.rules[g].targets, en.Target):
			return "the target is the default goal of " + en.Makefile
		default:
			for _, t := range mf.info.rules[g].targets {
				if dynamicWord(t) {
					return "the first rule of " + en.Makefile + " has a variable or % in its target"
				}
			}
		}
	}
	return ""
}

// devVoidedBy checks the target name and the prerequisites against the
// files, given which entries are applied now ("" when none voids it).
func devVoidedBy(en DevOnlyMake, files []devFile, allApplied func(string, []string) bool) string {
	for _, f := range files {
		if f.kind != surfMake {
			continue
		}
		for _, r := range f.info.rules {
			if r.dynPrereq && !allApplied(f.path, r.targets) {
				return fmt.Sprintf("a rule of %s in %s has a prerequisite with a variable or %%", strings.Join(r.targets, " "), f.path)
			}
		}
	}
	for _, f := range files {
		switch f.kind {
		case surfMake, surfShell, surfBuild:
		default:
			continue
		}
		for _, u := range f.info.find(en.Target) {
			if u.ctx >= 0 {
				tg := f.info.ctxs[u.ctx]
				if (f.path == en.Makefile && containsWord(tg, en.Target)) || (!u.recipe && dotRule(tg)) || allApplied(f.path, tg) {
					continue
				}
				if u.recipe {
					return fmt.Sprintf("invoked by %s in %s", strings.Join(tg, " "), f.path)
				}
				return fmt.Sprintf("prerequisite or target of %s in %s", strings.Join(tg, " "), f.path)
			}
			return "the name occurs in " + f.path
		}
	}
	return ""
}

// DevOnlyMakeRecord is the proof of one dev-only Makefile target entry at
// one commit.
type DevOnlyMakeRecord struct {
	Makefile string `json:"makefile"`
	Target   string `json:"target"`
	// Applied: the recipe lines of the target were not counted as an install
	// of an excluded path. WhyNot says why not when it is false.
	Applied bool   `json:"applied"`
	WhyNot  string `json:"whyNot,omitempty"`
	// Waived are the references of an excluded path the entry did not count
	// (the exclusion and the word of the recipe line).
	Waived []DevOnlyWaiver `json:"waived,omitempty"`
	// Docs are the documents that name the target (at most 20): they do not
	// void the entry.
	Docs []string `json:"docs,omitempty"`
}

// DevOnlyWaiver is one reference the guard did not count.
type DevOnlyWaiver struct {
	Exclusion string `json:"exclusion"`
	Token     string `json:"token"`
}

// devSkip returns the test of a Makefile job: the targets of a recipe line
// are all applied entries of that Makefile (nil when the file has none).
func devSkip(jobPath string, entries []DevOnlyMake, applied map[string]bool) func([]string) bool {
	has := false
	for _, en := range entries {
		has = has || (en.Makefile == jobPath && applied[devKey(en.Makefile, en.Target)])
	}
	if !has {
		return nil
	}
	return func(targets []string) bool {
		if len(targets) == 0 {
			return false
		}
		for _, t := range targets {
			if !applied[devKey(jobPath, t)] {
				return false
			}
		}
		return true
	}
}

// devWaivers lists, for an applied entry, the references of the live
// exclusions its recipe lines made and the guard did not count.
func devWaivers(en DevOnlyMake, lines []surfaceLine, live []Exclusion, skip func([]string) bool) []DevOnlyWaiver {
	var out []DevOnlyWaiver
	seen := map[DevOnlyWaiver]bool{}
	if skip == nil {
		return nil
	}
	for _, e := range live {
		makeRefs(e, lines, func(l surfaceLine, tok string) bool {
			w := DevOnlyWaiver{Exclusion: e.Path, Token: tok}
			if skip(l.Targets) && containsWord(l.Targets, en.Target) && !seen[w] {
				seen[w] = true
				out = append(out, w)
			}
			return false
		})
	}
	return out
}
