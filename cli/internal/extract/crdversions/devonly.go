// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode"
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

// maxDevAssigns bounds the variable assignments kept for one Makefile.
const maxDevAssigns = 20000

// Bounds of the expansion of one prerequisite word.
const (
	maxExpandDepth = 8
	maxExpansions  = 256
	maxCandidates  = 256
)

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
	// dyn are the prerequisite words that hold "$", "%" or "=" (a variable
	// reference, a pattern, a target-specific assignment); "%" alone when the
	// header could not be split.
	dyn []string
}

// devAssign is one assignment of a variable in a Makefile (bad: a value
// that cannot be read as words, such as a define or a shell assignment).
type devAssign struct {
	name, value string
	bad         bool
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
	// goalTarget is the first target of the first rule that can be the
	// default goal (a name that does not start with "." unless it holds a
	// "/"); goalSeen says there is one.
	goalTarget string
	goalSeen   bool
	// goalUnknown: a rule that could be the default goal lies in a
	// conditional or a define before one that is unconditional.
	goalUnknown bool
	// goalValue is the value of the .DEFAULT_GOAL assignment when hasGoal.
	goalValue string
	// assigns are the variable assignments, in file order.
	assigns []devAssign
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
	makeCondRE    = regexp.MustCompile(`^ *(?:ifeq|ifneq|ifdef|ifndef)(?:[ \t(]|$)`)
	makeEndifRE   = regexp.MustCompile(`^ *endif(?:[ \t]|$)`)
	makeEndefRE   = regexp.MustCompile(`^ *endef(?:[ \t]|$)`)
	makeDefineRE  = regexp.MustCompile(`^ *(?:(?:export|override|private|unexport)[ \t]+)*(?:define|endef)(?:[ \t]|$)`)
	// makeAppendGoalRE is an append to .DEFAULT_GOAL.
	makeAppendGoalRE = regexp.MustCompile(`^\s*(?:(?:export|override|private|unexport)[ \t]+)*\.DEFAULT_GOAL\s*\+=`)
	// makeDefineNameRE reads the name of a define.
	makeDefineNameRE = regexp.MustCompile(`^ *(?:(?:export|override|private|unexport)[ \t]+)*define[ \t]+([^ \t]+)`)
	// makeShellAssignRE is an assignment whose value is a shell command.
	makeShellAssignRE = regexp.MustCompile(`^\s*(?:(?:export|override|private|unexport)[ \t]+)*(?:\.DEFAULT_GOAL|[A-Za-z_][A-Za-z0-9_.-]*)\s*!=`)
)

// dynamicWord reports a word that may expand to a name: it holds a variable
// or automatic variable reference ("$") or a pattern ("%").
func dynamicWord(w string) bool { return strings.ContainsAny(w, "$%") }

// makefileFlag reports a word that selects the makefile make reads (-f, a
// cluster of short flags ending in f, --file, --makefile): the rules it
// holds are not those of the files that were read.
func makefileFlag(w string) bool {
	if strings.HasPrefix(w, "--file") || strings.HasPrefix(w, "--makefile") {
		return true
	}
	if !strings.HasPrefix(w, "-") || strings.HasPrefix(w, "--") {
		return false
	}
	for _, r := range w[1:] {
		if r == 'f' {
			return true
		}
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return false
}

// dynamicMake reports a line that runs make (make, gmake, $(MAKE), ${MAKE})
// with a word after it that holds "$" or "%", or that selects the makefile
// (-f, --file, --makefile). The words after the command
// are not cut at a pipe or a separator: more is read, never less.
func dynamicMake(line string) bool {
	for _, loc := range makeInvokeRE.FindAllStringIndex(line, -1) {
		for _, w := range strings.Fields(line[loc[1]:]) {
			if dynamicWord(w) || makefileFlag(w) {
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
	return &devBuilder{info: &devInfo{}, seen: map[devUse]bool{}, ctxOf: map[string]int{}}
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
		}
	}
}

// goal reads a line that holds .DEFAULT_GOAL: only a variable assignment
// ("=", ":=", "?=") of a non-empty literal value sets a default goal that is
// known, and a second assignment must give the same value; any other line
// that holds the word (a recipe, "+=", "!=", a define, an empty or computed
// value) leaves it open. The rule form (".DEFAULT_GOAL: x") is an ordinary
// rule and is not read here.
func (b *devBuilder) goal(line string, literalAssign bool, value string, nested bool) {
	if b == nil {
		return
	}
	for _, w := range tokenize(line) {
		if w != ".DEFAULT_GOAL" {
			continue
		}
		if literalAssign && !nested {
			if b.info.hasGoal && b.info.goalValue != value {
				b.info.dynGoal = true
			}
			b.info.hasGoal, b.info.goalValue = true, value
		} else {
			b.info.dynGoal = true
		}
		return
	}
}

// assign records a variable assignment.
func (b *devBuilder) assign(name, value string, bad bool) {
	if b == nil {
		return
	}
	if b.info.assigns = append(b.info.assigns, devAssign{name: name, value: value, bad: bad}); len(b.info.assigns) > maxDevAssigns {
		b.info.over = true
	}
}

func (b *devBuilder) include(operands []string) {
	if b == nil {
		return
	}
	if !b.info.goalSeen {
		b.info.includeBeforeGoal = true
	}
	if b.info.includes = append(b.info.includes, operands...); len(b.info.includes) > maxSurfaceLines {
		b.info.over = true
	}
}

// rule records a rule header line: the targets, the header text (before a
// ";") and the recipe text after it.
func (b *devBuilder) rule(targets []string, line string, nested bool) {
	if b == nil {
		return
	}
	head, recipe := line, ""
	if i := strings.Index(line, ";"); i >= 0 {
		head, recipe = line[:i], line[i+1:]
	}
	var dyn []string
	if c := strings.Index(head, ":"); c >= 0 {
		pre := head[c+1:]
		if i := commentStart(pre); i >= 0 {
			pre = pre[:i]
		}
		for _, w := range strings.Fields(pre) {
			if dynamicWord(w) || strings.Contains(w, "=") {
				dyn = append(dyn, w)
			}
		}
	} else {
		dyn = []string{"%"}
	}
	b.info.rules = append(b.info.rules, devRule{targets: append([]string(nil), targets...), dyn: dyn})
	if len(b.info.rules) > maxSurfaceLines {
		b.info.over = true
	}
	if !b.info.goalSeen {
		for _, t := range targets {
			if !strings.HasPrefix(t, ".") || strings.Contains(t, "/") {
				if nested {
					b.info.goalUnknown = true
				} else {
					b.info.goalTarget, b.info.goalSeen = t, true
				}
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
	// extra: a file under an excluded or vendored path, read for this check
	// only.
	extra bool
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

// specialTargets are the GNU make special targets whose prerequisites are
// never built as goals. Any other name that starts with "." is a normal rule.
var specialTargets = map[string]bool{
	".PHONY": true, ".SUFFIXES": true, ".PRECIOUS": true, ".INTERMEDIATE": true, ".NOTINTERMEDIATE": true,
	".SECONDARY": true, ".SECONDEXPANSION": true, ".DELETE_ON_ERROR": true, ".IGNORE": true,
	".LOW_RESOLUTION_TIME": true, ".SILENT": true, ".EXPORT_ALL_VARIABLES": true, ".NOTPARALLEL": true,
	".ONESHELL": true, ".POSIX": true,
}

// dotRule reports the targets of a special rule: every one is a special
// target.
func dotRule(targets []string) bool {
	if len(targets) == 0 {
		return false
	}
	for _, t := range targets {
		if !specialTargets[t] {
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
			pick("make is run with a variable, % or a makefile option in " + f.path)
		}
		if f.kind != surfMake || f.info == nil {
			continue
		}
		if f.info.dynGoal {
			pick(".DEFAULT_GOAL is not set by one literal assignment in " + f.path)
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
	vars := newDevVars(files)
	applied := map[string]bool{}
	recs := make([]DevOnlyMakeRecord, len(entries))
	for i, en := range entries {
		recs[i] = DevOnlyMakeRecord{Makefile: en.Makefile, Target: en.Target}
		if why := staticDevWhy(en, byPath, blobs, vars, global); why != "" {
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
			if why := devVoidedBy(en, files, vars, allApplied); why != "" {
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
func staticDevWhy(en DevOnlyMake, byPath map[string]devFile, blobs map[string]bool, vars *devVars, global string) string {
	mf, ok := byPath[en.Makefile]
	if !ok || mf.kind != surfMake || mf.info == nil {
		return "the Makefile is missing at this release or is not read"
	}
	if mf.extra {
		return "the Makefile lies under an excluded or vendored path"
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
		switch g := mf.info.goalTarget; {
		case mf.info.includeBeforeGoal:
			return "an include precedes the first rule of " + en.Makefile + ": the default goal is not known"
		case mf.info.goalUnknown || !mf.info.goalSeen:
			return "the default goal of " + en.Makefile + " is not known"
		case g == en.Target:
			return "the target is the default goal of " + en.Makefile
		case strings.Contains(g, "%"):
			return "the first rule of " + en.Makefile + " has a pattern target"
		case strings.Contains(g, "$") && vars.mayBeEmpty(g):
			return "the first rule of " + en.Makefile + " may have no target: the default goal is not known"
		case strings.Contains(g, "$") && vars.cannotName(g, en.Target):
			return "the default goal of " + en.Makefile + " may be the target"
		}
	}
	return ""
}

// devVoidedBy checks the target name and the prerequisites against the
// files, given which entries are applied now ("" when none voids it).
func devVoidedBy(en DevOnlyMake, files []devFile, vars *devVars, allApplied func(string, []string) bool) string {
	for _, f := range files {
		if f.kind != surfMake {
			continue
		}
		for _, r := range f.info.rules {
			if allApplied(f.path, r.targets) {
				continue
			}
			for _, w := range r.dyn {
				if !vars.cannotName(w, en.Target) {
					continue
				}
				return fmt.Sprintf("a rule of %s in %s has a prerequisite that may name the target: %s", strings.Join(r.targets, " "), f.path, clipWord(w))
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

// wildcard stands for an unknown value in an expansion: any string without
// white space.
const wildcard = "\x00"

// devVars are the assignments of every variable in the Makefiles of a tag.
type devVars struct {
	vals map[string][]string
	bad  map[string]bool
}

func newDevVars(files []devFile) *devVars {
	v := &devVars{vals: map[string][]string{}, bad: map[string]bool{}}
	for _, f := range files {
		if f.kind != surfMake || f.info == nil {
			continue
		}
		for _, a := range f.info.assigns {
			if a.bad {
				v.bad[a.name] = true
			}
			v.vals[a.name] = append(v.vals[a.name], a.value)
		}
	}
	return v
}

var plainNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)

// refAt reads the variable reference that starts at s[i] == '$': $(NAME),
// ${NAME} or $X with a plain name. A function call, a substitution
// reference, an automatic variable and "$$" are not read.
func refAt(s string, i int) (name string, end int, ok bool) {
	if i+1 >= len(s) {
		return "", 0, false
	}
	c := s[i+1]
	switch {
	case c == '(' || c == '{':
		closer := byte(')')
		if c == '{' {
			closer = '}'
		}
		j := strings.IndexByte(s[i+2:], closer)
		if j < 0 || !plainNameRE.MatchString(s[i+2:i+2+j]) {
			return "", 0, false
		}
		return s[i+2 : i+2+j], i + 2 + j + 1, true
	case c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
		return string(c), i + 2, true
	}
	return "", 0, false
}

// expander expands the variable references of one word into the strings it
// may become. It over-approximates: every assignment of a variable counts,
// a variable assigned in no Makefile is the wildcard, and what it cannot
// read (a function call, an automatic variable, "$$", a cycle, a bound) sets
// fail.
type expander struct {
	v     *devVars
	n     int
	stack []string
	fail  bool
}

func (e *expander) expand(s string, depth int) []string {
	i := strings.IndexByte(s, '$')
	if i < 0 {
		return []string{s}
	}
	if e.fail {
		return nil
	}
	name, end, ok := refAt(s, i)
	if !ok || depth >= maxExpandDepth || e.v.bad[name] || containsWord(e.stack, name) {
		e.fail = true
		return nil
	}
	if e.n++; e.n > maxExpansions {
		e.fail = true
		return nil
	}
	prefix := s[:i]
	sufs := e.expand(s[end:], depth)
	if e.fail {
		return nil
	}
	vals, assigned := e.v.vals[name]
	if !assigned {
		vals = []string{wildcard}
	}
	seen := map[string]bool{}
	var out []string
	add := func(c string) {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	e.stack = append(e.stack, name)
	defer func() { e.stack = e.stack[:len(e.stack)-1] }()
	for _, val := range vals {
		fields := strings.Fields(val)
		if len(fields) == 0 {
			for _, suf := range sufs {
				add(prefix + suf)
			}
			continue
		}
		for k, fw := range fields {
			cands := e.expand(fw, depth+1)
			if e.fail {
				return nil
			}
			for _, c := range cands {
				switch {
				case len(fields) == 1:
					for _, suf := range sufs {
						add(prefix + c + suf)
					}
				case k == 0:
					add(prefix + c)
				case k == len(fields)-1:
					for _, suf := range sufs {
						add(c + suf)
					}
				default:
					add(c)
				}
			}
			if len(out) > maxCandidates {
				e.fail = true
				return nil
			}
		}
	}
	return out
}

// wildMatch reports whether s matches a pattern in which the wildcard
// stands for any string.
func wildMatch(pat, s string) bool {
	parts := strings.Split(pat, wildcard)
	if len(parts) == 1 {
		return pat == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, mid := range parts[1 : len(parts)-1] {
		j := strings.Index(s, mid)
		if j < 0 {
			return false
		}
		s = s[j+len(mid):]
	}
	return strings.HasSuffix(s, last)
}

// cannotName reports a prerequisite word that may expand to the target
// name, or that cannot be read (so it may): a "%", a "=", a word the
// expansion does not read, or any expansion that matches the name.
func (v *devVars) cannotName(word, target string) bool {
	if strings.ContainsAny(word, "%=") {
		return true
	}
	e := &expander{v: v}
	for _, c := range e.expand(word, 0) {
		if wildMatch(c, target) {
			return true
		}
	}
	return e.fail
}

// mayBeEmpty reports a word that may expand to nothing, or that cannot be
// read: a rule whose target it is may have no target at all.
func (v *devVars) mayBeEmpty(word string) bool {
	e := &expander{v: v}
	for _, c := range e.expand(word, 0) {
		if strings.Trim(c, wildcard) == "" {
			return true
		}
	}
	return e.fail
}
