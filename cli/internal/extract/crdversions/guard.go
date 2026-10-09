// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// The install-surface guard. A reviewed exclusion (one that is not a
// declared, checked copy) says that the files under it are not installed.
// That is a claim about every release, and a reviewer read the code of one.
// At each tag the scan reads, the guard checks the part of the claim a
// program can check: nothing that installs refers to the excluded path.
// The surfaces it reads:
//
//   - kustomizations (resources, bases, components, patches, generators,
//     every path-like value), followed recursively from every kustomization
//     outside the excluded paths, through kustomizations inside them;
//   - Helm charts: Chart.yaml and requirements.yaml (local dependencies,
//     file:// repositories), followed the same way; and an excluded path
//     that lies under a chart (a directory with a Chart.yaml) is void;
//   - Makefiles: a recipe line of a target that is not a test target that
//     runs an install tool (kubectl, kustomize, helm, ...) on a path under
//     the excluded path, or through a variable that names it;
//   - documents (README, docs, quickstarts: .md .mdx .rst .adoc .txt): a
//     command line that runs an install tool on a path under the excluded
//     path;
//   - shell scripts (.sh, .bash): a command line that runs an install tool
//     on a path under the excluded path;
//   - container builds (Dockerfile, Containerfile, *.dockerfile, Earthfile):
//     a COPY or ADD source (Earthfile also SAVE ARTIFACT) under the excluded
//     path, read from the repository root and from the file's directory;
//   - nix files: a path word under the excluded path;
//   - ko: an excluded path under a kodata directory (ko packs it into the
//     image);
//   - Go packages in a directory above the excluded path or inside it: a
//     //go:embed pattern that matches a file under it.
//
// A reference voids the exclusion for that tag: the files under it are
// classified like the files of a default-excluded directory (location
// "void: <entry>"; Go sources are read too), and a finding of class
// exclusion-void names the referrer, so the tag (and every pair that
// contains it) is not attestable. The pair is not withheld because of them:
// a rule stays derived. Not followed, and recorded as such in
// every scan (NotRead): symbolic links (a link inside a chart, kustomization
// or kodata directory voids every entry), CI configuration, other scripts
// and build systems, a container build that copies its whole context
// ("COPY . ...") and selects files while it runs, and Go code that opens a
// path at run time.

// ClassVoided: a reviewed exclusion that does not hold at this tag.
const ClassVoided = "exclusion-void"

// Bounds of what one surface file may hold.
const (
	maxSurfaceTokens = 20000
	maxSurfaceLines  = 5000
	maxSurfaceLine   = 4000
	maxEmbeds        = 1000
)

// Surface kinds, by file name.
const (
	surfNone = iota
	// surfRefs: a kustomization, Chart.yaml or requirements.yaml.
	surfRefs
	surfMake
	surfDoc
	surfGo
	// surfShell: a shell script.
	surfShell
	// surfBuild: a Dockerfile, Containerfile or Earthfile.
	surfBuild
	// surfNix: a nix file.
	surfNix
)

var (
	makeNameRE = regexp.MustCompile(`(?i)^(makefile|gnumakefile)$|\.(mk|make)$`)
	docNameRE  = regexp.MustCompile(`(?i)\.(md|mdx|rst|adoc|asciidoc|txt)$`)
	// toolRE names the programs that apply, build or render manifests. The
	// command line of a project's own tool (cilium, velero, argocd,
	// crossplane) counts only with a verb after it: their names also occur
	// in prose and in URLs.
	toolRE = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_./-])(?:kubectl|kustomize|helm|kapp|skaffold|flux|istioctl|kumactl|kubeadm)(?:$|[^A-Za-z0-9_/-])|(?:^|[^A-Za-z0-9_./-])(?-i:oc)(?:$|[^A-Za-z0-9_/-])|(?:^|[^A-Za-z0-9_./-])(?:cilium|velero|argocd|crossplane)[ \t]+(?:install|upgrade|apply|create|generate|manifests?|app|appset|add|render|xpkg|beta|-f|--filename)(?:$|[^A-Za-z0-9_/-])|\$[({][A-Za-z_]*(?i:KUBECTL|KUSTOMIZE|HELM)[A-Za-z_]*[)}]`)
	// applyRE marks a command line that applies, renders or builds
	// manifests: a verb in lower case (commands are; prose starts its
	// sentences with a capital), or a flag that takes a manifest file or
	// directory.
	applyRE = regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])(?:apply|create|replace|install|upgrade|template|build|diff|delete|render)(?:$|[^A-Za-z0-9_-])|(?:^|\s)-[fk](?:$|[\s=])|--(?:filename|kustomize|values|chart-directory|path)(?:$|[\s=])`)
	// testTargetRE marks a Makefile target that runs tests: what it
	// applies is test infrastructure, not an install.
	testTargetRE = regexp.MustCompile(`(?i)(?:^|[-_./])(?:test|tests|e2e|lint|check|verify|conformance|integration|bench|benchmark|smoke|fuzz|coverage|unit)(?:$|[-_./])`)
	// installTargetRE marks a target that installs whatever else its name
	// says (verify-install, e2e-deploy): never a test target.
	installTargetRE = regexp.MustCompile(`(?i)(?:^|[-_./])(?:install|deploy|setup|apply|bootstrap|provision|release|up)(?:$|[-_./])`)
	shellNameRE     = regexp.MustCompile(`(?i)\.(sh|bash)$`)
	buildNameRE     = regexp.MustCompile(`(?i)^(?:dockerfile|containerfile)(?:[._-].*)?$|\.(?:dockerfile|containerfile)$|^earthfile$`)
	// buildCopyRE is a container build instruction that takes files from
	// the build context.
	buildCopyRE = regexp.MustCompile(`(?i)^(?:copy|add|save[ \t]+artifact)(?:$|[ \t])`)
	// buildFlagRE is an option of a COPY or ADD instruction.
	buildFlagRE  = regexp.MustCompile(`^--[a-z-]+(?:=\S*)?$`)
	makeRuleRE   = regexp.MustCompile(`^([^\s:=#][^:=#]*?)\s*::?(?:[^=]|$)`)
	makeAssignRE = regexp.MustCompile(`^\s*(?:export\s+|override\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*(?:[:?+!]|::)?=\s*(.*)$`)
	embedRE      = regexp.MustCompile(`(?m)^[ \t]*//go:embed[ \t]+(.+?)[ \t]*$`)
	// vendoredDocs are directories whose documents belong to other
	// projects.
	vendoredDocs = map[string]bool{"vendor": true, "third_party": true, "node_modules": true}
)

// isCommand reports a line that runs an install tool to apply, render or
// build manifests.
func isCommand(line string) bool { return toolRE.MatchString(line) && applyRE.MatchString(line) }

// surfaceKindOf decides what an install-surface file is, by its path.
func surfaceKindOf(p string) int {
	base := path.Base(p)
	switch {
	case isKustomizationName(base) || base == "Chart.yaml" || base == "requirements.yaml":
		return surfRefs
	case makeNameRE.MatchString(base):
		return surfMake
	case docNameRE.MatchString(base):
		return surfDoc
	case shellNameRE.MatchString(base):
		return surfShell
	case buildNameRE.MatchString(base):
		return surfBuild
	case strings.HasSuffix(base, ".nix"):
		return surfNix
	}
	return surfNone
}

// inVendored reports a path under a vendored directory.
func inVendored(p string) bool {
	dir := path.Dir(p)
	if dir == "." {
		return false
	}
	for _, seg := range strings.Split(dir, "/") {
		if vendoredDocs[seg] {
			return true
		}
	}
	return false
}

// surfaceLine is one line a Makefile or document keeps: a command that
// runs an install tool, or (Makefile) a variable assignment.
type surfaceLine struct {
	// Targets are the Makefile targets a recipe line belongs to.
	Targets []string
	// Assign is the variable an assignment line sets ("" for a command).
	Assign string
	Text   string
}

// surfaceInfo is what one install-surface file says. It depends only on
// the bytes and the kind of file.
type surfaceInfo struct {
	// tokens are the path-like words of a kustomization or chart file.
	tokens []string
	lines  []surfaceLine
	// embeds are the //go:embed patterns of a Go file.
	embeds []string
	// unread says why the file cannot be checked ("" when it was).
	unread string
}

func isSepRune(r rune) bool {
	return unicode.IsSpace(r) || strings.ContainsRune("\"'`,;|&<>()[]{}=:@$!", r)
}

// tokenize splits text into words on whitespace and punctuation.
func tokenize(text string) []string {
	return strings.FieldsFunc(text, isSepRune)
}

// refTokens are the words of a kustomization or chart file, comments
// removed, in order and without repeats. The file need not be decodable:
// a templated or malformed file is read as text.
func refTokens(data []byte) ([]string, string) {
	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "file://", " "), "\n") {
		if i := commentStart(line); i >= 0 {
			line = line[:i]
		}
		for _, tok := range tokenize(line) {
			// path.Join cleans a leading "//" (the rest of a URL) away.
			if tok == "" || tok == "-" || len(tok) > 512 || seen[tok] {
				continue
			}
			seen[tok] = true
			if out = append(out, tok); len(out) > maxSurfaceTokens {
				return nil, fmt.Sprintf("more than %d words", maxSurfaceTokens)
			}
		}
	}
	return out, ""
}

// commentStart is the index of a YAML or Makefile comment ("#" at the
// start or after white space), or -1.
func commentStart(line string) int {
	for i := 0; i < len(line); i++ {
		if line[i] == '#' && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
			return i
		}
	}
	return -1
}

// logicalLines joins lines that end in a backslash.
func logicalLines(data []byte) []string {
	var out []string
	var cur strings.Builder
	for _, raw := range strings.Split(string(data), "\n") {
		raw = strings.TrimRight(raw, "\r")
		if strings.HasSuffix(raw, "\\") {
			cur.WriteString(strings.TrimSuffix(raw, "\\"))
			cur.WriteByte(' ')
			continue
		}
		cur.WriteString(raw)
		out = append(out, cur.String())
		cur.Reset()
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func clip(s string) string {
	if len(s) > maxSurfaceLine {
		return s[:maxSurfaceLine]
	}
	return s
}

// makeLines reads a Makefile: the recipe and other lines that run an
// install tool (with the targets of the rule they follow) and the
// variable assignments whose value holds a path.
func makeLines(data []byte) ([]surfaceLine, string) {
	var out []surfaceLine
	var targets []string
	add := func(l surfaceLine) string {
		if out = append(out, l); len(out) > maxSurfaceLines {
			return fmt.Sprintf("more than %d command lines", maxSurfaceLines)
		}
		return ""
	}
	for _, line := range logicalLines(data) {
		switch {
		case strings.HasPrefix(line, "\t"):
			text := strings.TrimSpace(line)
			if isCommand(text) {
				if why := add(surfaceLine{Targets: targets, Text: clip(text)}); why != "" {
					return nil, why
				}
			}
		case strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#"):
		default:
			if m := makeAssignRE.FindStringSubmatch(line); m != nil {
				if strings.Contains(m[2], "/") {
					if why := add(surfaceLine{Assign: m[1], Text: clip(m[2])}); why != "" {
						return nil, why
					}
				}
				if isCommand(m[2]) {
					if why := add(surfaceLine{Text: clip(m[2])}); why != "" {
						return nil, why
					}
				}
				continue
			}
			if m := makeRuleRE.FindStringSubmatch(line); m != nil {
				targets = strings.Fields(m[1])
				if i := strings.Index(line, ";"); i >= 0 && isCommand(line[i:]) {
					if why := add(surfaceLine{Targets: targets, Text: clip(line[i+1:])}); why != "" {
						return nil, why
					}
				}
				continue
			}
			if isCommand(line) {
				if why := add(surfaceLine{Text: clip(strings.TrimSpace(line))}); why != "" {
					return nil, why
				}
			}
		}
	}
	return out, ""
}

// docLines reads a document: the lines that run an install tool.
func docLines(data []byte) ([]surfaceLine, string) {
	var out []surfaceLine
	for _, line := range logicalLines(data) {
		if isCommand(line) {
			if out = append(out, surfaceLine{Text: clip(strings.TrimSpace(line))}); len(out) > maxSurfaceLines {
				return nil, fmt.Sprintf("more than %d command lines", maxSurfaceLines)
			}
		}
	}
	return out, ""
}

// buildLines reads a container build file: the COPY and ADD (and
// Earthfile SAVE ARTIFACT) instructions, options and the destination
// removed. A source of "." (the whole context) is left out: what the build
// then selects is not followed (NotRead).
func buildLines(data []byte) ([]surfaceLine, string) {
	var out []surfaceLine
	for _, line := range logicalLines(data) {
		t := strings.TrimSpace(line)
		if !buildCopyRE.MatchString(t) {
			continue
		}
		words := strings.Fields(t)[1:]
		if strings.EqualFold(words[0], "artifact") {
			words = words[1:]
		}
		var srcs []string
		for _, w := range words {
			if buildFlagRE.MatchString(w) {
				continue
			}
			if strings.EqualFold(w, "AS") {
				break
			}
			srcs = append(srcs, w)
		}
		// COPY and ADD name a destination last; SAVE ARTIFACT names one
		// optionally, so every word is kept.
		if !strings.HasPrefix(strings.ToLower(t), "save") && len(srcs) > 1 {
			srcs = srcs[:len(srcs)-1]
		}
		var kept []string
		for _, w := range srcs {
			if c := strings.Trim(w, "\"[],"); c != "." && c != "./" && c != "" {
				kept = append(kept, c)
			}
		}
		if len(kept) == 0 {
			continue
		}
		if out = append(out, surfaceLine{Text: clip(strings.Join(kept, " "))}); len(out) > maxSurfaceLines {
			return nil, fmt.Sprintf("more than %d copy instructions", maxSurfaceLines)
		}
	}
	return out, ""
}

// nixLines reads a nix file: every line, comments removed, that holds a
// path word (a word with a slash).
func nixLines(data []byte) ([]surfaceLine, string) {
	var out []surfaceLine
	for _, line := range strings.Split(string(data), "\n") {
		if i := commentStart(line); i >= 0 {
			line = line[:i]
		}
		if !strings.Contains(line, "/") {
			continue
		}
		if out = append(out, surfaceLine{Text: clip(strings.TrimSpace(line))}); len(out) > maxSurfaceLines {
			return nil, fmt.Sprintf("more than %d lines with a path", maxSurfaceLines)
		}
	}
	return out, ""
}

// goEmbeds are the patterns of the //go:embed directives of a Go file.
func goEmbeds(data []byte) ([]string, string) {
	var out []string
	for _, m := range embedRE.FindAllSubmatch(data, -1) {
		for _, pat := range embedFields(string(m[1])) {
			pat = strings.TrimPrefix(pat, "all:")
			if pat == "" || strings.Contains(pat, "..") {
				continue
			}
			if out = append(out, pat); len(out) > maxEmbeds {
				return nil, fmt.Sprintf("more than %d embed patterns", maxEmbeds)
			}
		}
	}
	return out, ""
}

// embedFields splits the arguments of a //go:embed line: bare words and
// double-quoted or back-quoted strings.
func embedFields(s string) []string {
	var out []string
	for s = strings.TrimSpace(s); s != ""; s = strings.TrimSpace(s) {
		switch s[0] {
		case '"', '`':
			end := strings.IndexByte(s[1:], s[0])
			if end < 0 {
				return append(out, s[1:])
			}
			out = append(out, s[1:1+end])
			s = s[end+2:]
		default:
			end := strings.IndexAny(s, " \t")
			if end < 0 {
				return append(out, s)
			}
			out = append(out, s[:end])
			s = s[end:]
		}
	}
	return out
}

// summarizeSurface reads an install-surface file.
func summarizeSurface(kind int, data []byte) *surfaceInfo {
	info := &surfaceInfo{}
	switch kind {
	case surfRefs:
		info.tokens, info.unread = refTokens(data)
	case surfMake:
		info.lines, info.unread = makeLines(data)
	case surfDoc, surfShell:
		info.lines, info.unread = docLines(data)
	case surfBuild:
		info.lines, info.unread = buildLines(data)
	case surfNix:
		info.lines, info.unread = nixLines(data)
	case surfGo:
		info.embeds, info.unread = goEmbeds(data)
	}
	return info
}

// surface reads one install-surface file (or reuses an earlier read of the
// same blob id).
func (x *Extractor) surface(r extract.PinnedReader, repo extract.RepoRef, commit string, kind int, e extract.TreeEntry) (*surfaceInfo, error) {
	key := fmt.Sprintf("%d:%s", kind, e.SHA)
	x.mu.Lock()
	info, ok := x.surfaces[key]
	x.mu.Unlock()
	if ok && e.SHA != "" {
		if _, reused := extract.Reuse(r, repo, commit, e.Path, e.SHA); reused {
			return info, nil
		}
	}
	data, err := r.Read(repo, commit, e.Path)
	if err != nil {
		return nil, fmt.Errorf("guard reading %s at %s: %w", e.Path, commit, err)
	}
	info = summarizeSurface(kind, data)
	if e.SHA != "" {
		x.mu.Lock()
		if prev, ok := x.surfaces[key]; ok {
			info = prev
		} else {
			x.surfaces[key] = info
		}
		x.mu.Unlock()
	}
	return info, nil
}

// hitsPath reports whether the repository path r (a file or a directory,
// without a trailing slash) lies under an exclusion entry.
func hitsPath(e Exclusion, r string) bool {
	switch {
	case r == "" || r == ".":
		return false
	case strings.HasSuffix(e.Path, "/"):
		return strings.HasPrefix(r+"/", e.Path)
	case strings.ContainsAny(e.Path, globMeta):
		ok, _ := path.Match(e.Path, r)
		return ok
	default:
		return r == e.Path
	}
}

// mention returns the first word of text that names a path under the
// exclusion. A word is read as a path from its start and from after each
// slash (a URL, a variable prefix and a relative path all end in the
// repository path), with a leading "./", a query and trailing punctuation
// removed.
func mention(e Exclusion, text string) (string, bool) {
	dir := strings.HasSuffix(e.Path, "/")
	for _, tok := range tokenize(text) {
		word := tok
		if i := strings.IndexAny(word, "?#"); i >= 0 {
			word = word[:i]
		}
		// A bare word is prose: only a directory named with a slash, or a
		// path under it, is a reference to a directory entry.
		if dir && !strings.Contains(word, "/") {
			continue
		}
		starts := []int{0}
		for i := 0; i < len(word); i++ {
			if word[i] == '/' {
				starts = append(starts, i+1)
			}
		}
		for _, s := range starts {
			// A leading "./" or "/" starts its own candidate (after the
			// slash), so neither is removed here.
			cand := strings.TrimRight(word[s:], "./,")
			if hitsPath(e, cand) {
				return tok, true
			}
		}
	}
	return "", false
}

// copyMention finds the first word of a container build or nix line that
// names a path under the exclusion, or a directory above it (copying a
// directory copies what lies under it; the repository root is left out, see
// buildLines). A word is read from the repository root (and from after each
// slash, as mention does: conservative, a URL or a path relative to another
// directory may name it too) and joined to dir, the directory of the file;
// bare words (without a slash) are joined to dir only when bare is set.
func copyMention(e Exclusion, dir string, bare bool, text string) (string, bool) {
	if tok, ok := mention(e, text); ok {
		return tok, true
	}
	above := func(cand string) bool {
		return strings.HasSuffix(e.Path, "/") && cand != "" && cand != "." && strings.HasPrefix(e.Path, cand+"/")
	}
	for _, tok := range tokenize(text) {
		word := tok
		if i := strings.IndexAny(word, "?#"); i >= 0 {
			word = word[:i]
		}
		word = strings.TrimRight(word, ",")
		if strings.Contains(word, "://") {
			continue
		}
		var cands []string
		if strings.Contains(word, "/") {
			for i := 0; i < len(word); i++ {
				if i == 0 || word[i-1] == '/' {
					if c := path.Clean(word[i:]); !strings.HasPrefix(c, "/") && !strings.HasPrefix(c, "../") {
						cands = append(cands, c)
					}
				}
			}
		}
		if !strings.HasPrefix(word, "/") && (bare || strings.Contains(word, "/")) {
			if c := path.Join(dir, word); !strings.HasPrefix(c, "../") {
				cands = append(cands, c)
			}
		}
		for _, c := range cands {
			if c != "." && (hitsPath(e, c) || above(c)) {
				return tok, true
			}
		}
	}
	return "", false
}

// testOnlyTargets reports a recipe whose every target is a test target: a
// test word in its name and no install word (verify-install installs).
func testOnlyTargets(targets []string) bool {
	if len(targets) == 0 {
		return false
	}
	for _, t := range targets {
		if !testTargetRE.MatchString(t) || installTargetRE.MatchString(t) {
			return false
		}
	}
	return true
}

// makeHit finds the first command line of a Makefile that applies a path
// under the exclusion, directly or through a variable.
func makeHit(e Exclusion, lines []surfaceLine) (string, bool) {
	var vars []string
	for _, l := range lines {
		if l.Assign != "" {
			if _, ok := mention(e, l.Text); ok {
				vars = append(vars, l.Assign)
			}
		}
	}
	for _, l := range lines {
		if l.Assign != "" || testOnlyTargets(l.Targets) {
			continue
		}
		if tok, ok := mention(e, l.Text); ok {
			return tok, true
		}
		for _, v := range vars {
			for _, ref := range []string{"$(" + v + ")", "${" + v + "}"} {
				if strings.Contains(l.Text, ref) {
					return ref, true
				}
			}
		}
	}
	return "", false
}

// docHit finds the first command line of a document that runs an install
// tool on a path under the exclusion.
func docHit(e Exclusion, lines []surfaceLine) (string, bool) {
	for _, l := range lines {
		if tok, ok := mention(e, l.Text); ok {
			return tok, true
		}
	}
	return "", false
}

// linesHit finds the first line of a container build or nix file that
// names a path under the exclusion or a directory above it.
func linesHit(e Exclusion, dir string, bare bool, lines []surfaceLine) (string, bool) {
	for _, l := range lines {
		if tok, ok := copyMention(e, dir, bare, l.Text); ok {
			return tok, true
		}
	}
	return "", false
}

// kodataDir returns the kodata directory a path lies in or is ("" when
// none).
func kodataDir(p string) string {
	segs := strings.Split(p, "/")
	for i, seg := range segs {
		if seg == "kodata" {
			return strings.Join(segs[:i+1], "/")
		}
	}
	return ""
}

// embedMatches reports whether a //go:embed pattern, resolved to the
// repository, embeds the file f: it matches the file or a directory above
// it that lies below the package directory.
func embedMatches(pattern, pkgDir, f string) bool {
	if ok, _ := path.Match(pattern, f); ok {
		return true
	}
	for d := path.Dir(f); d != "." && len(d) > len(pkgDir); d = path.Dir(d) {
		if ok, _ := path.Match(pattern, d); ok {
			return true
		}
	}
	return false
}

// candidateName reports a file name the scan would read if it were not
// excluded: data, template sources, Go sources that name crd, packaged
// charts.
func candidateName(p string) bool {
	name := path.Base(p)
	switch {
	case dataNameRE.MatchString(name) || name == "Kustomization" || sourceNameRE.MatchString(name):
		return true
	case strings.HasSuffix(name, ".go"):
		return !strings.HasSuffix(name, "_test.go") && crdPathRE.MatchString(p)
	case strings.HasSuffix(strings.ToLower(name), ".tgz"):
		return path.Base(path.Dir(p)) == "charts"
	}
	return false
}

// hit is one reference found by the guard.
type hit struct {
	kind, by, ref string
}

func (h hit) detail(e Exclusion) string {
	if h.ref == "" {
		return fmt.Sprintf("%s: the reviewed exclusion %s does not hold at this release", h.kind, e.Path)
	}
	return fmt.Sprintf("%s refers to %s: the reviewed exclusion %s does not hold at this release", h.kind, h.ref, e.Path)
}

func refKind(p string) string {
	if b := path.Base(p); b == "Chart.yaml" || b == "requirements.yaml" {
		return "Helm chart"
	}
	return "kustomization"
}

// guard checks the reviewed exclusions that are not declared copies
// against the install surfaces of one tag. It returns a finding for each
// exclusion that has files at the tag and is referenced, and the set of
// those exclusions (by entry path). blobs are all the files of the tree,
// commits its submodules.
func (x *Extractor) guard(ctx context.Context, r extract.PinnedReader, repo extract.RepoRef, commit string, blobs []extract.TreeEntry, commits []string) ([]Finding, map[string]bool, error) {
	var excl []Exclusion
	for _, e := range x.target.Exclude {
		if !e.Copies {
			excl = append(excl, e)
		}
	}
	if len(excl) == 0 {
		return nil, nil, nil
	}
	blobs = append([]extract.TreeEntry(nil), blobs...)
	sort.Slice(blobs, func(i, j int) bool { return blobs[i].Path < blobs[j].Path })
	// The entries that have files at this tag.
	present := map[string]bool{}
	for _, b := range blobs {
		for _, e := range excl {
			if !present[e.Path] && exclusionMatches(e.Path, b.Path) && candidateName(b.Path) {
				present[e.Path] = true
			}
		}
	}
	for _, c := range commits {
		for _, e := range excl {
			if exclusionMatches(e.Path, c) {
				present[e.Path] = true
			}
		}
	}
	if len(present) == 0 {
		return nil, nil, nil
	}
	var live []Exclusion
	for _, e := range excl {
		if present[e.Path] {
			live = append(live, e)
		}
	}
	inExcluded := func(p string) bool {
		for _, e := range excl {
			if exclusionMatches(e.Path, p) {
				return true
			}
		}
		return false
	}
	found := map[string]hit{}
	record := func(e Exclusion, h hit) {
		if _, done := found[e.Path]; !done {
			found[e.Path] = h
		}
	}

	// Under a chart.
	var charts []string
	for _, b := range blobs {
		if path.Base(b.Path) == "Chart.yaml" {
			d := path.Dir(b.Path)
			if d == "." {
				d = ""
			}
			charts = append(charts, d)
		}
	}
	for _, e := range live {
		base := strings.TrimSuffix(e.Path, "/")
		for _, c := range charts {
			if c == "" || base == c || strings.HasPrefix(base, c+"/") {
				record(e, hit{kind: "the excluded path lies under a Helm chart", by: path.Join(c, "Chart.yaml")})
				break
			}
		}
		// ko packs every file under a kodata directory into the image.
		if d := kodataDir(base); d != "" {
			record(e, hit{kind: "the excluded path lies under a ko kodata directory", by: d})
		}
	}

	// What to read.
	type job struct {
		e    extract.TreeEntry
		kind int
	}
	var jobs []job
	for _, b := range blobs {
		if b.Mode == "120000" {
			continue
		}
		switch k := surfaceKindOf(b.Path); k {
		case surfRefs:
			jobs = append(jobs, job{b, k})
		case surfMake, surfDoc, surfShell, surfBuild, surfNix:
			if !inExcluded(b.Path) && !inVendored(b.Path) {
				jobs = append(jobs, job{b, k})
			}
		}
	}
	// Go packages above an excluded path, and inside it.
	goDirs := map[string]bool{}
	for _, e := range live {
		d := path.Dir(strings.TrimSuffix(e.Path, "/"))
		for {
			if d == "." {
				d = ""
			}
			goDirs[d] = true
			if d == "" {
				break
			}
			d = path.Dir(d)
		}
	}
	for _, b := range blobs {
		if b.Mode == "120000" || !strings.HasSuffix(b.Path, ".go") || strings.HasSuffix(b.Path, "_test.go") {
			continue
		}
		d := path.Dir(b.Path)
		if d == "." {
			d = ""
		}
		inside := false
		for _, e := range live {
			inside = inside || exclusionMatches(e.Path, b.Path)
		}
		if goDirs[d] || inside {
			jobs = append(jobs, job{b, surfGo})
		}
	}
	infos := make([]*surfaceInfo, len(jobs))
	errs := make([]error, len(jobs))
	x.parallel(len(jobs), func(i int) {
		infos[i], errs[i] = x.surface(r, repo, commit, jobs[i].kind, jobs[i].e)
	})
	for i := range jobs {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if errs[i] != nil {
			return nil, nil, errs[i]
		}
	}
	// A surface that cannot be checked voids every live entry: an
	// unreadable file, and a symbolic link inside a chart or kustomization
	// directory (it may lead anywhere; links are not followed).
	var unverified *hit
	for i, j := range jobs {
		if infos[i].unread != "" {
			unverified = &hit{kind: "an install surface that cannot be checked (" + infos[i].unread + ")", by: j.e.Path}
			break
		}
	}
	if unverified == nil {
		refDirs := map[string]bool{}
		for _, b := range blobs {
			if surfaceKindOf(b.Path) == surfRefs {
				d := path.Dir(b.Path)
				if d == "." {
					d = ""
				}
				refDirs[d] = true
			}
		}
	links:
		for _, b := range blobs {
			if b.Mode != "120000" || inExcluded(b.Path) || inVendored(b.Path) {
				continue
			}
			for d := path.Dir(b.Path); ; d = path.Dir(d) {
				if d == "." {
					d = ""
				}
				if refDirs[d] {
					unverified = &hit{kind: "a symbolic link inside a chart or kustomization directory is not followed", by: b.Path}
					break links
				}
				if path.Base(d) == "kodata" {
					unverified = &hit{kind: "a symbolic link inside a ko kodata directory is not followed", by: b.Path}
					break links
				}
				if d == "" {
					break
				}
			}
		}
	}
	if unverified != nil {
		for _, e := range live {
			record(e, *unverified)
		}
	}

	// Kustomizations and charts, followed from every one outside the
	// excluded paths.
	refInfo := map[string]*surfaceInfo{}
	var refPaths []string
	for i, j := range jobs {
		if j.kind == surfRefs {
			refInfo[j.e.Path] = infos[i]
			refPaths = append(refPaths, j.e.Path)
		}
	}
	sort.Strings(refPaths)
	var queue []string
	seen := map[string]bool{}
	for _, p := range refPaths {
		if !inExcluded(p) {
			queue = append(queue, p)
			seen[p] = true
		}
	}
	refNames := []string{"kustomization.yaml", "kustomization.yml", "Kustomization", "Chart.yaml", "requirements.yaml"}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		dir := path.Dir(p)
		if dir == "." {
			dir = ""
		}
		for _, tok := range refInfo[p].tokens {
			ref := path.Join(dir, tok)
			if ref == "." || ref == ".." || strings.HasPrefix(ref, "../") {
				continue
			}
			for _, e := range live {
				if hitsPath(e, ref) {
					record(e, hit{kind: refKind(p), by: p, ref: ref})
				}
			}
			var next []string
			if _, ok := refInfo[ref]; ok {
				next = append(next, ref)
			}
			for _, n := range refNames {
				if _, ok := refInfo[path.Join(ref, n)]; ok {
					next = append(next, path.Join(ref, n))
				}
			}
			for _, n := range next {
				if !seen[n] {
					seen[n] = true
					queue = append(queue, n)
				}
			}
		}
	}

	// Makefiles, documents, shell scripts, container builds and nix files.
	for i, j := range jobs {
		switch j.kind {
		case surfMake, surfDoc, surfShell, surfBuild, surfNix:
		default:
			continue
		}
		dir := path.Dir(j.e.Path)
		if dir == "." {
			dir = ""
		}
		for _, e := range live {
			if _, done := found[e.Path]; done {
				continue
			}
			var tok string
			var ok bool
			kind := "document"
			switch j.kind {
			case surfMake:
				kind = "Makefile"
				tok, ok = makeHit(e, infos[i].lines)
			case surfDoc:
				tok, ok = docHit(e, infos[i].lines)
			case surfShell:
				kind = "shell script"
				tok, ok = docHit(e, infos[i].lines)
			case surfBuild:
				kind = "container build"
				tok, ok = linesHit(e, dir, true, infos[i].lines)
			case surfNix:
				kind = "nix file"
				tok, ok = linesHit(e, dir, false, infos[i].lines)
			}
			if ok {
				record(e, hit{kind: kind, by: j.e.Path, ref: tok})
			}
		}
	}

	// Go packages that embed files.
	under := map[string][]string{}
	for _, e := range live {
		if _, done := found[e.Path]; done {
			continue
		}
		for _, b := range blobs {
			if exclusionMatches(e.Path, b.Path) {
				under[e.Path] = append(under[e.Path], b.Path)
			}
		}
	}
	for i, j := range jobs {
		if j.kind != surfGo {
			continue
		}
		pkg := path.Dir(j.e.Path)
		if pkg == "." {
			pkg = ""
		}
		for _, e := range live {
			if _, done := found[e.Path]; done {
				continue
			}
			for _, pat := range infos[i].embeds {
				rp := path.Join(pkg, pat)
				matched := false
				for _, f := range under[e.Path] {
					if embedMatches(rp, pkg, f) {
						matched = true
						break
					}
				}
				if matched {
					record(e, hit{kind: "Go package", by: j.e.Path, ref: "//go:embed " + pat})
					break
				}
			}
		}
	}

	var findings []Finding
	voided := map[string]bool{}
	for _, e := range live {
		h, ok := found[e.Path]
		if !ok {
			continue
		}
		voided[e.Path] = true
		findings = append(findings, Finding{Path: h.by, Class: ClassVoided, Location: e.Path, Detail: h.detail(e)})
	}
	return findings, voided, nil
}

// voidPrefix starts the location of a file under a void reviewed exclusion.
const voidPrefix = "void: "

// withVoided returns a copy of the target in which the named exclusion
// entries do not hold.
func (t Target) withVoided(entries map[string]bool) Target {
	t.voided = entries
	return t
}
