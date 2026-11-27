// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // Git object identity, not a security signature.
	"encoding/hex"
	"fmt"
	"path"
	"regexp"
	"strings"
	"text/template/parse"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

const staticHelperProfile = "static-helper-empty-v1"

var staticDefineRE = regexp.MustCompile(`\{\{-?\s*define\s+"([^"\\]+)"\s*-?\}\}`)

// staticHelperFile proves absence of output, without evaluating any action.
// Every definition, including unused definitions, must satisfy the profile.
func staticHelperFile(data []byte) bool {
	_, ok := staticHelperDefinitions(data)
	return ok
}

func staticHelperDefinitions(data []byte) (map[string]bool, bool) {
	if len(data) == 0 || len(data) > 16<<10 || bytes.Contains(data, []byte("<no value>")) || bytes.Count(data, []byte("{{")) > 2048 {
		return nil, false
	}
	defs := map[string]bool{}
	for _, m := range staticDefineRE.FindAllSubmatch(data, -1) {
		name := string(m[1])
		if name == "root" || defs[name] {
			return nil, false
		}
		defs[name] = true
	}
	t := parse.New("root")
	t.Mode = parse.SkipFuncCheck
	trees := map[string]*parse.Tree{}
	if _, err := t.Parse(string(data), "", "", trees); err != nil || len(trees) != len(defs)+1 {
		return nil, false
	}
	budget := 2048
	for name, tree := range trees {
		if name != "root" && !defs[name] {
			return nil, false
		}
		if !staticHelperList(tree.Root, name == "root", 0, &budget) {
			return nil, false
		}
	}
	return defs, true
}

func staticHelperList(list *parse.ListNode, root bool, depth int, budget *int) bool {
	if list == nil {
		return true
	}
	*budget--
	if depth > 16 || *budget < 0 {
		return false
	}
	for _, node := range list.Nodes {
		*budget--
		if *budget < 0 {
			return false
		}
		switch n := node.(type) {
		case *parse.TextNode:
			for _, b := range n.Text {
				if b != ' ' && b != '\t' && b != '\r' && b != '\n' {
					return false
				}
			}
		case *parse.ActionNode:
			*budget -= 4 // pipe, command, identifier and string
			if *budget < 0 {
				return false
			}
			if root || len(n.Pipe.Decl) != 0 || n.Pipe.IsAssign || len(n.Pipe.Cmds) != 1 {
				return false
			}
			args := n.Pipe.Cmds[0].Args
			if len(args) != 2 {
				return false
			}
			fn, ok := args[0].(*parse.IdentifierNode)
			_, literal := args[1].(*parse.StringNode)
			if !ok || fn.Ident != "fail" || !literal {
				return false
			}
		case *parse.IfNode:
			if root || !staticHelperGuard(n.Pipe, depth+1, budget) || !staticHelperList(n.List, false, depth+1, budget) || !staticHelperList(n.ElseList, false, depth+1, budget) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func staticHelperGuard(p *parse.PipeNode, depth int, budget *int) bool {
	*budget -= 2 // pipe and command
	if p == nil || depth > 16 || *budget < 0 || len(p.Decl) != 0 || p.IsAssign || len(p.Cmds) != 1 {
		return false
	}
	for i, arg := range p.Cmds[0].Args {
		*budget--
		if *budget < 0 {
			return false
		}
		switch n := arg.(type) {
		case *parse.IdentifierNode:
			if i != 0 || !slicesContains([]string{"and", "or", "not", "eq", "ne"}, n.Ident) {
				return false
			}
		case *parse.FieldNode:
			if len(n.Ident) < 2 || n.Ident[0] != "Values" {
				return false
			}
		case *parse.StringNode, *parse.BoolNode, *parse.NumberNode:
		case *parse.PipeNode:
			if !staticHelperGuard(n, depth+1, budget) {
				return false
			}
		default:
			return false
		}
	}
	return len(p.Cmds[0].Args) > 0
}

// readStaticHelper checks the complete bounded chart, not just the named
// helper. This first profile refuses subcharts, dependencies and templated
// callers: it makes no claim about .Files visibility or tpl byte identity.
func readStaticHelper(r extract.PinnedReader, repo extract.RepoRef, commit, tpath string) (bool, error) {
	if !strings.HasSuffix(tpath, ".tpl") || !extract.IsCommitSHA(commit) {
		return false, nil
	}
	chart, ok, err := specChartDir(r, repo, commit, tpath)
	if err != nil || !ok {
		return false, err
	}
	if ok, err := specRegularFile(r, repo, commit, "", path.Join(chart, "Chart.yaml")); err != nil || !ok {
		return false, err
	}
	// A nested chart shares global definitions with its parent. This profile
	// does not load dependency graphs, so it cannot admit a subchart alone.
	for dir, steps := path.Dir(chart), 0; chart != ""; dir, steps = path.Dir(dir), steps+1 {
		if dir == "." {
			dir = ""
		}
		if steps >= specIncludeMaxAncestors {
			return false, nil
		}
		entries, err := r.List(repo, commit, dir)
		if err != nil {
			if isNotFound(err) {
				return false, nil
			}
			return false, err
		}
		for _, e := range entries {
			if e.Path == path.Join(dir, "Chart.yaml") {
				return false, nil
			}
		}
		if dir == "" {
			break
		}
	}
	seen, names := map[string]bool{}, map[string]bool{}
	count, total, found := 0, 0, false
	var walk func(string, int) (bool, error)
	walk = func(dir string, depth int) (bool, error) {
		if depth > 16 {
			return false, nil
		}
		entries, err := r.List(repo, commit, dir)
		if isNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		for _, e := range entries {
			count++
			parent := path.Dir(e.Path)
			if count > 200 || seen[e.Path] || (parent != dir && !(dir == "" && parent == ".")) || !extract.IsCommitSHA(e.SHA) {
				return false, nil
			}
			seen[e.Path] = true
			rel := strings.TrimPrefix(strings.TrimPrefix(e.Path, chart), "/")
			if rel == ".helmignore" || rel == "charts" || rel == "Chart.lock" || rel == "requirements.yaml" || rel == "requirements.lock" || (path.Base(e.Path) == "Chart.yaml" && rel != "Chart.yaml") {
				return false, nil
			}
			if e.Type == "tree" && e.Mode == "040000" {
				if ok, err := walk(e.Path, depth+1); err != nil || !ok {
					return false, err
				}
				continue
			}
			if e.Type != "blob" || (e.Mode != "100644" && e.Mode != "100755") {
				return false, nil
			}
			data, err := r.Read(repo, commit, e.Path)
			if isNotFound(err) {
				return false, nil
			}
			if err != nil {
				return false, err
			}
			total += len(data)
			h := sha1.New() //nolint:gosec // Git blob identities use SHA-1.
			fmt.Fprintf(h, "blob %d%c", len(data), 0)
			h.Write(data)
			if total > 512<<10 || hex.EncodeToString(h.Sum(nil)) != e.SHA || bytes.Contains(data, []byte("<no value>")) {
				return false, nil
			}
			if rel == "Chart.yaml" {
				_, values, err := decodeStrict(data)
				if err != nil || len(values) != 1 {
					return false, nil
				}
				m, ok := values[0].(map[string]any)
				if !ok || m["dependencies"] != nil {
					return false, nil
				}
			}
			if strings.HasPrefix(rel, "templates/") && strings.HasSuffix(rel, ".tpl") {
				defs, ok := staticHelperDefinitions(data)
				if !ok {
					return false, nil
				}
				for name := range defs {
					if names[name] {
						return false, nil
					}
					names[name] = true
				}
			} else if bytes.Contains(data, []byte("{{")) {
				return false, nil
			}
			found = found || e.Path == tpath
		}
		return true, nil
	}
	ok, err = walk(chart, 0)
	return ok && found, err
}
