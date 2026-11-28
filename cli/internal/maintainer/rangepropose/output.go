// SPDX-License-Identifier: AGPL-3.0-only

package rangepropose

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// The fixed output file names.
const (
	ProposalsFile = "proposals.json"
	ReviewFile    = "needs-review.json"
	SummaryFile   = "summary.txt"
)

// Files renders the three output files. The bytes depend only on the report.
func Files(r Report) (map[string][]byte, error) {
	candidates := struct {
		Schema     string     `json:"schema"`
		Status     string     `json:"status"`
		Disclaimer string     `json:"disclaimer"`
		Coverage   string     `json:"coverageNote"`
		Binding    Binding    `json:"binding"`
		Proposals  []Proposal `json:"proposals"`
	}{CandidatesSchema, StatusUnreviewed, Disclaimer, coverageNote, r.Binding, r.Proposals}
	review := struct {
		Schema      string    `json:"schema"`
		Status      string    `json:"status"`
		Disclaimer  string    `json:"disclaimer"`
		Binding     Binding   `json:"binding"`
		NeedsReview []Review  `json:"needsReview"`
		Refused     []Refused `json:"refused"`
	}{ReviewSchema, StatusNeedsReview, Disclaimer, r.Binding, r.NeedsReview, r.Refused}
	files := map[string][]byte{SummaryFile: []byte(Summary(r))}
	for name, v := range map[string]any{ProposalsFile: candidates, ReviewFile: review} {
		var b bytes.Buffer
		e := json.NewEncoder(&b)
		e.SetEscapeHTML(false)
		e.SetIndent("", "  ")
		if err := e.Encode(v); err != nil {
			return nil, fmt.Errorf("encode %s: %w", name, err)
		}
		files[name] = b.Bytes()
	}
	return files, nil
}

// Summary is the short text form, without control characters taken from the
// inputs.
func Summary(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Unreviewed range proposals: %s.\n", Disclaimer)
	fmt.Fprintf(&b, "rules commit %s\n", clean(r.Binding.RulesCommit))
	fmt.Fprintf(&b, "unreviewed proposals %d, needs review %d, refused %d; not candidates: already ranged %d, not active %d\n",
		len(r.Proposals), len(r.NeedsReview), len(r.Refused), r.AlreadyRanged, r.NotActive)
	for _, p := range r.Proposals {
		c := p.Candidate
		fmt.Fprintf(&b, "%s %s from [%s, %s) to [%s, %s) %s\n", p.Status, clean(p.RuleID), c.From.Gte, c.From.Lt, c.To.Gte, c.To.Lt, strings.Join(p.Flags, ","))
	}
	for _, v := range r.NeedsReview {
		codes := make([]string, 0, len(v.Reasons))
		for _, reason := range v.Reasons {
			codes = append(codes, reason.Code)
		}
		fmt.Fprintf(&b, "%s %s %s\n", v.Status, clean(v.RuleID), strings.Join(codes, ","))
	}
	for _, v := range r.Refused {
		fmt.Fprintf(&b, "%s %s %s: %s\n", v.Status, clean(v.RuleID), v.Code, clean(v.Detail))
	}
	return b.String()
}

// OutputDir resolves the directory the outputs may go to: new or empty, and
// after resolving symbolic links outside every git work tree, git directory
// and rule data directory.
func OutputDir(dir string) (string, error) {
	if dir == "" {
		return "", errors.New("no output directory")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", errors.New("the output directory path is invalid")
	}
	resolved, err := filepath.EvalSymlinks(abs)
	switch {
	case err == nil:
		f, err := os.Open(resolved)
		if err != nil {
			return "", errors.New("the output directory cannot be read")
		}
		defer f.Close()
		if info, err := f.Stat(); err != nil || !info.IsDir() {
			return "", errors.New("the output path is not a directory")
		}
		if _, err := f.Readdirnames(1); !errors.Is(err, io.EOF) {
			return "", errors.New("the output directory is not empty")
		}
	case os.IsNotExist(err):
		// A dangling symbolic link is not a new directory.
		if _, err := os.Lstat(abs); !os.IsNotExist(err) {
			return "", errors.New("the output path is not a new directory")
		}
		parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
		if err != nil {
			return "", errors.New("the parent of the output directory does not exist")
		}
		resolved = filepath.Join(parent, filepath.Base(abs))
	default:
		return "", errors.New("the output directory cannot be resolved")
	}
	if strings.Contains(strings.ToLower(filepath.ToSlash(resolved))+"/", "/internal/cncfcheck/data/") {
		return "", errors.New("the output directory is inside the rule data directory")
	}
	for d := resolved; ; d = filepath.Dir(d) {
		if exists(d, ".git") {
			return "", errors.New("the output directory is inside a git work tree")
		}
		if exists(d, "HEAD") && exists(d, "objects") {
			return "", errors.New("the output directory is inside a git directory")
		}
		if filepath.Dir(d) == d {
			return resolved, nil
		}
	}
}

// Write creates the three files in dir, which OutputDir must accept. Every
// file is created exclusively, so nothing is overwritten or followed.
func Write(dir string, r Report) error {
	resolved, err := OutputDir(dir)
	if err != nil {
		return err
	}
	files, err := Files(r)
	if err != nil {
		return err
	}
	if err := os.Mkdir(resolved, 0o755); err != nil && !os.IsExist(err) {
		return errors.New("the output directory cannot be created")
	}
	for _, name := range []string{ProposalsFile, ReviewFile, SummaryFile} {
		f, err := os.OpenFile(filepath.Join(resolved, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return fmt.Errorf("%s cannot be created", name)
		}
		_, werr := f.Write(files[name])
		if cerr := f.Close(); werr != nil || cerr != nil {
			return fmt.Errorf("%s cannot be written", name)
		}
	}
	return nil
}
