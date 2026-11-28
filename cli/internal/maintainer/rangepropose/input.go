// SPDX-License-Identifier: AGPL-3.0-only

package rangepropose

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// RulesPath is the rule pack read from the named commit.
const RulesPath = "cli/internal/cncfcheck/data/rules.json"

var (
	commitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
	nameRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

// strictUnmarshal decodes one JSON document and refuses a duplicate object
// key at any depth, invalid UTF-8 and trailing data. With known set it also
// refuses unknown fields.
func strictUnmarshal(raw []byte, v any, known bool) error {
	if !utf8.Valid(raw) {
		return errors.New("invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := checkKeys(d, 0); err != nil {
		return err
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	if known {
		d.DisallowUnknownFields()
	}
	return d.Decode(v)
}

// checkKeys walks one JSON value. Keys that differ only in case are refused
// too, because the decoder matches field names without regard to case.
func checkKeys(d *json.Decoder, depth int) error {
	if depth > 128 {
		return errors.New("nesting too deep")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	for d.More() {
		if delim == '{' {
			keyToken, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			folded := strings.ToLower(strings.ToUpper(key))
			if seen[folded] {
				return fmt.Errorf("duplicate key %q", key)
			}
			seen[folded] = true
		}
		if err := checkKeys(d, depth+1); err != nil {
			return err
		}
	}
	_, err = d.Token()
	return err
}

// Config names, per rule project, the local clone and its tag convention.
type Config struct {
	Projects map[string]Project `json:"projects"`
}

// Project is the subject repository of one rule project.
type Project struct {
	// Repo is owner/name on github.com. It is the caller's statement of the
	// subject repository; it is never inferred from a rule's sources.
	Repo string `json:"repo"`
	// Path is the local bare clone.
	Path string `json:"path"`
	// TagPrefix precedes X.Y.Z in a final release tag; it may be empty.
	TagPrefix string `json:"tagPrefix"`
	// Tags, when present, is the expected set of final release tags of every
	// line the tool reads; it must equal what the clone holds.
	Tags *[]ExpectedTag `json:"tags,omitempty"`
}

// ExpectedTag pins one tag name to its commit.
type ExpectedTag struct {
	Tag    string `json:"tag"`
	Commit string `json:"commit"`
}

// DecodeConfig reads the project file strictly.
func DecodeConfig(raw []byte) (Config, error) {
	var c Config
	if err := strictUnmarshal(raw, &c, true); err != nil {
		return Config{}, fmt.Errorf("projects file: %w", err)
	}
	if len(c.Projects) == 0 {
		return Config{}, errors.New("projects file: no projects")
	}
	for name, p := range c.Projects {
		owner, repo, ok := strings.Cut(p.Repo, "/")
		if !ok || !nameRE.MatchString(owner) || !nameRE.MatchString(repo) || p.Path == "" {
			return Config{}, fmt.Errorf("projects file: %q needs repo (owner/name) and path", name)
		}
		if p.Tags == nil {
			continue
		}
		seen := map[string]bool{}
		for _, t := range *p.Tags {
			rest, prefixed := strings.CutPrefix(t.Tag, p.TagPrefix)
			_, final := parseVersion(rest)
			if !prefixed || !final || !commitRE.MatchString(t.Commit) || seen[t.Tag] {
				return Config{}, fmt.Errorf("projects file: %q expected tag %q must be a unique final release tag with a full commit id", name, t.Tag)
			}
			seen[t.Tag] = true
		}
	}
	return c, nil
}

// packRule is one rule of the pack, as far as the tool reads it.
type packRule struct {
	project     string
	id          string
	entryDigest string
	shape       ruleShape
	key         string
}

type ruleShape struct {
	ID          string          `json:"id"`
	Operator    string          `json:"operator"`
	AppliesWhen json.RawMessage `json:"appliesWhen"`
	Subject     struct {
		Component string          `json:"component"`
		Chart     json.RawMessage `json:"chart"`
		From      string          `json:"from"`
		To        string          `json:"to"`
	} `json:"subject"`
	Range        *constraintengine.VersionRange `json:"range"`
	Crossing     json.RawMessage                `json:"crossing"`
	SetCondition *struct {
		Members []string `json:"members"`
	} `json:"setCondition"`
	Evidence struct {
		State   string   `json:"state"`
		Sources []source `json:"sources"`
	} `json:"evidence"`
}

type source struct {
	ID            string `json:"id"`
	URL           string `json:"url"`
	Revision      string `json:"revision"`
	ContentDigest string `json:"contentDigest"`
	StartLine     int    `json:"startLine"`
	EndLine       int    `json:"endLine"`
}

// rulesGitDir pins the git directory of the rules repository: its .git entry
// when it has one, else the directory itself. Nothing is searched upward.
func rulesGitDir(repo string) (string, error) {
	abs, err := filepath.Abs(repo)
	if err != nil {
		return "", errors.New("the rules repository path is invalid")
	}
	if _, err := os.Lstat(filepath.Join(abs, ".git")); err == nil {
		return filepath.Join(abs, ".git"), nil
	}
	return abs, nil
}

// readPack reads the rule pack from one commit of a local repository.
func readPack(ctx context.Context, repo, commit string) ([]byte, []packRule, error) {
	if !commitRE.MatchString(commit) {
		return nil, nil, errors.New("the rules commit must be a full 40 hex commit id")
	}
	gitDir, err := rulesGitDir(repo)
	if err != nil {
		return nil, nil, err
	}
	kind, err := runGit(ctx, gitDir, "cat-file", "-t", commit)
	if err != nil || strings.TrimSpace(string(kind)) != "commit" {
		return nil, nil, errors.New("the rules commit is not in the rules repository")
	}
	file, err := readTreeFile(ctx, gitDir, commit, RulesPath)
	if err != nil || file == nil || file.problem != "" {
		return nil, nil, fmt.Errorf("%s cannot be read at the rules commit", RulesPath)
	}
	var doc map[string]json.RawMessage
	if err := strictUnmarshal(file.data, &doc, false); err != nil {
		return nil, nil, fmt.Errorf("the rule pack is not strict JSON: %w", err)
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(doc["entries"], &entries); err != nil || len(entries) == 0 {
		return nil, nil, errors.New("the rule pack is not a document with entries")
	}
	rules := make([]packRule, 0, len(entries))
	seen := map[string]bool{}
	for _, raw := range entries {
		var entry struct {
			Project string          `json:"project"`
			Rule    json.RawMessage `json:"rule"`
		}
		if err := json.Unmarshal(raw, &entry); err != nil {
			return nil, nil, errors.New("the rule pack has an unreadable entry")
		}
		r := packRule{project: entry.Project, entryDigest: digest(raw)}
		if err := json.Unmarshal(entry.Rule, &r.shape); err != nil || !nameRE.MatchString(r.shape.ID) || entry.Project == "" || seen[r.shape.ID] {
			return nil, nil, errors.New("the rule pack has an unreadable or duplicate rule")
		}
		r.id = r.shape.ID
		seen[r.id] = true
		if r.key, err = constraintengine.ConstraintKey(entry.Rule); err != nil {
			return nil, nil, fmt.Errorf("rule %s: %w", r.id, err)
		}
		rules = append(rules, r)
	}
	return file.data, rules, nil
}

// ParseGaps reads the optional ordering file: one rule id per line; blank
// lines and lines starting with # are ignored.
func ParseGaps(raw []byte) ([]string, error) {
	var ids []string
	seen := map[string]bool{}
	for _, l := range strings.Split(string(raw), "\n") {
		id := strings.TrimSpace(l)
		if id == "" || strings.HasPrefix(id, "#") {
			continue
		}
		if seen[id] {
			return nil, fmt.Errorf("gap list: %q is listed twice", id)
		}
		seen[id] = true
		ids = append(ids, id)
	}
	return ids, nil
}

// clean removes control and format characters from text that came from a
// rule pack or a repository.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			return -1
		}
		return r
	}, s)
}
