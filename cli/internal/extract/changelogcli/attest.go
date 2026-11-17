// SPDX-License-Identifier: AGPL-3.0-only

package changelogcli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/changelogattest"
	"github.com/prufyx/prufyx/cli/internal/extract/changelogentries"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/factorymirror"
)

// AttestationSchema names the manifest the attest command prints.
const AttestationSchema = "prufyx.io/changelog-attestation-manifest/v1"

type attestIdentity struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	CodeDigest string `json:"codeDigest"`
}

type attestPair struct {
	Component  string `json:"component"`
	Repo       string `json:"repo"`
	From       string `json:"from"`
	FromTag    string `json:"fromTag"`
	FromCommit string `json:"fromCommit"`
	To         string `json:"to"`
	ToTag      string `json:"toTag"`
	ToCommit   string `json:"toCommit"`
}

type attestSource struct {
	ID        string `json:"id"`
	Repo      string `json:"repo"`
	Commit    string `json:"commit"`
	Path      string `json:"path"`
	StartLine int    `json:"startLine"`
	EndLine   int    `json:"endLine"`
}

type attestation struct {
	Basis      string                `json:"basis"`
	Component  string                `json:"component"`
	Line       string                `json:"line"`
	FactFamily string                `json:"factFamily"`
	RuleIDs    []string              `json:"ruleIds"`
	Releases   *lineattest.Releases  `json:"releases"`
	Sources    []attestSource        `json:"sources"`
	Scope      string                `json:"scope"`
	Proof      changelogattest.Proof `json:"proof"`
}

type attestWithheld struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// attestManifest holds exactly one of Attestation and Withheld.
type attestManifest struct {
	Schema             string          `json:"schema"`
	Extractor          attestIdentity  `json:"extractor"`
	Pair               attestPair      `json:"pair"`
	DispositionsDigest string          `json:"dispositionsDigest"`
	Attestation        *attestation    `json:"attestation,omitempty"`
	Withheld           *attestWithheld `json:"withheld,omitempty"`
}

func attestCodeDigest() (string, error) {
	files, err := extract.CodeFiles(changelogattest.SourceSet(), extract.FrameworkSource())
	if err != nil {
		return "", err
	}
	return extract.CodeDigest(files), nil
}

// readDispositions reads the dispositions file: a regular file within the
// loader's bound, read once so the digest is that of the bytes parsed.
func readDispositions(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("dispositions: %w", err)
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("dispositions: not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("dispositions: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, changelogattest.MaxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("dispositions: %w", err)
	}
	if len(raw) > changelogattest.MaxFileBytes {
		return nil, fmt.Errorf("dispositions: file is over %d bytes", changelogattest.MaxFileBytes)
	}
	return raw, nil
}

func pinTag(tags []extract.Tag, name string) (extract.Tag, error) {
	var pinned *extract.Tag
	for i := range tags {
		if tags[i].Name == name {
			if pinned != nil {
				return extract.Tag{}, fmt.Errorf("tag %q is recorded twice", name)
			}
			pinned = &tags[i]
		}
	}
	if pinned == nil {
		return extract.Tag{}, fmt.Errorf("tag %q is not recorded", name)
	}
	if !extract.IsCommitSHA(pinned.Commit) {
		return extract.Tag{}, fmt.Errorf("tag %q has no commit", name)
	}
	return *pinned, nil
}

func attest(args []string, table []changelogentries.Target) ([]byte, error) {
	var component, repo, path, form, fromTag, toTag, dispPath, mirror, fixture string
	f := flag.NewFlagSet("changelog attest", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	for name, v := range map[string]*string{
		"component": &component, "repo": &repo, "path": &path, "form": &form,
		"from-tag": &fromTag, "to-tag": &toTag, "dispositions": &dispPath,
		"mirror-state": &mirror, "fixture": &fixture,
	} {
		f.Var(&once{v: v}, name, "")
	}
	if err := f.Parse(args); err != nil {
		return nil, fmt.Errorf("%v\n%s", err, usage)
	}
	if f.NArg() != 0 {
		return nil, fmt.Errorf("unexpected argument %q\n%s", f.Arg(0), usage)
	}
	if component == "" || repo == "" || path == "" || form == "" || fromTag == "" || toTag == "" || dispPath == "" {
		return nil, fmt.Errorf("--component, --repo, --path, --form, --from-tag, --to-tag and --dispositions are all required\n%s", usage)
	}
	if (mirror == "") == (fixture == "") {
		return nil, errors.New("give exactly one of --mirror-state and --fixture")
	}
	t, err := changelogentries.Lookup(table, component)
	if err != nil {
		return nil, err
	}
	if repo != t.Repo.Key || path != t.Path || form != t.Form {
		return nil, fmt.Errorf("--repo, --path and --form do not match the reviewed target of %q", component)
	}
	if t.Form != changelogentries.FormFile {
		return nil, fmt.Errorf("the reviewed target of %q is not a changelog file: nothing to attest", component)
	}
	raw, err := readDispositions(dispPath)
	if err != nil {
		return nil, err
	}
	disp, err := changelogattest.LoadDispositions(raw, component)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)

	var src source
	if mirror != "" {
		r, err := factorymirror.OpenReader(mirror)
		if err != nil {
			return nil, fmt.Errorf("open mirror: %w", err)
		}
		src = extract.MirrorReader{R: r}
	} else {
		src = extract.FixtureReader{Root: fixture}
	}
	tags, err := src.Tags(t.Repo)
	if err != nil {
		return nil, err
	}
	from, err := pinTag(tags, fromTag)
	if err != nil {
		return nil, fmt.Errorf("--from-tag: %w", err)
	}
	to, err := pinTag(tags, toTag)
	if err != nil {
		return nil, fmt.Errorf("--to-tag: %w", err)
	}
	pair := extract.VersionPair{
		Repo: t.Repo,
		From: strings.TrimPrefix(from.Name, "v"), FromTag: from.Name, FromCommit: from.Commit,
		To: strings.TrimPrefix(to.Name, "v"), ToTag: to.Name, ToCommit: to.Commit,
	}
	digest, err := attestCodeDigest()
	if err != nil {
		return nil, err
	}
	m := attestManifest{
		Schema:             AttestationSchema,
		Extractor:          attestIdentity{Name: changelogattest.IDPrefix + component, Version: changelogattest.Version, CodeDigest: digest},
		Pair:               attestPair{component, t.Repo.Key, pair.From, pair.FromTag, pair.FromCommit, pair.To, pair.ToTag, pair.ToCommit},
		DispositionsDigest: "sha256:" + hex.EncodeToString(sum[:]),
	}
	// No classifier and no pack rule is given: every item needs a reviewed
	// not-operator-facing mark, and a rule mark has no rule to cite.
	cfg := changelogattest.Config{Target: t, Dispositions: disp, PackRules: nil, Classifier: nil}
	res, err := changelogattest.Attest(src, cfg, tags, pair)
	if err != nil {
		code, ok := changelogentries.CodeOf(err)
		if !ok {
			return nil, err
		}
		detail := err.Error()
		var fl *changelogentries.Failure
		if errors.As(err, &fl) {
			detail = fl.Detail
		}
		m.Withheld = &attestWithheld{Code: string(code), Detail: detail}
	} else {
		c := res.Candidate
		a := attestation{Basis: c.Basis, Component: c.Component, Line: c.Line, FactFamily: c.FactFamily,
			RuleIDs: c.RuleIDs, Releases: c.Releases, Sources: []attestSource{}, Proof: res.Proof}
		for _, s := range c.Sources {
			a.Sources = append(a.Sources, attestSource{s.ID, s.Repo.Key, s.Commit, s.Path, s.StartLine, s.EndLine})
		}
		scope, ok := changelogattest.ScopeText(res.Proof)
		if !ok {
			return nil, errors.New("the family has no scope statement for this window")
		}
		a.Scope = scope
		m.Attestation = &a
	}
	if (m.Attestation == nil) == (m.Withheld == nil) {
		return nil, errors.New("manifest must hold exactly one of attestation and withheld")
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
