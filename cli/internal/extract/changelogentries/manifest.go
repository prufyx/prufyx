// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// Pins of the manifest a run prints. A reader of the manifest accepts exactly
// these values; a change of the derivation changes ExtractorVersion.
const (
	ManifestSchema   = "prufyx.io/changelog-entries-manifest/v1"
	ExtractorName    = "changelog.entries"
	ExtractorVersion = "changelog.entries/1"
)

// SourceDir is this package's directory under the module's internal/ tree.
const SourceDir = "extract/changelogentries"

//go:embed *.go
var own embed.FS

// SourceFiles implements extract.CodeSource: the package's own source.
func SourceFiles() (string, fs.FS) { return SourceDir, own }

// CodeDigest is the digest of every non-test source file of this package and
// of the extract framework it is built on, in the form other extractors use.
func CodeDigest() (string, error) {
	files, err := extract.CodeFiles(extract.SourceSet{Dir: SourceDir, Files: own}, extract.FrameworkSource())
	if err != nil {
		return "", err
	}
	return extract.CodeDigest(files), nil
}

// ExtractorIdentity names the code that derived a manifest.
type ExtractorIdentity struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	CodeDigest string `json:"codeDigest"`
}

// Withheld is the typed reason a tag has no entry. Code is the contract;
// Detail is for people.
type Withheld struct {
	Component string `json:"component"`
	Tag       string `json:"tag"`
	TagCommit string `json:"tagCommit"`
	Code      Code   `json:"code"`
	Detail    string `json:"detail"`
}

// Manifest is what one run prints for one tag: the entry, or the reason it is
// withheld, never both and never neither. It carries no classification and no
// disposition of any item.
type Manifest struct {
	Schema    string            `json:"schema"`
	Extractor ExtractorIdentity `json:"extractor"`
	Entry     *Entry            `json:"entry,omitempty"`
	Withheld  *Withheld         `json:"withheld,omitempty"`
}

// Reviewed is the reviewed table of changelog targets. It is empty until a
// component's row has been reviewed; a component without a row is refused.
var Reviewed = []Target{
	{Component: "vault", Repo: extract.RepoRef{Key: "github.com/hashicorp/vault"}, Form: FormPostTag},
}

// Lookup returns the row of a component in table. Exactly one row must match.
func Lookup(table []Target, component string) (Target, error) {
	var found []Target
	for _, t := range table {
		if t.Component == component {
			found = append(found, t)
		}
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return Target{}, fmt.Errorf("no reviewed changelog target for component %q", component)
	}
	return Target{}, fmt.Errorf("component %q has %d reviewed changelog targets", component, len(found))
}

// BuildManifest locates the tag's entry and wraps the result. A typed
// reason becomes a Withheld manifest; any other error (a read failure, a tag
// the source does not hold) is returned and never becomes a reason.
func BuildManifest(r extract.PinnedReader, t Target, tag extract.Tag, codeDigest string) (*Manifest, error) {
	m := &Manifest{
		Schema:    ManifestSchema,
		Extractor: ExtractorIdentity{Name: ExtractorName, Version: ExtractorVersion, CodeDigest: codeDigest},
	}
	e, err := Locate(r, t, tag)
	if err != nil {
		var f *Failure
		if !errors.As(err, &f) {
			return nil, err
		}
		m.Withheld = &Withheld{Component: t.Component, Tag: tag.Name, TagCommit: tag.Commit, Code: f.Code, Detail: f.Detail}
		return m, nil
	}
	if e.Component != t.Component || e.Tag != tag.Name || e.TagCommit != tag.Commit {
		return nil, errors.New("entry does not belong to the requested component and tag")
	}
	m.Entry = e
	return m, nil
}

// Bytes renders the manifest: compact JSON in struct order, one trailing LF.
// Equal inputs give equal bytes. A manifest holding both or neither of Entry
// and Withheld is refused.
func (m Manifest) Bytes() ([]byte, error) {
	if (m.Entry == nil) == (m.Withheld == nil) {
		return nil, errors.New("manifest must hold exactly one of entry and withheld")
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
