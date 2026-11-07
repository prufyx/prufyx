// SPDX-License-Identifier: AGPL-3.0-only

// Package providerderive holds the shared, pure pieces of the provider
// version mapping extractors (subpackages k3s and kind). An extractor turns
// committed anchored release excerpts (providerexcerpt) into rows that map a
// provider version to the upstream Kubernetes version it ships. Nothing here
// fetches, reads the clock or touches the file system, and the output depends
// only on the set of inputs, never on their order.
//
// Body convention of a release excerpt (after the providerexcerpt header):
//
//	tag: <release tag>
//	prerelease: true|false
//	draft: true|false
//	<release body lines, LF>
//
// Fail-closed: a release that is not a final release, or whose body carries
// no mapping, yields an Unknown entry and no row. Anything unparsable, any
// mismatch and any conflict is a DriftError and the whole derivation yields
// no output.
package providerderive

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/maintainer/providerexcerpt"
)

// Unknown reasons (the mapping is not stated; never guessed).
const (
	ReasonPrerelease      = "prerelease"
	ReasonUnknownSuffix   = "unknown_suffix"
	ReasonFlagged         = "prerelease_or_draft_flag"
	ReasonNoMapping       = "no_mapping_statement"
	ReasonBeforeFirstKind = "release_before_first_mapped"
)

// ErrDrift is wrapped by every DriftError.
var ErrDrift = errors.New("provider source drift")

// DriftError is the typed error for an unparsable required field, a
// mismatch or a mapping conflict. Excerpt is the manifest id concerned.
type DriftError struct {
	Provider string
	Excerpt  string
	Detail   string
}

func (e *DriftError) Error() string {
	return fmt.Sprintf("provider-source-drift: %s excerpt %q: %s", e.Provider, e.Excerpt, e.Detail)
}

func (e *DriftError) Unwrap() error { return ErrDrift }

// Drift builds a DriftError.
func Drift(provider, excerpt, format string, args ...any) error {
	return &DriftError{Provider: provider, Excerpt: excerpt, Detail: fmt.Sprintf(format, args...)}
}

// Input is one committed excerpt: its manifest entry and file bytes.
type Input struct {
	Entry providerexcerpt.Entry
	Data  []byte
}

// Row maps one provider version to an upstream Kubernetes version.
type Row struct {
	Distribution    string `json:"distribution"`
	ProviderVersion string `json:"providerVersion"`
	Kubernetes      string `json:"kubernetes"`
	NodeImage       string `json:"nodeImage,omitempty"`
	// NonProduction marks a developer tool: never production fidelity.
	NonProduction bool   `json:"nonProduction,omitempty"`
	Excerpt       string `json:"excerpt"`
	ExcerptSHA256 string `json:"excerptSha256"`
}

// Unknown records a release that yields no mapping, with the reason.
type Unknown struct {
	Excerpt string `json:"excerpt"`
	Tag     string `json:"tag"`
	Reason  string `json:"reason"`
}

// Result is the deterministic output: rows and unknowns in sorted order.
type Result struct {
	Rows    []Row     `json:"rows"`
	Unknown []Unknown `json:"unknown"`
}

// Header is the parsed leading metadata of an excerpt body.
type Header struct {
	Tag        string
	Prerelease bool
	Draft      bool
}

// Open validates the excerpt (digest, layout, secrets) with providerexcerpt,
// checks that it belongs to provider and to repo ("owner/name") on github.com,
// and returns the metadata header and the remaining release body lines.
func Open(provider, repo string, in Input) (Header, []string, error) {
	id := in.Entry.ID
	if in.Entry.Provider != provider {
		return Header{}, nil, Drift(provider, id, "excerpt belongs to provider %q", in.Entry.Provider)
	}
	u, err := url.Parse(in.Entry.SourceURL)
	if err != nil || u.Scheme != "https" || u.Host != "github.com" || u.RawQuery != "" || u.Fragment != "" ||
		!strings.HasPrefix(u.Path, "/"+repo+"/releases/tag/") {
		return Header{}, nil, Drift(provider, id, "source is not a %s release tag page on github.com", repo)
	}
	if in.Entry.Form != providerexcerpt.FormVerbatim {
		return Header{}, nil, Drift(provider, id, "release excerpt must be verbatim")
	}
	start, _, err := providerexcerpt.ParseExcerpt(in.Entry, in.Data)
	if err != nil {
		return Header{}, nil, Drift(provider, id, "%v", err)
	}
	all := strings.Split(strings.TrimSuffix(string(in.Data), "\n"), "\n")
	body := all[start-1:]
	h, rest, err := ParseBody(provider, id, body)
	if err != nil {
		return h, nil, err
	}
	// The source page must be exactly this release's tag page. u.Path is the
	// decoded path, so a literal '+' and %2B both match the tag once; a
	// double-escaped tag (%252B) decodes to "%2B" and is rejected.
	if u.Path != "/"+repo+"/releases/tag/"+h.Tag {
		return Header{}, nil, Drift(provider, id, "source URL path %q does not match header tag %q", u.Path, h.Tag)
	}
	return h, rest, nil
}

// CheckDisjoint fails when one tag is both a mapped row and an unknown (two
// excerpts of the same release disagreeing); no output may be produced.
func CheckDisjoint(provider string, rows []Row, unk []Unknown) error {
	mapped := make(map[string]string, len(rows))
	for _, r := range rows {
		mapped[r.ProviderVersion] = r.Excerpt
	}
	for _, u := range unk {
		if ex, ok := mapped[u.Tag]; ok {
			return Drift(provider, u.Excerpt, "tag %s is mapped by excerpt %s and unknown (%s) here", u.Tag, ex, u.Reason)
		}
	}
	return nil
}

// ParseBody splits body lines into the metadata header and the release text.
// A trailing CR on a line (CRLF source) is tolerated and removed.
func ParseBody(provider, id string, body []string) (Header, []string, error) {
	var h Header
	if len(body) < 3 {
		return h, nil, Drift(provider, id, "missing tag/prerelease/draft header")
	}
	var err error
	if h.Tag, err = field(provider, id, body[0], "tag"); err != nil {
		return h, nil, err
	}
	pre, err := field(provider, id, body[1], "prerelease")
	if err != nil {
		return h, nil, err
	}
	dr, err := field(provider, id, body[2], "draft")
	if err != nil {
		return h, nil, err
	}
	if h.Prerelease, err = boolean(provider, id, "prerelease", pre); err != nil {
		return h, nil, err
	}
	if h.Draft, err = boolean(provider, id, "draft", dr); err != nil {
		return h, nil, err
	}
	rest := make([]string, 0, len(body)-3)
	for _, l := range body[3:] {
		rest = append(rest, strings.TrimSuffix(l, "\r"))
	}
	return h, rest, nil
}

func field(provider, id, line, key string) (string, error) {
	v, ok := strings.CutPrefix(strings.TrimSuffix(line, "\r"), key+": ")
	if !ok || v == "" || v != strings.TrimSpace(v) {
		return "", Drift(provider, id, "header field %q missing or malformed", key)
	}
	return v, nil
}

func boolean(provider, id, key, v string) (bool, error) {
	switch v {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, Drift(provider, id, "header field %q is not true/false", key)
}

// Merge sorts rows with less, drops exact duplicates and fails on a conflict:
// two different upstream versions for one provider version.
func Merge(provider string, rows []Row, less func(a, b Row) bool) ([]Row, error) {
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].ProviderVersion == rows[j].ProviderVersion {
			return rows[i].Excerpt < rows[j].Excerpt
		}
		return less(rows[i], rows[j])
	})
	out := make([]Row, 0, len(rows))
	for _, r := range rows {
		if n := len(out); n > 0 && out[n-1].ProviderVersion == r.ProviderVersion {
			p := out[n-1]
			if p.Kubernetes != r.Kubernetes || p.NodeImage != r.NodeImage {
				return nil, Drift(provider, r.Excerpt, "mapping conflict for %s: %s (excerpt %s) vs %s", r.ProviderVersion, p.Kubernetes, p.Excerpt, r.Kubernetes)
			}
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

// SortUnknown orders unknowns by tag then excerpt id.
func SortUnknown(u []Unknown) {
	sort.SliceStable(u, func(i, j int) bool {
		if u[i].Tag != u[j].Tag {
			return u[i].Tag < u[j].Tag
		}
		return u[i].Excerpt < u[j].Excerpt
	})
}

// CheckDistinctIDs fails on two inputs with one manifest id.
func CheckDistinctIDs(provider string, in []Input) error {
	seen := map[string]bool{}
	for _, i := range in {
		if seen[i.Entry.ID] {
			return Drift(provider, i.Entry.ID, "duplicate excerpt id")
		}
		seen[i.Entry.ID] = true
	}
	return nil
}
