// SPDX-License-Identifier: AGPL-3.0-only

// Package providerderive holds the pure, offline building blocks of the
// provider lifecycle extractors (subpackages gke and aks). An extractor has
// two halves. The fetch-side half parses a vendor page (strict grammar, any
// surprise is a typed drift error, never partial output) and renders small
// paraphrase excerpt bodies of the facts it found. The derive-side half takes
// the committed excerpts (bytes plus manifest entry, as providerexcerpt
// defines them) and returns provider lifecycle rows of the distribution
// record shape. Nothing here touches the network, the clock or the disk.
package providerderive

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/maintainer/providerexcerpt"
)

// ErrDrift is wrapped by every *DriftError.
var ErrDrift = errors.New("provider source drift")

// Drift kinds. They are a closed set so a watcher can route on them.
const (
	KindEmpty      = "empty"     // no bytes, 404 body, or no table at all
	KindSize       = "size"      // input over its cap
	KindStructure  = "structure" // markup or document structure not as anchored
	KindHeader     = "header"    // header text, order, span or width differs
	KindRow        = "row"       // a row has the wrong width or order or an invalid invariant
	KindCell       = "cell"      // a cell is outside its grammar
	KindMarker     = "marker"    // unknown footnote marker
	KindConflict   = "conflict"  // two parts of one official source disagree
	KindExcerpt    = "excerpt"   // an excerpt is not a valid body of its format
	KindIncomplete = "incomplete"
)

// DriftError is the typed failure of an extractor. A DriftError means: the
// source no longer looks like the anchored one; publish nothing for it.
type DriftError struct {
	Source string // "gke-schedule", "gke-feed", "aks-support", "aks-releases"
	Kind   string
	Detail string
	cause  error // optional underlying error, kept for errors.Is/As
}

func (e *DriftError) Error() string {
	return fmt.Sprintf("%s: %s drift: %s", e.Source, e.Kind, e.Detail)
}

func (e *DriftError) Unwrap() []error {
	if e.cause == nil {
		return []error{ErrDrift}
	}
	return []error{ErrDrift, e.cause}
}

// Drift builds a *DriftError.
func Drift(source, kind, format string, args ...any) error {
	return &DriftError{Source: source, Kind: kind, Detail: fmt.Sprintf(format, args...)}
}

// Excerpt is one committed excerpt: its manifest entry and file bytes.
type Excerpt struct {
	Entry providerexcerpt.Entry
	Data  []byte
}

// Body validates an excerpt exactly as providerexcerpt does (digest, caps,
// paraphrase rules) and returns its body lines. A refusal is a *DriftError of
// source and KindExcerpt that keeps the cause.
func Body(source string, x Excerpt) ([]string, error) {
	start, _, err := providerexcerpt.ParseExcerpt(x.Entry, x.Data)
	if err != nil {
		return nil, wrapExcerpt(source, x.Entry.ID, err)
	}
	lines := strings.Split(strings.TrimSuffix(string(x.Data), "\n"), "\n")
	return lines[start-1:], nil
}

func wrapExcerpt(source, id string, cause error) error {
	return &DriftError{Source: source, Kind: KindExcerpt, Detail: fmt.Sprintf("%s: %v", id, cause), cause: cause}
}

// Spec describes an excerpt file to compose.
type Spec struct {
	ID, Provider, SourceURL, FetchedAt, Anchor, Sentence string
	PageSHA256                                           string // sha256:<hex> of the fetched page or feed
}

// PageDigest returns the sha256:<hex> digest of fetched page bytes.
func PageDigest(page []byte) string {
	sum := sha256.Sum256(page)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Compose builds the paraphrase excerpt file and manifest entry of a body
// (unknown-licence terms: paraphrase only) and validates both. The factory
// commits the file; this is the only writer-side format knowledge.
func Compose(source string, s Spec, body string) (providerexcerpt.Entry, []byte, error) {
	if !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	hdr := fmt.Sprintf("%s\nsource: %s\nfetchedAt: %s\nanchor: %s\nlicence: %s\nform: %s\npageSha256: %s\nsentence: %s\n---\n",
		providerexcerpt.FileMagic, s.SourceURL, s.FetchedAt, s.Anchor, providerexcerpt.LicenceUnknown, providerexcerpt.FormParaphrase, s.PageSHA256, s.Sentence)
	data := []byte(hdr + body)
	sum := sha256.Sum256(data)
	e := providerexcerpt.Entry{
		ID: s.ID, Provider: s.Provider, Path: s.Provider + "/" + s.ID + ".txt", SourceURL: s.SourceURL,
		FetchedAt: s.FetchedAt, SHA256: "sha256:" + hex.EncodeToString(sum[:]), Anchor: s.Anchor,
		Licence: providerexcerpt.LicenceUnknown, Form: providerexcerpt.FormParaphrase,
	}
	if _, _, err := providerexcerpt.ParseExcerpt(e, data); err != nil {
		return providerexcerpt.Entry{}, nil, wrapExcerpt(source, s.ID, err)
	}
	return e, data, nil
}

// ChunkLines packs head plus as many of rows as fit in maxBytes bytes and
// providerexcerpt.MaxBodyLines lines per chunk (each chunk starts with head).
// A row that cannot fit alone is an error.
func ChunkLines(source, head string, rows []string, maxBytes int) ([]string, error) {
	var out []string
	cur := head + "\n"
	n := 0
	for _, r := range rows {
		if len(head)+1+len(r)+1 > maxBytes {
			return nil, Drift(source, KindSize, "one row does not fit an excerpt body")
		}
		if len(cur)+len(r)+1 > maxBytes || n+2 > providerexcerpt.MaxBodyLines {
			out = append(out, cur)
			cur, n = head+"\n", 0
		}
		cur += r + "\n"
		n++
	}
	if n > 0 {
		out = append(out, cur)
	}
	return out, nil
}
