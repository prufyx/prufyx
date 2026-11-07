// SPDX-License-Identifier: AGPL-3.0-only

package aks

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"

	pd "github.com/prufyx/prufyx/cli/internal/maintainer/providerderive"
)

const (
	srcReleases = "aks-releases"
	// ReleasesFormat is the first body line of a releases excerpt.
	ReleasesFormat = "format aks-releases/v1"
	// ReleasesPath is the page path a releases excerpt must cite.
	ReleasesPath = "/Azure/AKS/releases"
	MaxReleases  = 300
	MaxJSONBytes = 8 << 20
)

// Release is one AKS release event. The GitHub prerelease flag is unused by
// AKS, so preview detection reads the tag, name and the first heading of the
// body only.
type Release struct {
	Tag        string // YYYY-MM-DD
	Published  string // YYYY-MM-DD of published_at (UTC)
	Prerelease bool
}

// Skipped is a release the extractor does not treat as an AKS release.
type Skipped struct {
	Tag    string
	Reason string
}

// Releases is the parsed list. Complete is false when the caller says more
// pages exist: the history is then known to be partial.
type Releases struct {
	Releases []Release
	Skipped  []Skipped
	Complete bool
}

var (
	tagRE     = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	previewRE = regexp.MustCompile(`(?i)\b(preview|alpha|beta|rc[0-9]*)\b`)
)

// Skip reasons.
const (
	SkipTagGrammar = "tag-grammar"
	SkipDraft      = "draft"
)

// ParseReleases reads one GitHub releases API page (newest first). hasNext
// reports a further page exists. An empty or non-JSON body, an unexpected
// shape, a tag that is a date but invalid, or dates out of order is drift.
// Tags outside the date grammar (other products) are skipped, never guessed.
func ParseReleases(body []byte, hasNext bool) (Releases, error) {
	if len(body) == 0 {
		return Releases{}, pd.Drift(srcReleases, pd.KindEmpty, "no body")
	}
	if len(body) > MaxJSONBytes {
		return Releases{}, pd.Drift(srcReleases, pd.KindSize, "body over %d bytes", MaxJSONBytes)
	}
	var raw []struct {
		Tag        string `json:"tag_name"`
		Name       string `json:"name"`
		Body       string `json:"body"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
		Published  string `json:"published_at"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return Releases{}, pd.Drift(srcReleases, pd.KindStructure, "not a releases array: %v", err)
	}
	if len(raw) == 0 {
		return Releases{}, pd.Drift(srcReleases, pd.KindEmpty, "no releases")
	}
	if len(raw) > MaxReleases {
		return Releases{}, pd.Drift(srcReleases, pd.KindSize, "more than %d releases", MaxReleases)
	}
	out := Releases{Complete: !hasNext}
	prevPub := ""
	prevTag := "9999-99-99"
	for i, r := range raw {
		pub, err := time.Parse(time.RFC3339, r.Published)
		if err != nil {
			return Releases{}, pd.Drift(srcReleases, pd.KindRow, "release %d: bad published_at", i+1)
		}
		p := pub.UTC().Format("2006-01-02")
		if prevPub != "" && p > prevPub {
			return Releases{}, pd.Drift(srcReleases, pd.KindRow, "release %d: not newest first", i+1)
		}
		prevPub = p
		if r.Draft {
			out.Skipped = append(out.Skipped, Skipped{Tag: safe(r.Tag), Reason: SkipDraft})
			continue
		}
		if !tagRE.MatchString(r.Tag) {
			out.Skipped = append(out.Skipped, Skipped{Tag: safe(r.Tag), Reason: SkipTagGrammar})
			continue
		}
		if _, err := time.Parse("2006-01-02", r.Tag); err != nil {
			return Releases{}, pd.Drift(srcReleases, pd.KindCell, "release %d: tag is not a valid date", i+1)
		}
		if r.Tag >= prevTag {
			return Releases{}, pd.Drift(srcReleases, pd.KindRow, "release %d: tags are not strictly descending", i+1)
		}
		prevTag = r.Tag
		out.Releases = append(out.Releases, Release{Tag: r.Tag, Published: p, Prerelease: r.Prerelease || isPreview(r.Name, r.Body)})
	}
	return out, nil
}

// safe keeps a skipped tag printable and short (it is only for reports).
func safe(t string) string {
	if len(t) > 64 {
		t = t[:64]
	}
	var b strings.Builder
	for _, c := range t {
		if c >= 0x21 && c < 0x7f {
			b.WriteRune(c)
		} else {
			b.WriteByte('?')
		}
	}
	return b.String()
}

func isPreview(name, body string) bool {
	if previewRE.MatchString(name) {
		return true
	}
	for _, ln := range strings.Split(body, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		return strings.HasPrefix(ln, "#") && previewRE.MatchString(ln)
	}
	return false
}

// Bodies renders the releases as excerpt bodies. A first line "complete" or
// "partial" records whether further pages existed.
func (r Releases) Bodies() ([]string, error) {
	head := ReleasesFormat + " " + map[bool]string{true: "complete", false: "partial"}[r.Complete]
	var rows []string
	for _, x := range r.Releases {
		kind := "release"
		if x.Prerelease {
			kind = "preview"
		}
		rows = append(rows, kind+" "+x.Tag+" "+x.Published)
	}
	return pd.ChunkLines(srcReleases, head, rows, MaxBody)
}

// DeriveReleases reads releases excerpts (newest first within and across the
// slice). Complete is true only when every excerpt says complete.
func DeriveReleases(xs []pd.Excerpt) (Releases, error) {
	if len(xs) == 0 {
		return Releases{}, pd.Drift(srcReleases, pd.KindEmpty, "no excerpts")
	}
	out := Releases{Complete: true}
	prev := "9999-99-99"
	for _, x := range xs {
		if x.Entry.Provider != Distribution || x.Entry.SourceURL != "https://github.com"+ReleasesPath {
			return Releases{}, pd.Drift(srcReleases, pd.KindExcerpt, "excerpt %s cites a source outside the anchored one", x.Entry.ID)
		}
		body, err := pd.Body(x)
		if err != nil {
			return Releases{}, err
		}
		switch {
		case len(body) < 2:
			return Releases{}, pd.Drift(srcReleases, pd.KindExcerpt, "%s: empty body", x.Entry.ID)
		case body[0] == ReleasesFormat+" partial":
			out.Complete = false
		case body[0] != ReleasesFormat+" complete":
			return Releases{}, pd.Drift(srcReleases, pd.KindExcerpt, "%s: not a releases body", x.Entry.ID)
		}
		for _, ln := range body[1:] {
			f := strings.Split(ln, " ")
			if len(f) != 3 || (f[0] != "release" && f[0] != "preview") || !tagRE.MatchString(f[1]) || !tagRE.MatchString(f[2]) || f[1] >= prev {
				return Releases{}, pd.Drift(srcReleases, pd.KindExcerpt, "%s: bad or unordered row", x.Entry.ID)
			}
			if _, ok := pd.ParseISO(f[1]); !ok {
				return Releases{}, pd.Drift(srcReleases, pd.KindExcerpt, "%s: invalid date", x.Entry.ID)
			}
			if _, ok := pd.ParseISO(f[2]); !ok {
				return Releases{}, pd.Drift(srcReleases, pd.KindExcerpt, "%s: invalid date", x.Entry.ID)
			}
			prev = f[1]
			out.Releases = append(out.Releases, Release{Tag: f[1], Published: f[2], Prerelease: f[0] == "preview"})
		}
	}
	return out, nil
}
